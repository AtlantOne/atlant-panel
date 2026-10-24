"""Standalone control service. Core API keys never reach the browser."""
import argparse
import getpass
import hashlib
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
import re
from pathlib import Path
import socket
import ssl
import threading
from urllib.parse import urlsplit

from atlantctl import AdminError, Manager, load_config, private_write
from control.i18n import catalog, error_message, language, message
from control.security import Authentication, Operations, password_record
from control.tls import from_panel_settings
from control.notify import ready
from control.peers import PeerError
import sqlite3

ASSETS = Path(__file__).with_name('web')


def origin_parts(origin):
    parts = urlsplit(origin)
    if parts.scheme not in {'http', 'https'} or not parts.netloc or parts.username or parts.password or parts.path or parts.query or parts.fragment:
        raise ValueError('Origin must be an HTTP(S) origin without path or credentials')
    if parts.scheme == 'http':
        if not ipaddress.ip_address(parts.hostname).is_loopback:
            raise ValueError('Plaintext control access is allowed only on a loopback IP')
    return parts


class PanelServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 16

    def __init__(self, address, origin, manager, credentials, context=None, demonstration=False, credential_writer=None, instance=None,base_path='/',credential_loader=None):
        if base_path!='/' and not re.fullmatch(r'/[A-Za-z0-9_-]{32}/',base_path):raise ValueError('Invalid panel entry path')
        self.base_path=base_path
        self.credential_loader=credential_loader
        self.credential_lock=threading.Lock()
        self.demonstration = demonstration
        self.instance=instance
        self.origin = origin
        parts = origin_parts(origin)
        if parts.scheme == 'https' and context is None:
            raise ValueError('HTTPS origin requires a certificate and private key')
        if context is not None and parts.scheme != 'https':
            raise ValueError('TLS listener requires an HTTPS origin')
        if context is None and not ipaddress.ip_address(address[0]).is_loopback:
            raise ValueError('Plaintext listener must bind to a loopback IP')
        self.authority = parts.netloc
        self.secure = parts.scheme == 'https'
        scope = hashlib.sha256((origin + base_path).encode()).hexdigest()[:16]
        self.cookie_name = ('__Host-atlant-control-' if self.secure else 'atlant-control-') + scope
        self.auth = Authentication(credentials)
        self.credential_writer = credential_writer
        self.operations = Operations(manager)
        self.context = context
        self.certificate_manager = None
        self.slots = threading.BoundedSemaphore(16)
        if ':' in address[0]:
            self.address_family = socket.AF_INET6
        super().__init__(address, Handler)
        manager.peers.live_origin=lambda:self.origin

    def get_request(self):
        sock, address = super().get_request()
        sock.settimeout(10)
        return sock, address

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()


class Handler(BaseHTTPRequestHandler):
    server_version = 'HTTP'
    sys_version = ''
    protocol_version = 'HTTP/1.0'

    def setup(self):
        # Negotiate TLS in a bounded worker, never in the accept loop.
        if self.server.context is not None:
            self.request = self.server.context.wrap_socket(self.request, server_side=True)
        super().setup()

    def finish(self):
        try:
            super().finish()
        finally:
            # wrap_socket owns the original descriptor; server shutdown still
            # receives the detached raw socket. Close the TLS owner explicitly.
            if isinstance(self.request, ssl.SSLSocket):
                self.request.close()

    def log_message(self, *_):
        # URL/query strings and request headers may contain credentials.
        pass

    def send(self, status, value, content_type='application/json; charset=utf-8', cookie=None, headers=None):
        body = value if isinstance(value, bytes) else json.dumps(value, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
        if self.server.secure:
            self.send_header('Strict-Transport-Security', 'max-age=31536000')
        if cookie:
            self.send_header('Set-Cookie', cookie)
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def fail(self, status, code, lang='en'):
        self.send(status, {'code': code, 'error': message(code, lang)})

    def cookie(self, token='', expire=False):
        cookie = SimpleCookie()
        cookie[self.server.cookie_name] = token
        entry = cookie[self.server.cookie_name]
        entry['path'], entry['httponly'], entry['samesite'] = '/', True, 'Strict'
        entry['max-age'] = '0' if expire else '28800'
        if self.server.secure:
            entry['secure'] = True
        return cookie.output(header='').strip()

    def token(self):
        try:
            cookie = SimpleCookie(self.headers.get('Cookie', ''))
            item = cookie.get(self.server.cookie_name)
            return item.value if item else ''
        except Exception:
            return ''

    def valid_host(self):
        return self.headers.get_all('Host') == [self.server.authority]

    def browser_path(self):
        if self.path.startswith('/peer/') or self.path=='/control/health':return True
        prefix=self.server.base_path
        if prefix!='/':
            if self.path==prefix[:-1]:
                self.send(302,b'','text/plain; charset=utf-8',headers={'Location':prefix})
                return False
            if not self.path.startswith(prefix):self.send(404,b'','text/plain; charset=utf-8');return False
            self.path='/'+self.path[len(prefix):]
        if self.server.credential_loader:
            try:
                with self.server.credential_lock:
                    record=self.server.credential_loader()
                    if record!=self.server.auth.record:
                        with self.server.auth.lock:
                            self.server.auth.record=record;self.server.auth.sessions.clear()
                        self.server.operations.revoke_confirmations()
            except (OSError,ValueError,TypeError):self.fail(503,'failed');return False
        return True

    def do_GET(self):
        if not self.browser_path():return
        if not self.valid_host():
            self.fail(403, 'forbidden')
            return
        routes = {'/': ('index.html', 'text/html; charset=utf-8'), '/app.js': ('app.js', 'text/javascript; charset=utf-8'), '/style.css': ('style.css', 'text/css; charset=utf-8'), '/theme.js': ('theme.js', 'text/javascript; charset=utf-8'), '/forms.js': ('forms.js', 'text/javascript; charset=utf-8')}
        routes.update({'/qrcode.js':('qrcode.js','text/javascript; charset=utf-8'),'/share.js':('share.js','text/javascript; charset=utf-8')})
        if self.path in routes:
            name, mime = routes[self.path]
            self.send(200, (ASSETS / name).read_bytes(), mime)
        elif self.path == '/license':
            self.send(200,Path(__file__).resolve().parent.parent.joinpath('LICENSE').read_bytes(),'text/plain; charset=utf-8')
        elif self.path == '/control/health':
            if not ipaddress.ip_address(self.client_address[0]).is_loopback:self.send(404,{'code':'not_found'})
            else:self.send(200,{'status':'ready','instance':self.server.instance})
        elif self.path == '/control/session':
            session = self.server.auth.authenticate(self.token())
            if not session:
                self.fail(401, 'unauthorized')
            else:
                self.send(200, {'csrf': session['csrf'], 'demo': self.server.demonstration, 'languages': {lang: catalog(lang) for lang in ('en', 'ru', 'zh')}})
        elif self.path == '/control/languages':
            self.send(200, {lang: catalog(lang) for lang in ('en', 'ru', 'zh')})
        elif self.path == '/control/certificate':
            if not self.server.auth.authenticate(self.token()):
                self.fail(401, 'unauthorized')
            else:
                manager = self.server.certificate_manager
                self.send(200, dict(manager.status() if manager else {'mode': 'external' if self.server.secure else 'loopback-http'}, origin=self.server.origin))
        else:
            self.send(404, {'code': 'not_found'})

    def do_POST(self):
        if not self.browser_path():return
        peer_route=self.path in {'/peer/claim','/peer/result','/peer/call'}
        if not self.valid_host() or (not peer_route and self.headers.get_all('Origin') != [self.server.origin]) or (peer_route and not self.server.secure):
            self.fail(403, 'forbidden')
            return
        try:
            if self.headers.get('Transfer-Encoding') or len(self.headers.get_all('Content-Length', [])) != 1 or self.headers.get_content_type() != 'application/json':
                raise ValueError()
            size = int(self.headers['Content-Length'])
            if not 0 < size <= 64 * 1024:
                raise ValueError()
            data = json.loads(self.rfile.read(size), parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
            if not isinstance(data, dict):
                raise ValueError()
        except (ValueError, UnicodeError, OSError):
            self.fail(400, 'invalid')
            return
        lang = language(data.get('lang') if isinstance(data.get('lang'), str) else 'en')
        if peer_route:
            peers=self.server.operations.manager.peers
            try:
                if self.path=='/peer/call':
                    result=peers.receive(data,lambda command:self.server.operations.manager.execute(self.server.operations.manager.prepare(command)),self.server.operations.manager.peer_execute)
                else:
                    peers.allow_attempt(self.client_address[0])
                    result=peers.claim(data) if self.path=='/peer/claim' else peers.result(data)
                self.send(200,result)
            except PeerError:self.fail(403,'peer_forbidden')
            except (ValueError,TypeError,KeyError):self.fail(400,'invalid')
            except (OSError,sqlite3.Error,AdminError):self.fail(503,'peer_unavailable')
            return
        if self.path == '/control/login':
            credentials, error = self.server.auth.login(self.client_address[0], data.get('password'), data.get('username'))
            if error:
                self.fail(429 if error == 'rate_limited' else 401, 'invalid_credentials' if error == 'unauthorized' else error, lang)
            else:
                token, csrf = credentials
                self.send(200, {'csrf': csrf, 'demo': self.server.demonstration}, cookie=self.cookie(token))
            return
        session = self.server.auth.authenticate(self.token())
        if not session:
            self.fail(401, 'unauthorized', lang)
            return
        if not self.server.auth.authenticate(self.token(), self.headers.get('X-CSRF-Token', '')):
            self.fail(403, 'csrf_expired', lang)
            return
        try:
            if self.path == '/control/logout':
                self.server.auth.logout(self.token())
                self.send(200, {'ok': True}, cookie=self.cookie(expire=True))
            elif self.path == '/control/password':
                self.send(404,{'code':'not_found'})
            elif self.path == '/control/prepare':
                self.send(200, self.server.operations.prepare(session['id'], data.get('command'), data.get('reveal', False)))
            elif self.path == '/control/commit' and data.get('confirm') is True:
                self.send(200, self.server.operations.commit(session['id'], data.get('confirmation')))
            else:
                self.send(404, {'code': 'not_found'})
        except AdminError as error:
            self.send(409, {'code': 'operation_failed', 'error': error_message(error, lang)})
        except PermissionError:
            self.fail(403, 'forbidden', lang)
        except OverflowError:
            self.fail(429, 'rate_limited', lang)
        except (ValueError, TypeError, KeyError):
            self.fail(400, 'invalid', lang)
        except (OSError, RuntimeError):
            self.fail(503, 'failed', lang)


def main():
    parser = argparse.ArgumentParser(description='Standalone Atlant Control (local development)')
    parser.add_argument('action', choices=('set-password', 'serve'))
    parser.add_argument('--config', default='/etc/atlant-control/client.json' if Path('/etc/atlant-control/client.json').is_file() else '/etc/atlant-admin/client.json')
    parser.add_argument('--lang',choices=('en','ru','zh'))
    args = parser.parse_args()
    config = load_config(args.config)
    lang=language(args.lang or config.get('language'))
    manager = Manager(config)
    panel = manager.panel_settings.effective()
    state = Path(panel.get('state_dir', config.get('state_dir','/var/lib/atlant-control')))
    credentials = state / 'credentials.json'
    if args.action == 'set-password':
        from control.access import set_password
        set_password(state,lang,private_write)
        print(message('cli_password_saved',lang))
        return
    if os.name == 'posix' and credentials.stat().st_mode & 0o077:
        parser.error('Panel credentials require mode 0600')
    from control.access import read_credentials
    record = read_credentials(credentials)
    context, certificate_manager = None, from_panel_settings(panel)
    if certificate_manager:
        context = certificate_manager.context
    from control.access import entry_path
    prefix=entry_path(state)
    def reload_credentials():
        return read_credentials(credentials)
    server = PanelServer((panel.get('listen', '127.0.0.1'), int(panel.get('port', 9090))),
                         panel.get('origin', 'http://127.0.0.1:9090'), manager, record, context,
                         instance=config.get('instance'),base_path=prefix,credential_loader=reload_credentials)
    server.certificate_manager = certificate_manager
    stopped, watcher = threading.Event(), None
    if certificate_manager:
        watcher = threading.Thread(target=certificate_manager.watch, args=(stopped, lambda context: setattr(server, 'context', context)), daemon=True)
        watcher.start()
    print('Atlant Control listening (use CLI panelurl for the private URL)')
    try:
        ready()
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        stopped.set()
        if watcher:
            watcher.join(timeout=2)
        server.server_close()


if __name__ == '__main__':
    main()
