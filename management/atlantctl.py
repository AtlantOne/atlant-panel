#!/usr/bin/python3 -I
"""Atlant management client: standard-library CLI and reusable local API client."""
import argparse
import base64
import datetime as dt
from decimal import Decimal, InvalidOperation
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import secrets
import shlex
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

# Keep the installed script directory available under the isolated shebang and
# when private integrations load this module by its absolute file location.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from control.i18n import error_message, help_text, language, message
from control.certificate_jobs import CertificateJobs, CertificateJobError
from control.panel_settings import PanelSettings, PanelSettingsError
from control.peers import Peers, PeerError
import sqlite3

MAX_BODY = 12 * 1024 * 1024
PANEL_CLI_COMMANDS = frozenset({
    'menu','panelurl','panelpassword','panelsettings','panelset','paneltls',
    'panelbackup','panelbackups','panelrestore','certjobs','certbackup','certbackups','certrestore',
    'certjobcreate','certjobset','certjobdelete','certservice','license','logs',
})


def panel_cli_help(lang):
    intro=help_text(lang).split('\n\n',1)[0]
    commands=('menu | panelurl | panelpassword\n'
              'panelsettings | panelset {SETTINGS} | paneltls\n'
              'panelbackup | panelbackups | panelrestore BACKUP [REVISION]\n'
              'certjobs | certjobcreate ID {SETTINGS} | certjobset ID {SETTINGS}\n'
              'certjobdelete ID [REVISION] | certbackup | certbackups | certrestore BACKUP [REVISION]\n'
              'certservice status|start|stop|restart\n'
              'logs [LINES] | license | help')
    return intro+'\n\n'+message('cli_panel_scope',lang)+'\n\n'+commands
HELP = '''Команды (бот: /команда, CLI: atlantctl команда):
status — состояние, скорость и трафик
users [страница] [поиск] | user ИМЯ | online
add ИМЯ [ГиБ=0] [дней=0] — создать пользователя
set ИМЯ {"total_limit":0,"expires_at":0,"ip_limit":2,"note":"..."}
enable ИМЯ | disable ИМЯ | kick ИМЯ | delete ИМЯ
reset ИМЯ | rekey ИМЯ | link ИМЯ
bulk enable|disable|delete|reset ИМЯ1 ИМЯ2 ...
subscriptions | sub ID | subcreate ИМЯ Заголовок подписки
subset ID {"title":"...","enabled":true,"expires_at":0,"update_hours":1}
subquota ID ГиБ — общий лимит подписки (например 0,1; 0 — безлимит)
quotanodes | quotaenroll VDS_ID ID_ПОДПИСКИ [ID_ПОДПИСКИ ...]
quotadisable VDS_ID | quotabind ИМЯ ID_ПОДПИСКИ | quotabindings
subrotate ID | subdelete ID
subkick ID | subrekey ID
submigration | submigrate REVISION ID [ID...]
peers | peerinvite | peerjoin LINK | peerapprove CLAIM | peerfinish CLAIM
peerreject CLAIM | peercancel CLAIM | peerrevoke PANEL | peercatalog PANEL
peergrant PANEL true|false | peerexecute PANEL 'INBOUND_COMMAND'
peerjobs PANEL | peerretry PANEL REQUEST_ID
panelurl | panelpassword (terminal only)
peersync PANEL | appliedinbounds | remotecatalogs
nodeadd ID {"name":"...","server":"IP:порт","sni":"...","server_pub_key":"64 hex","wire_version":4}
nodedel ID ИНДЕКС — нумерация с 1; nodes в subset заменяет весь список
config | configset {"sni":"example.com","up_mbps":0,"down_mbps":0}
configsave {"up_mbps":0} — сохранить в config.json; применить перезапуском
tls | tlsset {полные настройки службы HTTPS-подписок}
reload — перечитать пользователей, не перезапуск VPN
logs [строк=30] | export — все активные ссылки (секреты)
backup | backups | restore ИМЯ_БЭКАПА
service status|start|stop|restart — только служба Atlant
help | cancel
0 в лимитах/сроке — без ограничения. configset меняет только RAM.
Сертификаты tls используются только подписками, не REALITY.
'''

class AdminError(Exception):
    pass


INBOUND_TUNING = {
    'quic': (('max_idle_timeout_sec','quic_idle',86400), ('keep_alive_period_sec','quic_keepalive',3600),
             ('stream_receive_window_mb','quic_stream_window',256), ('conn_receive_window_mb','quic_conn_window',1024),
             ('socket_buffer_size_mb','quic_socket_buffer',64)),
    'yamux': (('max_stream_window_kb','yamux_stream_window',262144), ('keep_alive_period_sec','yamux_keepalive',3600),
              ('write_timeout_sec','yamux_write_timeout',3600)),
}


def validate_inbound_tuning(settings):
    for section, fields in INBOUND_TUNING.items():
        tuning = settings.get(section, {})
        if not isinstance(tuning, dict): raise AdminError('invalid')
        allowed = {key for key, _, _ in fields} | ({'disable_pacer'} if section == 'quic' else {'max_connection_window_kb'})
        if set(tuning)-allowed: raise AdminError('invalid')
        for key, _, maximum in fields:
            value = tuning.get(key, 0)
            if type(value) is not int or not 0 <= value <= maximum: raise AdminError('invalid')
        if section == 'quic' and type(tuning.get('disable_pacer', False)) is not bool: raise AdminError('invalid')
        if section == 'yamux':
            value = tuning.get('max_connection_window_kb', 0)
            if type(value) is not int or not 0 <= value <= 1048576: raise AdminError('invalid')
            if 0 < tuning.get('max_stream_window_kb', 0) < 256: raise AdminError('invalid')
    q = settings.get('quic', {})
    if (q.get('keep_alive_period_sec') or 10) >= (q.get('max_idle_timeout_sec') or 30): raise AdminError('invalid')
    if (q.get('conn_receive_window_mb') or 64) < (q.get('stream_receive_window_mb') or 32): raise AdminError('invalid')

def quota_bytes(text):
    try:
        gb = Decimal(str(text).strip().replace(',', '.'))
        if not gb.is_finite() or gb < 0 or gb > Decimal('1e8'):
            raise ValueError()
        value = int(gb * 1073741824)
        if gb > 0 and value == 0: raise ValueError()
        return value
    except (InvalidOperation, ValueError, OverflowError):
        raise AdminError('Лимит: число от 0 до 100000000 ГиБ, например 0.1 или 0,1; 0 — безлимит.') from None

def quota_input(value):
    if type(value) is not int or value < 0 or value > 2**63-1:
        raise AdminError('invalid_quota')
    for digits in range(11):
        scale = 10**digits
        candidate = (value * scale + 1073741823) // 1073741824
        if candidate * 1073741824 // scale == value:
            return str(candidate) if not digits else f'{candidate // scale}.{candidate % scale:0{digits}d}'
    raise AdminError('invalid_quota')


def replace_private_file(source, destination):
    deadline = time.monotonic() + 1
    while True:
        try:
            os.replace(source, destination)
            return
        except OSError as error:
            if getattr(error, 'winerror', None) not in (5, 32) or time.monotonic() >= deadline:
                raise
            # Never unlink the old file: it remains usable if replacement fails.
            time.sleep(0.01)


def private_write(path, data, permissions=0o600, owner=None):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temp = path.with_name(path.name + '.' + secrets.token_hex(8) + '.tmp')
    try:
        fd = os.open(temp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as out:
            if owner is not None:
                os.fchown(out.fileno(),*owner)
                os.fchmod(out.fileno(),permissions)
            json.dump(data, out, ensure_ascii=False, allow_nan=False)
            out.flush()
            os.fsync(out.fileno())
        replace_private_file(temp, path)
    finally:
        if temp.exists(): temp.unlink()

def load_config(path):
    path = Path(path)
    if os.name == 'posix' and path.stat().st_mode & 0o007:
        raise AdminError('Конфигурация не должна быть доступна посторонним (chmod 640/600).')
    with path.open(encoding='utf-8') as stream: return json.load(stream)

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

class API:
    def __init__(self, config):
        self.base = config['api_url'].rstrip('/')
        parts = urllib.parse.urlsplit(self.base)
        try: local = ipaddress.ip_address(parts.hostname).is_loopback
        except (ValueError,TypeError): local = False
        if parts.scheme != 'http' or not local or parts.username or parts.password or parts.path or parts.query or parts.fragment:
            raise AdminError('API должен быть HTTP на loopback IP; для удалённого сервера используйте SSH-туннель.')
        self.key = config['api_key']
        if not isinstance(self.key, str) or not self.key: raise AdminError('Нет ключа API.')
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def request(self, method, path, body=None, query=None):
        if not path.startswith('/api/') or '?' in path or '#' in path: raise AdminError('Недопустимый API-путь.')
        url = self.base + path + ('?' + urllib.parse.urlencode(query) if query else '')
        data = None if body is None else json.dumps(body, allow_nan=False).encode()
        req = urllib.request.Request(url, data=data, method=method,
            headers={'X-API-Key': self.key, 'Content-Type': 'application/json'})
        try:
            with self.opener.open(req, timeout=15) as response:
                response_limit = 48 * 1024 * 1024 if path == '/api/backup/sqlite' else MAX_BODY
                raw = response.read(response_limit + 1)
        except urllib.error.HTTPError as error:
            failure=AdminError('API: HTTP %s. Проверьте параметры и состояние сервера.' % error.code)
            failure.status_code=error.code
            error.close()
            raise failure from None
        except (OSError, urllib.error.URLError):
            raise AdminError('API недоступен; проверьте службу и адрес loopback.') from None
        if len(raw) > response_limit: raise AdminError('Ответ API слишком большой.')
        try: return json.loads(raw)
        except (ValueError, UnicodeError): return raw.decode('utf-8', errors='replace')

def clean(value):
    if isinstance(value, dict):
        return {k: (v if k in {'server_pub_key','revision'} and isinstance(v,str) and re.fullmatch('[0-9a-fA-F]{64}',v) else '[скрыто]' if k.lower() in {'pbk','link','api_key','api_secret','token','token_hash','key','private_key','admission_tickets'} else clean(v)) for k,v in value.items()}
    if isinstance(value, list): return [clean(v) for v in value]
    if isinstance(value, str):
        value = re.sub(r'atlant-pair://[^\s"<>]+', '[invitation hidden]', value)
        value = re.sub(r'atlant://[^\s"<>]+', '[ссылка скрыта]', value)
        value = re.sub(r'(?i)(/sub/)[A-Za-z0-9_-]{32,}', r'\1[скрыто]', value)
        value = re.sub(r'\b\d{6,}:[A-Za-z0-9_-]{25,}\b', '[токен скрыт]', value)
        value = re.sub(r'\b[0-9a-fA-F]{64}\b', '[ключ скрыт]', value)
    return value

def username(value):
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', value): raise AdminError('Имя: 1–64 латинских букв, цифр, _ или -.')
    if value.lower()=='all': raise AdminError('Имя all зарезервировано сервером для массовых операций; используйте bulk.')
    return value

def identifier(value):
    if not re.fullmatch(r'[0-9a-f]{32}', value): raise AdminError('Нужен ID подписки из /subscriptions.')
    return value

def public_host(value):
    if not isinstance(value,str):return ''
    text=value.strip()
    if not text:return ''
    if '://' in text:text=urllib.parse.urlsplit(text).hostname or ''
    else:
        text=text.strip().strip('[]')
        if text.count(':')==1:text=text.split(':',1)[0]
    text=text.strip().strip('[]').lower()
    return text if text and len(text)<=253 and not any(c in text for c in '/\\ \t\r\n') else ''

def public_ip(value):
    host=public_host(value)
    try:address=ipaddress.ip_address(host)
    except ValueError:return ''
    return address.compressed if address.is_global else ''

def public_address(value):
    """A public IPv4/IPv6 address for a host, preferring the literal value."""
    direct=public_ip(value)
    if direct:return direct
    host=public_host(value)
    if not host:return ''
    try:
        for info in socket.getaddrinfo(host,None,proto=socket.IPPROTO_TCP):
            resolved=public_ip(info[4][0])
            if resolved:return resolved
    except (OSError, UnicodeError):pass
    return ''

def object_json(text):
    try: value = json.loads(text, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except ValueError: raise AdminError('Ожидается JSON-объект: {"поле":значение}.') from None
    if not isinstance(value, dict): raise AdminError('Ожидается JSON-объект.')
    return value

class Manager:
    def __init__(self, config, api=None):
        self.api = api or API(config)
        self.language = language(config.get('language', 'ru'))
        self.state = Path(config.get('state_dir','/var/lib/atlant-admin'))
        self.panel = config.get('panel',{})
        panel_state=self.panel.get('state_dir',config.get('state_dir','/var/lib/atlant-control'))
        def panel_writer(path,data):
            owner=None
            credential=Path(panel_state)/'credentials.json'
            if os.name=='posix' and credential.exists():
                if credential.is_symlink():raise AdminError('invalid')
                info=credential.stat();owner=(info.st_uid,info.st_gid)
                if Path(path).parent==Path(panel_state)/'panel-backups':
                    if Path(path).parent.is_symlink():raise AdminError('invalid')
                    os.chown(Path(path).parent,*owner)
            private_write(path,data,owner=owner)
        self.certificates = CertificateJobs(config.get('certificate_agent',{}),panel_state,private_write)
        self.panel_settings=PanelSettings(self.panel,panel_state,self.certificates,panel_writer)
        self.peers=Peers(panel_state,lambda:self.panel_settings.effective()['origin'],config.get('peer_ca_file'),config.get('peer_allow_private_networks',False) is True)
        self.helper = config.get('service_helper','/usr/local/libexec/atlant-service-action')
        self.helper_socket=config.get('service_socket')

    def certificate_call(self,method,*args):
        try:return getattr(self.certificates,method)(*args)
        except CertificateJobError as error:raise AdminError(str(error)) from None

    def certificate_defaults(self,current):
        """Everything the panel needs for a new job, derived from the panel address."""
        used={job['id'] for job in current.get('jobs',[]) if isinstance(job,dict) and isinstance(job.get('id'),str)}
        name,index='panel',2
        while name in used:
            name='panel-%d'%index;index+=1
        origin=''
        try:origin=public_host(self.panel_settings.effective().get('origin',''))
        except (PanelSettingsError,CertificateJobError,OSError,ValueError,TypeError):pass
        ip=domain=''
        try:literal=ipaddress.ip_address(origin)
        except ValueError:literal=None
        if literal is not None:
            ip=literal.compressed if literal.is_global else ''
        elif origin:
            domain=origin;ip=public_address(origin)
        return {'id':name,'mode':'acme-ip' if ip else 'acme-domain','host':ip or domain,'ip':ip,'domain':domain,
                'email':'','accept_terms':True,'staging':False}

    def panel_call(self,method,*args):
        try:return getattr(self.panel_settings,method)(*args)
        except (PanelSettingsError,CertificateJobError) as error:raise AdminError(str(error)) from None

    def peer_call(self,method,*args):
        try:return getattr(self.peers,method)(*args)
        except PeerError as error:raise AdminError(str(error)) from None
        except (OSError,ValueError,sqlite3.Error):raise AdminError('peer_storage') from None

    def peer_execute(self,remote,command):
        """Only explicitly granted inbound operations, never arbitrary admin commands."""
        try:
            self.peers.admin_command(command)
            action=self.prepare(command)
            self.audit('peer '+remote+' '+action['label'],'authorized')
            result=self.execute(action)
            return {'ok':True,'result':result.get('result',result)}
        except (AdminError,PeerError):return {'ok':False,'error':'peer_operation_failed'}

    def helper_call(self, action, body=None):
        if self.helper_socket:
            from control.service_client import request
            try:return request(self.helper_socket,action,body)
            except (OSError,ValueError,KeyError):raise AdminError('Операция службы не выполнена; проверьте журнал локально.') from None
        if action not in {'status','start','stop','restart','configsave'}: raise AdminError('Недопустимая операция службы.')
        command = [self.helper, action]
        if os.name == 'posix' and os.geteuid() != 0: command = ['/usr/bin/sudo','-n'] + command
        try:
            result = subprocess.run(command, input=json.dumps(body) if body is not None else '',
                text=True, capture_output=True, timeout=50, check=False)
        except (OSError, subprocess.TimeoutExpired): raise AdminError('Управление службой недоступно или истёк таймаут.') from None
        if result.returncode: raise AdminError('Операция службы не выполнена; проверьте журнал локально.')
        try: return json.loads(result.stdout)
        except ValueError: raise AdminError('Некорректный ответ помощника службы.') from None

    def prepare(self, text):
        text = text.strip().lstrip('/')
        command, _, tail = text.partition(' ')
        command = command.split('@')[0].lower()
        tail = tail.strip()
        a = {'label':command, 'method':'GET', 'path':'', 'body':None, 'query':{}, 'write':False, 'secret':False}
        def need(n=1):
            args=shlex.split(tail)
            if len(args)!=n: raise AdminError('Проверьте аргументы: /help.')
            return args
        def write(path, body=None, method='POST', query=None):
            a.update(path=path, body=body, method=method, query=query or {}, write=True)
        if command in {'start','help','cancel','license'}: a['local']=command
        elif command=='panelurl':
            need(0)
            from control.access import entry_path
            a.update(local='result',secret=True,result=self.panel_settings.effective()['origin']+entry_path(self.panel_settings.state))
        elif command=='peers':need(0);a['local']='peer_read'
        elif command=='peercatalog':
            remote=need()[0];identifier(remote)
            a.update(local='peer_catalog',remote=remote)
        elif command=='peerjobs':
            remote=need()[0];identifier(remote)
            a.update(local='peer_jobs',remote=remote)
        elif command=='peersync':
            remote=need()[0];identifier(remote)
            a.update(local='peer_sync',remote=remote,write=True,label='peersync '+remote,label_key='peersync',target=remote)
        elif command=='peergrant':
            remote,enabled=need(2);identifier(remote)
            if enabled not in ('true','false'):raise AdminError('invalid')
            a.update(local='peer_write',operation='grant',arguments=[remote,enabled=='true'],write=True,label='peergrant '+remote,label_key='peergrant',target=remote+' · '+enabled)
        elif command=='peerexecute':
            remote,nested=need(2);identifier(remote);self.peer_call('admin_command',nested)
            self.prepare(nested)
            a.update(local='peer_write',operation='admin',arguments=[remote,nested],write=True,label='peerexecute '+remote+' '+nested.partition(' ')[0],label_key='peerexecute',target=remote+' · '+nested.partition(' ')[0])
        elif command=='peerretry':
            remote,request=need(2);identifier(remote);identifier(request)
            a.update(local='peer_write',operation='retry',arguments=[remote,request],write=True,label='peerretry '+remote+' '+request)
        elif command in {'peerinvite','peerjoin','peerapprove','peerfinish','peerreject','peercancel','peerrevoke'}:
            methods={'peerinvite':'invite','peerjoin':'join','peerapprove':'approve','peerfinish':'finish','peerreject':'reject','peercancel':'cancel','peerrevoke':'revoke'}
            arguments=need(0 if command=='peerinvite' else 1)
            if command in {'peerinvite','peerjoin'}:self.peer_call('current_origin')
            if command=='peerjoin':self.peer_call('parse_invite',arguments[0])
            elif arguments:identifier(arguments[0])
            a.update(local='peer_write',operation=methods[command],arguments=arguments,write=True,secret=command=='peerinvite')
        elif command=='paneltls':
            need(0);a['local']='paneltls'
        elif command in {'panelsettings','panelbackups'}:
            need(0);a['local']=command
        elif command in {'panelbackup','certbackup'}:
            need(0);a.update(local=command,write=True)
        elif command=='configinfo':
            need(0);a['local']='configinfo'
        elif command in {'panelset','panelrestore'}:
            if command=='panelset':prepared=self.panel_call('prepare',object_json(tail))
            else:
                parts=shlex.split(tail)
                if not 1<=len(parts)<=2:raise AdminError('panel_settings_invalid')
                prepared=self.panel_call('prepare_restore',parts[0],parts[1] if len(parts)==2 else None)
            a.update(local='panel_write',panel_settings=prepared,write=True,label=command)
        elif command=='certjobs':
            need(0);a['local']='certificate_read'
        elif command=='certlisten':
            parts=shlex.split(tail)
            if not 1<=len(parts)<=2:raise AdminError('certificate_invalid')
            prepared=self.certificate_call('prepare_listener',parts[0],parts[1] if len(parts)==2 else None)
            a.update(local='certificate_write',certificate=prepared,write=True,label='certlisten')
        elif command=='certbackups':
            need(0);a['local']='certificate_backups'
        elif command=='certrestore':
            parts=shlex.split(tail)
            if not 1<=len(parts)<=2:raise AdminError('certificate_invalid')
            prepared=self.certificate_call('prepare_restore',parts[0],parts[1] if len(parts)==2 else None)
            a.update(local='certificate_write',certificate=prepared,write=True,label='certrestore '+parts[0])
        elif command in {'certjobcreate','certjobset','certjobdelete'}:
            name,_,payload=tail.partition(' ')
            has_listener=False;listener=None
            if command=='certjobdelete':
                parts=shlex.split(payload)
                if len(parts)>1:raise AdminError('certificate_invalid')
                patch,expected=None,parts[0] if parts else None
            else:
                patch=object_json(payload);expected=patch.pop('revision',None)
                has_listener='challenge_listen' in patch
                listener=patch.pop('challenge_listen',None)
            prepared=self.certificate_call('prepare',command,name,patch,expected)
            if has_listener:
                listener_config=self.certificate_call('prepare_listener',listener,prepared['revision'])
                prepared['config']['challenge_listen']=listener_config['config']['challenge_listen']
            a.update(local='certificate_write',certificate=prepared,write=True,label=command+' '+name)
            if command=='certjobcreate':a.update(label_key='certificate_create',target=patch.get('host',name))
        elif command in {'status','online','config','tls','export'}:
            need(0)
            a['path']={'status':'/api/status','online':'/api/online','config':'/api/config','tls':'/api/subscription-service','export':'/api/export'}[command]
            a['secret']=command=='export'
        elif command=='users':
            args=shlex.split(tail)
            page=int(args[0]) if args else 1
            if page<1 or len(args)>2: raise AdminError('users [страница>=1] [поиск]')
            a.update(path='/api/users',query={'limit':8,'offset':(page-1)*8,'sort':'name','search':args[1] if len(args)>1 else ''},page=page)
        elif command=='usersall':
            need(0);a['local']='users_all'
        elif command in {'user','link','enable','disable','kick','delete','reset','rekey'}:
            name=username(need()[0]); a['label']=command+' '+name
            if command in {'user','link'}:
                a.update(path='/api/sub' if command=='link' else '/api/user',query={'name':name},secret=command=='link')
            else:
                operation={'reset':'reset-traffic','rekey':'regenerate-key'}.get(command,command)
                write('/api/user/'+operation,query={'name':name})
        elif command=='add':
            args=shlex.split(tail)
            if not 1<=len(args)<=3: raise AdminError('add ИМЯ [ГиБ] [дней]')
            name=username(args[0]); quota=quota_bytes(args[1]) if len(args)>1 else 0
            days=int(args[2]) if len(args)>2 else 0
            if not 0<=days<=36500: raise AdminError('Недопустимый срок.')
            # The API create endpoint is an upsert; never silently overwrite an account.
            users=self.api.request('GET','/api/users',query={'search':name})['users']
            if any(u['name']==name for u in users): raise AdminError('Пользователь уже существует; используйте set.')
            write('/api/user/create',{'name':name,'total_limit':quota,'expires_at':int(time.time())+days*86400 if days else 0,'enabled':True})
            a['label']='add '+name
        elif command=='usercreate':
            body=object_json(tail)
            if not body or set(body)-{'name','total_limit','expires_at','ip_limit','enabled','note'}: raise AdminError('Недопустимые поля конфигурации.')
            username(body.get('name',''))
            write('/api/user/create',body);a['label']='add '+body['name']
        elif command=='set':
            name,_,payload=tail.partition(' '); username(name)
            body=object_json(payload)
            if not body or set(body)-{'total_limit','expires_at','ip_limit','enabled','note'}: raise AdminError('Разрешены total_limit, expires_at, ip_limit, enabled, note.')
            write('/api/user/update',dict(body,name=name)); a['label']='set '+name
        elif command=='bulk':
            args=shlex.split(tail)
            if len(args)<2 or len(args)>101 or args[0] not in {'enable','disable','delete','reset'}: raise AdminError('bulk enable|disable|delete|reset ИМЕНА (до 100)')
            op='reset-traffic' if args[0]=='reset' else args[0]
            write('/api/users/bulk-'+op,{'names':[username(n) for n in args[1:]]}); a['label']='bulk '+op+' ('+str(len(args)-1)+')'
        elif command in {'inbounds','appliedinbounds','remotecatalogs'}:
            need(0);a['path']={'inbounds':'/api/inbounds','appliedinbounds':'/api/inbounds/applied','remotecatalogs':'/api/control/catalogs'}[command]
        elif command in {'inboundcreate','inboundset','inbounddelete','inboundapply'}:
            revision,_,payload=tail.partition(' ')
            if not re.fullmatch(r'[1-9][0-9]{0,18}',revision) or int(revision)>9223372036854775807:raise AdminError('invalid')
            body={'revision':int(revision)}
            if command in {'inboundcreate','inboundset'}:
                settings=object_json(payload)
                allowed={'id','name','enabled','listen','advertise_addr','sni','transports','wire_version','xhttp_path','up_mbps','down_mbps','quic','yamux'}
                if set(settings)-allowed or not {'id','name','enabled','listen','sni','transports','wire_version'}<=set(settings):raise AdminError('invalid')
                if not isinstance(settings['id'],str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}',settings['id']):raise AdminError('invalid')
                if type(settings['enabled']) is not bool or type(settings['wire_version']) is not int or settings['wire_version']!=7:raise AdminError('invalid')
                if not isinstance(settings['transports'],list) or not settings['transports'] or any(value not in ('tcp','xhttp','quic') for value in settings['transports']) or len(settings['transports'])!=len(set(settings['transports'])):raise AdminError('invalid')
                validate_inbound_tuning(settings)
                body['settings']=settings
            elif command=='inbounddelete':
                if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}',payload):raise AdminError('invalid')
                body['id']=payload
            elif payload:raise AdminError('invalid')
            write('/api/inbounds/apply' if command=='inboundapply' else '/api/inbounds',body,'PUT' if command=='inboundset' else 'DELETE' if command=='inbounddelete' else 'POST')
        elif command=='subscribercreate':
            body=object_json(tail)
            if set(body)-{'title','enabled','expires_at','update_hours','support_url','announcement','total_limit','inbound_refs','ip_limit','note'} or not body.get('title') or not isinstance(body.get('inbound_refs'),list) or not body['inbound_refs']:raise AdminError('invalid')
            body.setdefault('enabled',True);body.setdefault('expires_at',0);body.setdefault('update_hours',1);body.setdefault('total_limit',0)
            write('/api/subscriptions',body)
            a['secret']=True
        elif command=='subscriptions': need(0); a['path']='/api/subscriptions'
        elif command in {'subshare','subshareimport'}:
            parts=need(1 if command=='subshare' else 2);sid=parts[0];identifier(sid)
            if not any(s['id']==sid for s in self.api.request('GET','/api/subscriptions')):raise AdminError('Подписка не найдена.')
            a.update(local='subscription_link',sid=sid,secret=True,label=command+' '+sid)
            if command=='subshareimport':
                from control.subscription_links import validated_link
                a.update(url=validated_link(parts[1]),write=True)
        elif command=='submigration':need(0);a['path']='/api/subscriptions/migrate'
        elif command=='submigrate':
            parts=shlex.split(tail)
            if not 2<=len(parts)<=101 or not re.fullmatch(r'[0-9a-f]{64}',parts[0]):raise AdminError('invalid')
            ids=[identifier(value) for value in parts[1:]]
            if len(set(parts[1:]))!=len(parts)-1:raise AdminError('invalid')
            write('/api/subscriptions/migrate',{'revision':parts[0],'ids':parts[1:]})
        elif command in {'subkick','subrekey'}:
            sid=need()[0];identifier(sid)
            records=self.api.request('GET','/api/subscriptions')
            record=next((record for record in records if record['id']==sid),None)
            if not record: raise AdminError('Подписка не найдена.')
            if not record.get('managed'): raise AdminError('native_subscriber_required')
            name=username(record['user'])
            write('/api/user/'+('kick' if command=='subkick' else 'regenerate-key'),query={'name':name})
            a['label']=command+' '+sid
            a['label_key'],a['target']=command,sid
        elif command=='groups': need(0);a['path']='/api/groups'
        elif command in {'groupcreate','groupset','groupdelete'}:
            if command=='groupcreate':
                patch=object_json(tail)
                if set(patch)-{'name','note','users'} or not patch.get('name'): raise AdminError('Недопустимые поля группы.')
                write('/api/groups',dict({'note':''},**patch),'POST')
            else:
                gid,_,payload=tail.partition(' ');identifier(gid)
                groups=self.api.request('GET','/api/groups')
                record=next((group for group in groups if group['id']==gid),None)
                if record is None: raise AdminError('Группа не найдена.')
                body={key:record[key] for key in ('id','name','note','revision')}
                if command=='groupdelete':
                    if payload: raise AdminError('Недопустимые аргументы группы.')
                    write('/api/groups',body,'DELETE')
                else:
                    patch=object_json(payload)
                    if not patch or set(patch)-{'name','note','users','revision'}: raise AdminError('Недопустимые поля группы.')
                    body.update(patch);write('/api/groups',body,'PUT')
            a['label']=command+' '+str(a['body'].get('name',''))
        elif command in {'quotanodes','quotabindings'}:
            need(0);a['path']='/api/quota/'+('nodes' if command=='quotanodes' else 'bindings')
        elif command in {'quotaenroll','quotadisable'}:
            parts=shlex.split(tail)
            if len(parts)<1 or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}',parts[0]) or parts[0]=='local': raise AdminError('Нужен ID VDS: латинские буквы, цифры, _ и -.')
            for sid in parts[1:]: identifier(sid)
            if command=='quotaenroll' and len(parts)<2: raise AdminError('Укажите хотя бы одну подписку.')
            if command=='quotadisable' and len(parts)!=1: raise AdminError('quotadisable VDS_ID')
            write('/api/quota/nodes',{'id':parts[0],'subscriptions':parts[1:],'enabled':command=='quotaenroll'},'POST' if command=='quotaenroll' else 'DELETE')
            a['secret']=command=='quotaenroll'
        elif command=='quotaset':
            node,_,payload=tail.partition(' ')
            if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}',node) or node=='local':raise AdminError('Нужен ID VDS: латинские буквы, цифры, _ и -.')
            patch=object_json(payload)
            if not patch or set(patch)-{'enabled','subscriptions'}:raise AdminError('Недопустимые поля узла квот.')
            records=self.api.request('GET','/api/quota/nodes') or []
            record=next((record for record in records if record['id']==node),None)
            if record is None:raise AdminError('Узел квот не найден.')
            body={'id':node,'enabled':record['enabled'],'subscriptions':record['subscriptions']}
            body.update(patch)
            if not isinstance(body['enabled'],bool) or not isinstance(body['subscriptions'],list):raise AdminError('Недопустимые поля узла квот.')
            for sid in body['subscriptions']:identifier(sid)
            write('/api/quota/nodes',body,'PUT');a['label']='quotaset '+node
        elif command=='quotabind':
            name,sid=need(2);username(name);identifier(sid)
            write('/api/quota/bindings',{'user':name,'subscription':sid},'PUT')
        elif command=='subattach':
            sid,name,index=need(3);identifier(sid);username(name)
            index=int(index)
            if index<1 or index>256: raise AdminError('Индекс узла вне списка.')
            write('/api/subscription-account',{'subscription':sid,'user':name,'node':index})
            a['label']='subattach '+sid+' '+name
        elif command=='subquota':
            sid,value=need(2);identifier(sid);quota=quota_bytes(value)
            if quota>1<<60: raise AdminError('Лимит слишком велик.')
            records=self.api.request('GET','/api/subscriptions');record=next((dict(s) for s in records if s['id']==sid),None)
            if record is None: raise AdminError('Подписка не найдена.')
            record['total_limit']=quota;write('/api/subscriptions',record,'PUT')
        elif command in {'sub','subset','subrotate','subdelete','nodeadd','nodeset','nodedel'}:
            sid,_,payload=tail.partition(' '); identifier(sid)
            a['label']=command+' '+sid
            if command=='subdelete':
                need(); write('/api/subscriptions',method='DELETE',query={'id':sid})
            else:
                records=self.api.request('GET','/api/subscriptions')
                record=next((s for s in records if s['id']==sid),None)
                if not record: raise AdminError('Подписка не найдена.')
                record=dict(record);record.pop('token_hash',None)
                if command=='sub': need(); a.update(local='result',result=record)
                else:
                    if command=='subset':
                        patch=object_json(payload)
                        if not patch or set(patch)-{'title','enabled','expires_at','update_hours','support_url','announcement','nodes','total_limit','revision','inbound_refs','ip_limit','note'}: raise AdminError('Недопустимые поля подписки.')
                        record.update(patch)
                    elif command=='nodeadd':
                        node=object_json(payload)
                        if 'revision' in node:record['revision']=node.pop('revision')
                        if set(node)-{'name','server','sni','server_pub_key','user','pbk','transport','wire_version','path'}: raise AdminError('Недопустимые поля подключения.')
                        node.setdefault('transport','reality')
                        record['nodes']=record['nodes']+[node]
                    elif command=='nodeset':
                        position,_,patch=payload.partition(' ')
                        index=int(position)-1
                        if not 0<=index<len(record['nodes']): raise AdminError('Индекс узла вне списка.')
                        patch=object_json(patch)
                        if 'revision' in patch:record['revision']=patch.pop('revision')
                        if not patch or set(patch)-{'name','server','sni','server_pub_key','user','pbk','transport','wire_version','path'}: raise AdminError('Недопустимые поля подключения.')
                        # Read keys from the authenticated core, not the redacted
                        # browser view. Omitting pbk preserves a remote account.
                        nodes=list(record['nodes']);nodes[index]=dict(nodes[index],**patch)
                        record['nodes']=nodes
                    elif command=='nodedel':
                        parts=shlex.split(payload)
                        if len(parts) not in (1,2):raise AdminError('Индекс узла вне списка.')
                        index=int(parts[0])-1
                        if len(parts)==2:record['revision']=parts[1]
                        if not 0<=index<len(record['nodes']): raise AdminError('Индекс узла вне списка.')
                        record['nodes']=[v for i,v in enumerate(record['nodes']) if i!=index]
                    else: need();record['rotate']=True
                    a['secret']=command=='subrotate'
                    write('/api/subscriptions',record,'PUT')
        elif command=='subcreate':
            name,_,title=tail.partition(' ');username(name)
            if not title or len(title)>256: raise AdminError('subcreate ИМЯ Заголовок подписки')
            config=self.api.request('GET','/api/config')
            user=self.api.request('GET','/api/user',query={'name':name})
            link=urllib.parse.urlsplit(user.get('link',''))
            if link.scheme!='atlant' or not link.hostname or not link.port:raise AdminError('Сервер не выдал корректный endpoint пользователя.')
            params=urllib.parse.parse_qs(link.query)
            wire=int(params.get('wire_version',['4'])[0])
            node={'name':'Atlant','server':config.get('advertise_addr') or link.netloc,'sni':config['sni'],
                'server_pub_key':config['server_pub_key'],'transport':'reality','wire_version':wire}
            write('/api/subscriptions',{'user':name,'title':title,'enabled':True,'expires_at':0,'update_hours':1,'nodes':[node]})
            a['secret']=True;a['label']='subcreate '+name
        elif command in {'configset','tlsset','configsave'}:
            body=object_json(tail)
            if command=='configset':
                if not body or set(body)-{'sni','advertise_addr','up_mbps','down_mbps'}: raise AdminError('Недопустимые поля конфигурации.')
                write('/api/config/update',body)
            elif command=='tlsset': write('/api/subscription-service',body,'PUT')
            else:
                if self.helper_socket:body=self.helper_call('configcheck',body)
                a.update(local='configsave',body=body,write=True)
        elif command=='reload': need(0);write('/api/server/reload',{})
        elif command=='logs':
            lines=int(need()[0]) if tail else 30
            if not 1<=lines<=200: raise AdminError('От 1 до 200 строк.')
            a.update(path='/api/logs',query={'lines':lines})
            if self.helper_socket:a.update(local='logs',lines=lines)
        elif command in {'backup','backups'}: need(0);a['local']=command
        elif command=='backuptrash':
            need(0);a['local']='backup_trash'
        elif command in {'backupremove','backuprecover'}:
            kind,name=need(2)
            prefixes={'data':'backup','panel':'panel-settings','certificate':'cert-config'}
            if kind not in prefixes or not re.fullmatch(prefixes[kind]+r'-[0-9TZ-]+-[a-f0-9]{8}\.json',name):raise AdminError('invalid')
            a.update(local='backup_move',kind=kind,backup=name,recover=command=='backuprecover',write=True)
        elif command=='restore':
            name=need()[0]
            if not re.fullmatch(r'backup-[0-9TZ-]+-[a-f0-9]{8}\.json',name): raise AdminError('Выберите имя из backups.')
            a.update(local='restore',backup=name,write=True)
        elif command in {'service','certservice'}:
            op=need()[0]
            if op not in {'status','start','stop','restart'}: raise AdminError('service status|start|stop|restart')
            if command=='certservice' and not self.helper_socket:raise AdminError('service_socket_required')
            a.update(local='service',operation=('cert-' if command=='certservice' else '')+op,write=op!='status',label=command+' '+op)
        else: raise AdminError('Неизвестная команда. /help')
        return a

    @staticmethod
    def needs_database_backup(action):
        # Backups are explicit user actions, never a side effect of a mutation.
        return False

    def archive_backups(self):
        folder=self.state/'backups';archive=self.state/'backup-archive'
        if folder.is_symlink() or archive.is_symlink():raise AdminError('invalid')
        existing=sorted(folder.glob('backup-*.json'),key=lambda p:p.stat().st_mtime)
        total=sum(p.stat().st_size for p in existing)
        # Reserve room for a maximum-size new snapshot. Keep every older file
        # recoverable in the archive instead of deleting user backups.
        while existing and (len(existing)>=500 or total>208*1024*1024):
            source=existing.pop(0)
            if source.is_symlink() or not source.is_file() or source.resolve().parent!=folder.resolve():raise AdminError('invalid')
            archive.mkdir(parents=True,exist_ok=True,mode=0o700)
            target=archive/source.name
            if target.exists() or target.is_symlink():raise AdminError('invalid')
            size=source.stat().st_size
            source.rename(target);total-=size

    def backup(self):
        self.archive_backups()
        try: data=self.api.request('GET','/api/backup')
        except AdminError as error:
            if getattr(error,'status_code',None)!=409: raise
            data=self.api.request('GET','/api/backup/sqlite')
        valid=isinstance(data,dict) and isinstance(data.get('users'),dict)
        if isinstance(data,dict) and data.get('format')=='sqlite3-base64-v1':
            try:
                raw=base64.b64decode(data.get('database',''),validate=True)
                valid=raw.startswith(b'SQLite format 3\x00') and len(raw)<=32*1024*1024 and data.get('recovery')=='coordinated-offline-only'
            except (ValueError,TypeError): valid=False
        if not valid: raise AdminError('Некорректный бэкап API; изменение отменено.')
        folder=self.state/'backups'
        folder.mkdir(parents=True,exist_ok=True,mode=0o700)
        existing=list(folder.glob('backup-*.json'))
        if len(existing)>=500 or sum(p.stat().st_size for p in existing)>256*1024*1024:
            raise AdminError('Хранилище бэкапов заполнено; перенесите старые копии локально. Изменение отменено.')
        stamp=dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        name='backup-'+stamp+'-'+secrets.token_hex(4)+'.json'
        private_write(folder/name,data)
        return name

    def execute(self,a):
        local=a.get('local'); backup=None
        if a['write']:
            self.audit(a['label'],'begin')
        if local in {'start','help'}: result=help_text(self.language)
        elif local=='license':result=Path(__file__).with_name('LICENSE').read_text(encoding='utf-8')
        elif local=='cancel': result={'cancelled':True}
        elif local=='result': result=a['result']
        elif local=='users_all':
            records=[]
            for offset in range(0,10000,100):
                batch=self.api.request('GET','/api/users',query={'limit':100,'offset':offset,'sort':'name'})['users']
                records.extend(batch)
                if len(batch)<100:break
            else:raise AdminError('Too many users; use paginated search')
            result={'users':records,'total':len(records)}
        elif local=='subscription_link':
            from control.subscription_links import access,verify
            if a.get('url'):verify(self.api,a['sid'],a['url'])
            result={'url':access(self.state,a['sid'],a.get('url'))}
        elif local=='peer_read':result=self.peer_call('info')
        elif local=='peer_catalog':result=self.peer_call('call',a['remote'],'inbounds')
        elif local=='peer_jobs':result=self.peer_call('jobs',a['remote'])
        elif local=='peer_sync':
            catalog=self.peer_call('call',a['remote'],'appliedinbounds')
            if not isinstance(catalog,dict) or set(catalog)!={'server_id','revision','inbounds'}:raise AdminError('peer_invalid')
            result=self.api.request('POST','/api/control/catalogs',dict(catalog,peer_id=a['remote']))
        elif local=='peer_write':result=self.peer_call(a['operation'],*a['arguments'])
        elif local=='backup': result={'backup':self.backup(),'location':'server-only'}
        elif local=='backups': result={'backups':sorted({p.name for folder in ('backups','backup-archive') for p in (self.state/folder).glob('backup-*.json')},reverse=True)[:40]}
        elif local=='backup_trash':
            result=[]
            for kind,base in [('data',self.state),('panel',self.panel_settings.state),('certificate',self.certificates.state)]:
                folder=base/'backup-trash'/kind
                if folder.is_symlink():raise AdminError('invalid')
                if folder.exists():result.extend({'kind':kind,'name':path.name} for path in sorted(folder.glob('*.json')) if path.is_file() and not path.is_symlink())
        elif local=='backup_move':
            kind=a['kind']
            folder={'data':self.state/'backups','panel':self.panel_settings.state/'panel-backups','certificate':self.certificates.state/'backups'}[kind]
            trash={'data':self.state,'panel':self.panel_settings.state,'certificate':self.certificates.state}[kind]/'backup-trash'/kind
            if folder.is_symlink() or trash.parent.is_symlink() or trash.is_symlink():raise AdminError('invalid')
            trash.mkdir(parents=True,exist_ok=True,mode=0o700)
            source,target=(trash/a['backup'],folder/a['backup']) if a['recover'] else (folder/a['backup'],trash/a['backup'])
            if kind=='data' and not a['recover'] and not source.exists():source=self.state/'backup-archive'/a['backup']
            if source.parent.is_symlink():raise AdminError('invalid')
            if source.is_symlink() or not source.is_file() or target.exists() or target.is_symlink():raise AdminError('invalid')
            folder.mkdir(parents=True,exist_ok=True,mode=0o700)
            source.rename(target)
            result={'recovered':a['recover'],'moved_to_trash':not a['recover']}
        elif local=='restore':
            path=self.state/'backups'/a['backup']
            if not path.exists():path=self.state/'backup-archive'/a['backup']
            if path.parent.is_symlink():raise AdminError('invalid')
            if not path.is_file() or path.is_symlink() or path.stat().st_size>MAX_BODY: raise AdminError('Бэкап не найден или слишком большой.')
            data=json.loads(path.read_text(encoding='utf-8'))
            if data.get('format')=='sqlite3-base64-v1': raise AdminError('Эта копия содержит общую квоту. Восстановление SQLite требует остановки всех узлов; онлайн-откат запрещён.')
            result=self.api.request('POST','/api/restore',data)
        elif local=='service': result=self.helper_call(a['operation'])
        elif local=='logs':result=self.helper_call('logs',{'lines':a['lines']})
        elif local=='configsave': result=self.helper_call('configsave',a['body'])
        elif local=='configinfo':result=self.helper_call('configinfo') if self.helper_socket else {'verified':False,'overridden_fields':[]}
        elif local=='certificate_read':
            result=self.certificate_call('read')
            result['defaults']=self.certificate_defaults(result)
        elif local=='certificate_backups':result=self.certificate_call('backups')
        elif local=='panelsettings':result=self.panel_call('read')
        elif local=='panelbackups':result=self.panel_call('backups')
        elif local=='panelbackup':result={'backup':self.panel_call('backup')}
        elif local=='certbackup':result={'backup':self.certificate_call('backup')}
        elif local=='panel_write':
            try:result=self.panel_call('commit',a['panel_settings'])
            except (AdminError,OSError):self.audit(a['label'],'failed');raise
            backup=result.pop('safety_backup',None)
        elif local=='certificate_write':
            try:result=self.certificate_call('commit',a['certificate'])
            except (AdminError,OSError):self.audit(a['label'],'failed');raise
            backup=result.pop('safety_backup',None)
        elif local=='paneltls':
            from control.tls import from_panel_settings
            manager=from_panel_settings(self.panel_settings.effective())
            result=dict(manager.status() if manager else {'mode':'unconfigured'},source='local-files-not-live-listener')
        else:
            if a['label'].startswith('add '):
                name=a['body']['name']
                users=self.api.request('GET','/api/users',query={'search':name})['users']
                if any(u['name']==name for u in users): raise AdminError('Пользователь уже существует; создание отменено.')
            result=self.api.request(a['method'],a['path'],a['body'],a['query'])
        if isinstance(result,dict) and result.get('url') and isinstance(result.get('subscription'),dict):
            from control.subscription_links import access
            try:access(self.state,result['subscription']['id'],result['url'])
            except (OSError,ValueError,sqlite3.Error):result['link_cache_saved']=False
        if a['label'].startswith('link '): result={'link':result if isinstance(result,str) else result.get('link','')}
        if a['label'].startswith('subrekey '):result={'success':True,'refresh_subscription':True}
        if not a['secret']: result=clean(result)
        if a['write']:
            self.audit(a['label'],'done')
            result={'result':result,'safety_backup':backup}
        return result

    def audit(self,label,event):
        self.state.mkdir(parents=True,exist_ok=True,mode=0o700)
        path=self.state/'audit.jsonl'
        if path.exists() and path.stat().st_size>2*1024*1024:
            os.replace(path,self.state/'audit.previous.jsonl')
        fd=os.open(path,os.O_CREAT|os.O_WRONLY|os.O_APPEND,0o600)
        with os.fdopen(fd,'a',encoding='utf-8') as out:
            out.write(json.dumps({'time':int(time.time()),'operation':label,'event':event},ensure_ascii=False)+'\n')

def main():
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, 'reconfigure'):
            stream.reconfigure(encoding='utf-8')
    p=argparse.ArgumentParser(description='Atlant server management. Use help for operations.')
    p.add_argument('--config',default='/etc/atlant-control/client.json' if Path('/etc/atlant-control/client.json').is_file() else '/etc/atlant-admin/client.json')
    p.add_argument('--yes',action='store_true',help='Confirm mutations without a prompt')
    p.add_argument('--lang',choices=('en','ru','zh'),help='Interface language: English, Russian, Simplified Chinese')
    p.add_argument('command',nargs=argparse.REMAINDER)
    args=p.parse_args()
    try:
        line=' '.join(args.command) or ('menu' if sys.stdin.isatty() else 'help')
        if line=='license':print(Path(__file__).with_name('LICENSE').read_text(encoding='utf-8'));return
        if line in {'help','--help'}:
            if not args.lang:
                try:
                    from control.console import saved_language
                    preference=load_config(args.config)
                    args.lang=saved_language(preference.get('state_dir','/var/lib/atlant-admin'),'en')
                except (AdminError,ValueError,OSError):pass
            print(panel_cli_help(args.lang or 'en'));return
        config=load_config(args.config)
        from control.console import saved_language
        args.lang=args.lang or saved_language(config.get('state_dir','/var/lib/atlant-admin'),'en')
        config['language']=args.lang
        verb=line.partition(' ')[0]
        if verb not in PANEL_CLI_COMMANDS:
            raise AdminError('cli_panel_scope')
        manager=Manager(config)
        if line=='panelpassword':
            from control.access import set_password
            set_password(manager.panel_settings.state,args.lang,private_write)
            print(message('cli_password_saved',args.lang));return
        if line=='menu':
            from control.console import Console
            Console(manager,args.lang).run()
            return
        if verb=='logs':
            from control.console import Console
            parts=shlex.split(line)
            lines=int(parts[1]) if len(parts)==2 else 50
            if len(parts)>2 or not 1<=lines<=200:raise ValueError()
            try:Console(manager,args.lang).logs_menu(lines)
            except (EOFError,KeyboardInterrupt):print(message('cancelled',args.lang))
            return
        action=manager.prepare(line)
        if action['write'] and not args.yes:
            if input(message('confirm',args.lang,operation=action['label']))!='yes': raise AdminError('Отменено.')
        result=manager.execute(action)
        print(result if isinstance(result,str) else json.dumps(result,ensure_ascii=False,indent=2))
    except (AdminError,ValueError,OSError,KeyError) as error:
        print(error_message(error,args.lang) if isinstance(error,AdminError) else message('invalid',args.lang),file=sys.stderr)
        raise SystemExit(1)

if __name__=='__main__': main()
