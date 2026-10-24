import ast
import http.client
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import Mock

from atlantctl import AdminError, Manager
from control.i18n import ERRORS, LANGUAGES, catalog, error_message, help_text, language
from control.security import Authentication, Operations, password_record, verify_password
from control.server import PanelServer, origin_parts
from test_atlantctl import FakeAPI


class TranslationTests(unittest.TestCase):
    def test_catalogs_have_identical_nonempty_keys(self):
        keys = set(catalog('en'))
        for lang in LANGUAGES:
            self.assertEqual(keys, set(catalog(lang)))
            self.assertTrue(all(catalog(lang).values()))
            self.assertIn('subquota ID GiB', help_text(lang))
            self.assertIn('acme-ip', help_text(lang))

    def test_locale_selection(self):
        for value, expected in [('ru_RU', 'ru'), ('zh-CN', 'zh'), ('en-US', 'en'), ('fr-FR', 'en')]:
            self.assertEqual(expected, language(value))

    def test_existing_manager_errors_are_translated(self):
        tree = ast.parse(Path(__file__).with_name('atlantctl.py').read_text(encoding='utf-8'))
        translated = {entry[0] for entry in ERRORS}
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name) or node.func.id != 'AdminError' or not node.args:
                continue
            literal = node.args[0]
            if isinstance(literal, ast.Constant) and isinstance(literal.value, str) and any('\u0400' <= char <= '\u04ff' for char in literal.value):
                self.assertIn(literal.value, translated)
        for value in ['Подписка не найдена.', 'API: HTTP 409. Проверьте параметры и состояние сервера.']:
            for lang in ('en', 'zh'):
                self.assertFalse(any('\u0400' <= char <= '\u04ff' for char in error_message(value, lang)))

    def test_unknown_error_does_not_echo_secrets(self):
        for lang in LANGUAGES:
            self.assertNotIn('secret-value', error_message('internal secret-value', lang))


class SecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.record = password_record('test-password-long-enough')

    def test_password_validation_and_no_plaintext(self):
        self.assertTrue(verify_password(self.record, 'test-password-long-enough'))
        self.assertFalse(verify_password(self.record, 'wrong'))
        self.assertFalse(verify_password(self.record, None))
        self.assertFalse(verify_password(self.record, '\ud800'))
        self.assertNotIn('test-password', json.dumps(self.record))
        with self.assertRaises(ValueError):
            password_record('short')

    def test_session_csrf_expiry_logout(self):
        now = [0]
        auth = Authentication(self.record, lambda: now[0])
        (token, csrf), error = auth.login('127.0.0.1', 'test-password-long-enough')
        self.assertIsNone(error)
        self.assertTrue(auth.authenticate(token, csrf))
        self.assertIsNone(auth.authenticate(token, 'wrong'))
        self.assertNotIn(token, auth.sessions)
        now[0] = 1801
        self.assertIsNone(auth.authenticate(token, csrf))
        (token, csrf), _ = auth.login('127.0.0.1', 'test-password-long-enough')
        auth.logout(token)
        self.assertIsNone(auth.authenticate(token, csrf))

    def test_login_rate_limit(self):
        auth = Authentication(self.record)
        for _ in range(5):
            self.assertEqual((None, 'unauthorized'), auth.login('127.0.0.1', 'wrong'))
        self.assertEqual((None, 'rate_limited'), auth.login('127.0.0.1', 'test-password-long-enough'))

    def test_username_is_required_and_preserved_on_password_change(self):
        record=password_record('test-password-long-enough','operator')
        auth=Authentication(record)
        for login in [None,'admin','OPERATOR','',123]:
            self.assertEqual((None,'unauthorized'),auth.login(str(login),'test-password-long-enough',login))
        (token,csrf),error=auth.login('owner','test-password-long-enough','operator')
        self.assertIsNone(error)
        saved=[]
        auth.change_password('owner',auth.authenticate(token,csrf)['id'],'test-password-long-enough','replacement-password-long-enough',saved.append)
        self.assertEqual('operator',saved[0]['username'])

    def test_legacy_password_record_has_explicit_admin_login(self):
        record=dict(self.record);record.pop('username')
        self.assertIsNone(Authentication(record).login('owner','test-password-long-enough',None)[0])
        self.assertIsNotNone(Authentication(record).login('owner','test-password-long-enough','admin')[0])

    def test_invalid_login_cannot_be_persisted(self):
        for value in ['', 'a'*65,'space name','x\nadmin',None]:
            with self.assertRaises(ValueError):password_record('test-password-long-enough',value)

    def test_session_count_is_bounded(self):
        auth = Authentication(self.record)
        for index in range(17):
            auth.login(str(index), 'test-password-long-enough')
        self.assertEqual(16, len(auth.sessions))

    def test_password_change_persists_before_revocation(self):
        auth=Authentication(self.record)
        (token,csrf),_=auth.login('owner','test-password-long-enough')
        session=auth.authenticate(token,csrf)
        persist=Mock()
        auth.change_password('owner',session['id'],'test-password-long-enough','a-new-test-password-long-enough',persist)
        persist.assert_called_once()
        self.assertTrue(verify_password(persist.call_args.args[0],'a-new-test-password-long-enough'))
        self.assertIsNone(auth.authenticate(token,csrf))
        self.assertFalse(verify_password(auth.record,'test-password-long-enough'))

    def test_password_write_failure_keeps_old_credentials_and_session(self):
        auth=Authentication(self.record)
        (token,csrf),_=auth.login('owner','test-password-long-enough')
        session=auth.authenticate(token,csrf)
        with self.assertRaises(OSError):
            auth.change_password('owner',session['id'],'test-password-long-enough','a-new-test-password-long-enough',Mock(side_effect=OSError('disk full')))
        self.assertTrue(auth.authenticate(token,csrf))
        self.assertTrue(verify_password(auth.record,'test-password-long-enough'))

    def test_wrong_old_password_cannot_rotate_or_persist(self):
        auth=Authentication(self.record)
        (token,csrf),_=auth.login('owner','test-password-long-enough')
        persist=Mock()
        with self.assertRaises(PermissionError):
            auth.change_password('owner',auth.authenticate(token,csrf)['id'],'wrong','a-new-test-password-long-enough',persist)
        persist.assert_not_called()

    def test_confirmations_single_use_session_bound_and_expiring(self):
        manager = Mock()
        manager.prepare.return_value = {'write': True, 'secret': False, 'label': 'disable alice'}
        manager.execute.return_value = {'ok': True}
        now = [0]
        operations = Operations(manager, lambda: now[0])
        token = operations.prepare('alice-session', 'disable alice')['confirmation']
        manager.execute.assert_not_called()
        with self.assertRaises(PermissionError):
            operations.commit('bob-session', token)
        operations.commit('alice-session', token)
        with self.assertRaises(PermissionError):
            operations.commit('alice-session', token)
        self.assertEqual(1, manager.execute.call_count)
        token = operations.prepare('alice-session', 'disable alice')['confirmation']
        now[0] = 91
        with self.assertRaises(PermissionError):
            operations.commit('alice-session', token)

    def test_secret_access_is_explicit(self):
        manager = Mock()
        manager.prepare.return_value = {'write': False, 'secret': True}
        operations = Operations(manager)
        with self.assertRaises(PermissionError):
            operations.prepare('session', 'export')
        manager.execute.assert_not_called()
        operations.prepare('session', 'export', True)
        manager.execute.assert_called_once()

    def test_slow_read_does_not_block_an_independent_read(self):
        entered, release = threading.Event(), threading.Event()
        manager = Mock()
        manager.prepare.side_effect = lambda command: {'write':False,'secret':False,'label':command}
        def execute(action):
            if action['label']=='slow':
                entered.set()
                self.assertTrue(release.wait(3))
            return 'ok'
        manager.execute.side_effect=execute
        operations=Operations(manager)
        thread=threading.Thread(target=lambda:operations.prepare('session','slow'))
        thread.start()
        try:
            self.assertTrue(entered.wait(1))
            self.assertEqual('ok',operations.prepare('session','fast')['result'])
        finally:
            release.set();thread.join(3)

    def test_plaintext_public_listener_rejected(self):
        for origin in ['http://192.0.2.1:9090', 'http://localhost:9090', 'https://user:secret@example.org', 'https://example.org/path']:
            with self.assertRaises(ValueError):
                origin_parts(origin)
        with self.assertRaises(ValueError):
            PanelServer(('0.0.0.0', 0), 'http://127.0.0.1:9090', Mock(), self.record)
        with self.assertRaises(ValueError):
            PanelServer(('127.0.0.1', 0), 'https://example.org', Mock(), self.record)


class HTTPTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.api = FakeAPI()
        self.manager = Manager({'state_dir': self.tmp.name}, api=self.api)
        self.server = PanelServer(('127.0.0.1', 0), 'http://127.0.0.1:0', self.manager, password_record('test-password-long-enough'))
        self.host = '127.0.0.1:' + str(self.server.server_port)
        self.server.authority = self.host
        self.server.origin = 'http://' + self.host
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.cleanup)

    def cleanup(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        self.tmp.cleanup()

    def call(self, path, data=None, headers=None):
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=5)
        request_headers = {'Origin': self.server.origin, 'Content-Type': 'application/json'}
        request_headers.update(headers or {})
        body = None if data is None else json.dumps(data)
        connection.request('GET' if data is None else 'POST', path, body, request_headers)
        response = connection.getresponse()
        result = (response.status, dict(response.getheaders()), response.read())
        connection.close()
        return result

    def login(self):
        status, headers, raw = self.call('/control/login', {'username': 'admin', 'password': 'test-password-long-enough'})
        self.assertEqual(200, status)
        self.assertIn('HttpOnly', headers['Set-Cookie'])
        self.assertIn('SameSite=Strict', headers['Set-Cookie'])
        return {'Cookie': headers['Set-Cookie'].split(';')[0], 'X-CSRF-Token': json.loads(raw)['csrf']}

    def test_assets_do_not_contain_api_key_and_have_csp(self):
        for path in ['/', '/app.js', '/style.css', '/theme.js', '/forms.js']:
            status, headers, raw = self.call(path)
            self.assertEqual(200, status)
            self.assertIn("frame-ancestors 'none'", headers['Content-Security-Policy'])
            self.assertNotIn(b'YOUR_API_SECRET', raw)
        self.assertNotIn('innerHTML', Path(__file__).with_name('control').joinpath('web/app.js').read_text())

    def test_http_login_rejects_missing_or_wrong_username(self):
        for data in [{'password':'test-password-long-enough'},{'username':'unknown','password':'test-password-long-enough'}]:
            status,headers,raw=self.call('/control/login',data)
            self.assertEqual(401,status)
            self.assertNotIn('Set-Cookie',headers)
            self.assertEqual('invalid_credentials',json.loads(raw)['code'])
        self.login()

    def test_unauthenticated_csrf_foreign_origin_host_rejected(self):
        self.assertEqual(401, self.call('/control/prepare', {'command': 'users'})[0])
        auth = self.login()
        self.assertEqual(403, self.call('/control/prepare', {'command': 'users'}, {'Cookie': auth['Cookie']})[0])
        self.assertEqual(200, self.call('/control/session', headers=auth)[0])
        self.assertEqual(403, self.call('/control/prepare', {'command': 'users'}, dict(auth, Origin='https://evil.example'))[0])
        self.assertEqual(403, self.call('/control/prepare', {'command': 'users'}, dict(auth, Host='evil.example'))[0])
        self.assertFalse(self.api.calls)

    def test_full_prepare_commit_backup_and_replay_path(self):
        auth = self.login()
        status, _, raw = self.call('/control/prepare', {'command': 'delete alice'}, auth)
        self.assertEqual(200, status)
        token = json.loads(raw)['confirmation']
        self.assertFalse(self.api.calls)
        data = {'confirmation': token, 'confirm': True}
        self.assertEqual(200, self.call('/control/commit', data, auth)[0])
        self.assertEqual(['/api/user/delete'], [entry[1] for entry in self.api.calls])
        self.assertEqual(403, self.call('/control/commit', data, auth)[0])

    def test_backup_failure_prevents_mutation(self):
        auth = self.login()
        _, _, raw = self.call('/control/prepare', {'command': 'delete alice'}, auth)
        self.api.request = Mock(side_effect=AdminError('offline'))
        status, _, _ = self.call('/control/commit', {'confirmation': json.loads(raw)['confirmation'], 'confirm': True}, auth)
        self.assertEqual(409, status)
        self.assertEqual(1, self.api.request.call_count)

    def test_logout_invalidates_session(self):
        auth = self.login()
        self.assertEqual(200, self.call('/control/session', headers=auth)[0])
        self.assertEqual(200, self.call('/control/logout', {}, auth)[0])
        self.assertEqual(401, self.call('/control/session', headers=auth)[0])

    def test_panel_certificate_status_is_authenticated_and_independent_of_core(self):
        self.assertEqual(401,self.call('/control/certificate')[0])
        auth=self.login()
        self.api.request=Mock(side_effect=AdminError('offline'))
        status,_,raw=self.call('/control/certificate',headers=auth)
        self.assertEqual(200,status)
        self.assertEqual('loopback-http',json.loads(raw)['mode'])
        self.api.request.assert_not_called()

    def test_loopback_health_is_not_an_authentication_token(self):
        self.server.instance='test-installation-id'
        status,_,raw=self.call('/control/health')
        self.assertEqual(200,status)
        self.assertEqual({'status':'ready','instance':'test-installation-id'},json.loads(raw))
        self.assertEqual(401,self.call('/control/session')[0])
        self.assertNotIn(b'api_key',raw)

    def test_license_is_available_without_disclosing_configuration(self):
        status,headers,raw=self.call('/license')
        self.assertEqual(200,status)
        self.assertIn('text/plain',headers['Content-Type'])
        self.assertIn(b'GNU GENERAL PUBLIC LICENSE',raw)
        self.assertNotIn(b'api_key',raw)

    def test_password_rotation_revokes_sessions_and_pending_writes(self):
        saved=[]
        self.server.credential_writer=saved.append
        auth=self.login()
        _,_,raw=self.call('/control/prepare',{'command':'disable alice'},auth)
        pending=json.loads(raw)['confirmation']
        data={'current_password':'test-password-long-enough','new_password':'replacement-password-long-enough','repeat_password':'replacement-password-long-enough'}
        self.assertEqual(404,self.call('/control/password',data,auth)[0])
        self.assertEqual([],saved)
        replacement=password_record(data['new_password'])
        self.server.credential_loader=lambda:replacement
        self.assertEqual(401,self.call('/control/session',headers=auth)[0])
        self.assertEqual(401,self.call('/control/login',{'username':'admin','password':data['current_password']})[0])
        status,headers,raw=self.call('/control/login',{'username':'admin','password':data['new_password']})
        self.assertEqual(200,status)
        new_auth={'Cookie':headers['Set-Cookie'].split(';')[0],'X-CSRF-Token':json.loads(raw)['csrf']}
        self.assertEqual(403,self.call('/control/commit',{'confirmation':pending,'confirm':True},new_auth)[0])
        self.assertFalse(self.api.calls)

    def test_password_persistence_failure_is_not_reported_as_success(self):
        self.server.credential_writer=Mock(side_effect=OSError('disk full'))
        auth=self.login()
        data={'current_password':'test-password-long-enough','new_password':'replacement-password-long-enough','repeat_password':'replacement-password-long-enough'}
        self.assertEqual(404,self.call('/control/password',data,auth)[0])
        self.server.credential_writer.assert_not_called()
        self.assertEqual(200,self.call('/control/session',headers=auth)[0])

    def test_demo_http_edit_and_attach_use_confirmation_and_backup(self):
        from atlant_control_demo import DemoAPI
        demo=DemoAPI()
        self.server.operations.manager=Manager({'state_dir':self.tmp.name},api=demo)
        auth=self.login()
        commands=['set demo {"note":"edited","total_limit":107374182}', 'subattach '+('a'*32)+' demo 1']
        for command in commands:
            status,_,raw=self.call('/control/prepare',{'command':command},auth)
            self.assertEqual(200,status)
            token=json.loads(raw)['confirmation']
            status,_,raw=self.call('/control/commit',{'confirmation':token,'confirm':True},auth)
            self.assertEqual(200,status)
            self.assertIsNone(json.loads(raw)['result']['safety_backup'])
        self.assertEqual('edited',demo.users['demo']['note'])
        self.assertEqual('a'*32,demo.users['demo']['subscription_id'])
        self.assertEqual(2,len(demo.subscriptions[0]['nodes']))

    def test_demo_group_and_user_flows_share_cli_operations(self):
        from atlant_control_demo import DemoAPI
        demo=DemoAPI()
        manager=Manager({'state_dir':self.tmp.name},api=demo)
        self.server.operations.manager=manager
        auth=self.login()
        def execute(command):
            status,_,raw=self.call('/control/prepare',{'command':command},auth)
            self.assertEqual(200,status,raw)
            token=json.loads(raw)['confirmation']
            status,_,raw=self.call('/control/commit',{'confirmation':token,'confirm':True},auth)
            self.assertEqual(200,status,raw)
            if command.startswith('groupdelete '):self.assertIsNone(json.loads(raw)['result']['safety_backup'])
            else:self.assertIsNone(json.loads(raw)['result']['safety_backup'])
        execute('usercreate '+json.dumps({'name':'tablet','enabled':True,'note':'Keep this note','ip_limit':3,'total_limit':107374182,'expires_at':0}))
        self.assertEqual('Keep this note',demo.users['tablet']['note'])
        execute('groupcreate '+json.dumps({'name':'Family','note':'Devices','users':['demo','tablet']}))
        group=demo.groups[0]
        execute('groupset '+group['id']+' '+json.dumps({'note':'Updated'}))
        self.assertEqual(['demo','tablet'],group['users'])
        execute('bulk disable demo tablet')
        self.assertFalse(demo.users['tablet']['enabled'])
        execute('groupdelete '+group['id'])
        self.assertFalse(demo.groups)
        self.assertIn('tablet',demo.users)


if __name__ == '__main__':
    unittest.main()
