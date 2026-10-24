import http.client
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import Mock

from atlantctl import Manager, private_write
from control.access import entry_path, read_credentials, set_password
from control.security import password_record, verify_password
from control.server import PanelServer


class AccessTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.state=Path(self.tmp.name)

    def test_entry_is_random_persistent_and_invalid_file_is_not_regenerated(self):
        prefix=entry_path(self.state)
        self.assertRegex(prefix,r'^/[A-Za-z0-9_-]{32}/$')
        self.assertEqual(prefix,entry_path(self.state))
        self.assertNotEqual(prefix,entry_path(self.state/'other'))
        private_write(self.state/'entry-path.json',{'version':1,'path':'/../'})
        with self.assertRaises(ValueError):entry_path(self.state)

    def test_cli_url_does_not_require_a_running_core(self):
        api=Mock();manager=Manager({'state_dir':self.tmp.name,'panel':{'origin':'https://example.test:9090'}},api=api)
        action=manager.prepare('panelurl')
        self.assertTrue(action['secret'])
        self.assertEqual('https://example.test:9090'+entry_path(self.state),manager.execute(action))
        api.request.assert_not_called()

    def test_password_changes_only_from_terminal_and_mismatch_keeps_old_record(self):
        path=self.state/'credentials.json';private_write(path,password_record('old-password-long-enough'))
        values=iter(['new-password-long-enough','different-password-long-enough'])
        with self.assertRaises(ValueError):set_password(self.state,'en',private_write,ask=lambda _: '',hidden=lambda _:next(values))
        self.assertTrue(verify_password(read_credentials(path),'old-password-long-enough'))
        set_password(self.state,'en',private_write,ask=lambda _: 'owner',hidden=lambda _: 'new-password-long-enough')
        record=read_credentials(path)
        self.assertEqual('owner',record['username']);self.assertTrue(verify_password(record,'new-password-long-enough'))

    def test_prefixed_login_assets_and_cli_password_reload(self):
        credential=self.state/'credentials.json';record=password_record('old-password-long-enough');private_write(credential,record)
        prefix=entry_path(self.state)
        server=PanelServer(('127.0.0.1',0),'http://127.0.0.1:0',Mock(),record,base_path=prefix,credential_loader=lambda:read_credentials(credential))
        server.origin='http://127.0.0.1:'+str(server.server_port);server.authority='127.0.0.1:'+str(server.server_port)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        def call(path,data=None,headers=None):
            connection=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=3)
            try:
                extra={'Origin':server.origin,'Content-Type':'application/json',**(headers or {})}
                connection.request('POST' if data is not None else 'GET',path,json.dumps(data) if data is not None else None,extra)
                response=connection.getresponse();return response.status,dict(response.getheaders()),response.read()
            finally:connection.close()
        try:
            for path in ['/','/app.js','/control/languages','/wrong/control/languages',prefix+'../control/languages',prefix+'%2e%2e/control/languages']:
                self.assertEqual(404,call(path)[0],path)
            self.assertEqual(200,call(prefix)[0]);self.assertEqual(200,call(prefix+'app.js')[0])
            status,headers,body=call(prefix+'control/login',{'username':'admin','password':'old-password-long-enough'})
            self.assertEqual(200,status)
            auth={'Cookie':headers['Set-Cookie'].split(';')[0],'X-CSRF-Token':json.loads(body)['csrf']}
            self.assertEqual(404,call(prefix+'control/password',{'new_password':'anything'},auth)[0])
            set_password(self.state,'en',private_write,ask=lambda _: '',hidden=lambda _: 'new-password-long-enough')
            self.assertEqual(401,call(prefix+'control/session',headers=auth)[0])
            self.assertEqual(401,call(prefix+'control/login',{'username':'admin','password':'old-password-long-enough'})[0])
            self.assertEqual(200,call(prefix+'control/login',{'username':'admin','password':'new-password-long-enough'})[0])
        finally:server.shutdown();server.server_close();thread.join(timeout=3)


if __name__=='__main__':unittest.main()
