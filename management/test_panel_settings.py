import base64
import json
import http.client
from pathlib import Path
import tempfile
import socket
import ssl
import subprocess
import sys
import time
import unittest
from unittest.mock import Mock

from atlantctl import AdminError, Manager, private_write
from control.files import private_lock
from test_control_tls import certificate_pairs
from control.security import password_record
import test_control


class PanelSettingsTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.api=Mock();self.api.request.side_effect=AssertionError('Panel settings must not contact the VPN API')
        self.config={'state_dir':self.temp.name,'panel':{'state_dir':self.temp.name,'listen':'127.0.0.1','port':9090,'origin':'http://127.0.0.1:9090'}}
        self.manager=Manager(self.config,api=self.api)
        self.store=self.manager.panel_settings
        self.cert=Path(self.temp.name)/'cert.pem';self.key=Path(self.temp.name)/'key.pem'
        self.pairs=certificate_pairs()
        self.replace('first')

    def replace(self,name):
        self.cert.write_text(self.pairs[name]['certificate']);self.key.write_text(self.pairs[name]['key']);self.key.chmod(0o600)

    def patch(self,**changes):
        return dict({'listen':'127.0.0.1','port':9443,'origin':'https://127.0.0.1:9443','mode':'manual','cert_file':str(self.cert),'key_file':str(self.key)},**changes)

    def prepare(self,**changes):
        return self.manager.prepare('panelset '+json.dumps(self.patch(**changes)))

    def test_manual_save_is_backed_up_and_persisted_without_changing_core(self):
        action=self.prepare()
        self.assertFalse(self.store.path.exists())
        saved=self.manager.execute(action)
        self.assertIsNone(saved['safety_backup'])
        self.assertFalse((self.store.state/'panel-backups').exists())
        restarted=Manager(self.config,api=self.api)
        self.assertEqual('https://127.0.0.1:9443',restarted.panel_settings.effective()['origin'])
        self.assertEqual('127.0.0.1',restarted.execute(restarted.prepare('paneltls'))['host'])
        self.assertNotIn('PRIVATE KEY',self.store.path.read_text())
        self.api.request.assert_not_called()

    def test_saved_certificate_is_used_by_actual_isolated_panel_process(self):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1',0));port=listener.getsockname()[1]
        self.manager.execute(self.prepare(port=port,origin=f'https://127.0.0.1:{port}'))
        config=Path(self.temp.name)/'client.json'
        private_write(config,dict(self.config,api_url='http://127.0.0.1:1',api_key='local-test-only'))
        private_write(Path(self.temp.name)/'credentials.json',password_record('a-long-test-password'))
        from control.access import entry_path
        prefix=entry_path(self.temp.name)
        process=subprocess.Popen([sys.executable,'-I',str(Path(__file__).with_name('atlant_control.py')),'serve','--config',str(config)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        try:
            context=ssl.create_default_context(cafile=str(self.cert));context.verify_flags|=ssl.VERIFY_X509_PARTIAL_CHAIN
            deadline=time.monotonic()+10
            while True:
                connection=http.client.HTTPSConnection('127.0.0.1',port,context=context,timeout=1)
                try:
                    connection.request('GET',prefix);response=connection.getresponse()
                    self.assertEqual(200,response.status)
                    self.assertIn(b'Atlant Control',response.read())
                    break
                except (ConnectionError,OSError):
                    if process.poll() is not None or time.monotonic()>deadline:
                        self.fail('Saved HTTPS settings were not adopted by the panel process')
                    time.sleep(0.02)
                finally:connection.close()
        finally:
            if process.poll() is None:process.terminate()
            process.communicate(timeout=5)

    def test_certificate_identity_expiry_and_pair_are_checked(self):
        for name in ['wrong','expired']:
            self.replace(name)
            with self.assertRaisesRegex(AdminError,'panel_settings_invalid'):self.prepare()
        self.replace('first');self.key.write_text(self.pairs['second']['key'])
        with self.assertRaises(AdminError):self.prepare()
        self.assertFalse(self.store.path.exists())

    def test_revalidation_rejects_file_changed_after_confirmation_was_prepared(self):
        action=self.prepare();self.replace('wrong')
        with self.assertRaises(AdminError):self.manager.execute(action)
        self.assertFalse(self.store.path.exists())

    def test_bad_addresses_and_unsupported_fields_are_rejected(self):
        for change in [{'origin':'http://8.8.8.8:9443'},{'origin':'https://127.0.0.1:1234'},
                       {'origin':'https://user:password@127.0.0.1:9443'}, {'origin':'https://127.0.0.1:9443/path'},
                       {'origin':'https://127.0.0.1:9443\n'}, {'port':True},{'port':0},{'port':65536},
                       {'listen':'example.invalid'},{'cert_file':'relative.pem'},{'unknown':True}]:
            with self.subTest(change=change):
                with self.assertRaises(AdminError):self.prepare(**change)
        for listen,origin in [('0.0.0.0','http://127.0.0.1:9090'),('127.0.0.1','http://example.invalid:9090')]:
            with self.assertRaises(AdminError):self.manager.prepare('panelset '+json.dumps({'listen':listen,'port':9090,'origin':origin,'mode':'loopback-http'}))

    def test_stale_editor_and_parallel_confirmation_cannot_overwrite_settings(self):
        first=self.prepare();second=self.prepare(port=9444,origin='https://127.0.0.1:9444')
        revision=self.manager.execute(self.manager.prepare('panelsettings'))['revision']
        self.manager.execute(first)
        with self.assertRaisesRegex(AdminError,'panel_settings_changed'):self.manager.execute(second)
        with self.assertRaisesRegex(AdminError,'panel_settings_changed'):self.prepare(revision=revision)

    def test_backup_failure_preserves_previous_settings(self):
        action=self.prepare();self.store.write=Mock(side_effect=OSError('disk full'))
        with self.assertRaises(OSError):self.manager.execute(action)
        self.assertFalse(self.store.path.exists())

    def test_restore_has_a_new_backup_and_rejects_traversal(self):
        name=self.manager.execute(self.manager.prepare('panelbackup'))['result']['backup']
        self.manager.execute(self.prepare())
        revision=self.store.read()['revision']
        self.manager.execute(self.manager.prepare('panelrestore '+name+' '+revision))
        self.assertEqual('http://127.0.0.1:9090',self.store.effective()['origin'])
        self.assertEqual(1,len(self.manager.execute(self.manager.prepare('panelbackups'))))
        for name in ['../panel-settings.json','/etc/passwd','bad.json']:
            with self.assertRaises(AdminError):self.manager.prepare('panelrestore '+name)

    def test_distinct_process_editor_lock_prevents_writes(self):
        action=self.prepare()
        with private_lock(self.store.state/'.panel-settings.lock'):
            with self.assertRaisesRegex(AdminError,'panel_settings_changed'):self.manager.execute(action)
        self.assertFalse(self.store.path.exists())

    def test_legacy_certificate_paths_are_not_resurrected_when_switching_mode(self):
        self.store.base.update({'cert_file':str(self.cert),'key_file':str(self.key)})
        action=self.manager.prepare('panelset '+json.dumps({'listen':'127.0.0.1','port':9090,'origin':'http://127.0.0.1:9090','mode':'loopback-http'}))
        self.manager.execute(action)
        self.assertNotIn('cert_file',self.store.effective())

    def test_automatic_selection_requires_matching_bundle_and_unchanged_job(self):
        certs=self.manager.certificates;certs.validator=Mock()
        settings={'mode':'acme-ip','host':'8.8.8.8','email':'','accept_terms':True,'staging':False}
        self.manager.execute(self.manager.prepare('certjobcreate panel '+json.dumps(settings)))
        patch={'listen':'0.0.0.0','port':9443,'origin':'https://8.8.8.8:9443','mode':'agent','job_id':'panel'}
        with self.assertRaises(AdminError):self.manager.prepare('panelset '+json.dumps(patch))
        cache=Path(certs.read()['jobs'][0]['tls']['cache_dir']);cache.mkdir(parents=True)
        context={'Host':'8.8.8.8','Mode':'acme-ip','Directory':'https://acme-v02.api.letsencrypt.org/directory'}
        metadata=base64.encodebytes(json.dumps(context).encode()).decode()
        bundle=cache/'subscription.pem';bundle.write_text(self.pairs['public']['certificate']+self.pairs['public']['key']+'-----BEGIN ATLANT CERTIFICATE CONTEXT-----\n'+metadata+'-----END ATLANT CERTIFICATE CONTEXT-----\n');bundle.chmod(0o600)
        action=self.manager.prepare('panelset '+json.dumps(patch))
        self.manager.execute(action)
        self.assertEqual('acme-ip',self.store.effective()['tls']['mode'])
        action=self.manager.prepare('panelset '+json.dumps(patch))
        self.manager.execute(self.manager.prepare('certjobdelete panel'))
        before=self.store.path.read_bytes()
        with self.assertRaises(AdminError):self.manager.execute(action)
        self.assertEqual(before,self.store.path.read_bytes())


class PanelSettingsHTTPTests(unittest.TestCase):
    setUp=test_control.HTTPTests.setUp
    cleanup=test_control.HTTPTests.cleanup
    call=test_control.HTTPTests.call
    login=test_control.HTTPTests.login

    def test_http_settings_change_is_confirmed_and_does_not_restart_listener(self):
        auth=self.login();original=self.server.origin
        patch={'listen':'127.0.0.1','port':9091,'origin':'http://127.0.0.1:9091','mode':'loopback-http'}
        self.assertEqual(401,self.call('/control/prepare',{'command':'panelset '+json.dumps(patch)})[0])
        status,_,raw=self.call('/control/prepare',{'command':'panelset '+json.dumps(patch)},auth)
        self.assertEqual(200,status,raw)
        self.assertFalse(self.manager.panel_settings.path.exists())
        token=json.loads(raw)['confirmation']
        status,_,raw=self.call('/control/commit',{'confirmation':token,'confirm':True},auth)
        self.assertEqual(200,status,raw)
        self.assertEqual(original,self.server.origin)
        self.assertEqual(200,self.call('/control/session',headers=auth)[0])
        self.assertEqual('http://127.0.0.1:9091',self.manager.panel_settings.effective()['origin'])
        self.assertEqual(403,self.call('/control/commit',{'confirmation':token,'confirm':True},auth)[0])
        self.assertFalse(self.api.calls)
