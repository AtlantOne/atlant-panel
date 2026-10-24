import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

from atlantctl import AdminError, Manager, private_write
from control.certificate_jobs import CertificateJobError


class CertificateJobTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.api=Mock()
        self.api.request.side_effect=AssertionError('Certificate management must not require the VPN API')
        self.manager=Manager({'state_dir':self.temp.name},api=self.api)
        self.store=self.manager.certificates
        self.store.validator=Mock()

    def create(self,name='panel'):
        return self.manager.prepare('certjobcreate '+name+' '+json.dumps({'mode':'acme-domain','host':'panel.example.invalid','email':'','accept_terms':True,'staging':True}))

    def test_loopback_listener_preserves_jobs_and_rejects_public_alternate_port(self):
        self.manager.execute(self.create())
        self.manager.execute(self.manager.prepare('certlisten 127.0.0.1:18081'))
        saved=self.store.read()
        self.assertEqual('127.0.0.1:18081',saved['challenge_listen'])
        self.assertEqual('panel',saved['jobs'][0]['id'])
        with self.assertRaises(AdminError):self.manager.prepare('certlisten 0.0.0.0:18081')
        with self.assertRaises(AdminError):self.manager.prepare('certlisten 127.0.0.1:18082 stale')

    def test_prepare_has_no_configuration_write_and_commit_makes_private_backup(self):
        action=self.create()
        self.assertFalse(self.store.path.exists())
        result=self.manager.execute(action)
        self.assertTrue(self.store.path.is_file())
        self.assertIsNone(result['safety_backup'])
        self.assertFalse((self.store.state/'backups').exists())
        self.assertEqual('panel',self.manager.execute(self.manager.prepare('certjobs'))['jobs'][0]['id'])
        self.api.request.assert_not_called()

    def test_stale_confirmation_cannot_overwrite_newer_configuration(self):
        first=self.create('first');second=self.create('second')
        self.manager.execute(first)
        with self.assertRaisesRegex(AdminError,'certificate_changed'):self.manager.execute(second)
        self.assertEqual(['first'],[job['id'] for job in self.store.read()['jobs']])

    def test_edit_preserves_cache_and_other_settings_and_delete_keeps_certificate(self):
        self.manager.execute(self.create())
        original=self.store.read();cache=Path(original['jobs'][0]['tls']['cache_dir'])
        cache.mkdir(parents=True);bundle=cache/'subscription.pem';bundle.write_text('fixture certificate stays')
        self.manager.execute(self.manager.prepare('certjobset panel '+json.dumps({'email':'owner@example.invalid','revision':original['revision']})))
        updated=self.store.read()
        self.assertTrue(updated['jobs'][0]['tls']['staging'])
        self.assertEqual(str(cache),updated['jobs'][0]['tls']['cache_dir'])
        with self.assertRaisesRegex(AdminError,'certificate_changed'):
            self.manager.prepare('certjobset panel '+json.dumps({'email':'old@example.invalid','revision':original['revision']}))
        self.manager.execute(self.manager.prepare('certjobdelete panel '+updated['revision']))
        self.assertEqual([],self.store.read()['jobs'])
        self.assertEqual('fixture certificate stays',bundle.read_text())

    def test_backup_failure_blocks_configuration_change(self):
        action=self.create();self.store.write=Mock(side_effect=OSError('disk full'))
        with self.assertRaises(OSError):self.manager.execute(action)
        self.assertFalse(self.store.path.exists())

    def test_invalid_fields_terms_and_job_names_are_rejected(self):
        for patch in [{'accept_terms':False},{'staging':'false'},{'cache_dir':'/etc'},{'key_file':'/private/key.pem'}]:
            values={'mode':'acme-domain','host':'panel.example.invalid','email':'','accept_terms':True,'staging':False};values.update(patch)
            with self.assertRaises(AdminError):self.manager.prepare('certjobcreate panel '+json.dumps(values))
        for name in ['agent','../outside']:
            with self.assertRaises(AdminError):self.create(name)

    def test_interprocess_lock_refuses_second_editor(self):
        other=Manager({'state_dir':self.temp.name},api=Mock()).certificates
        other.validator=Mock()
        action=self.create()
        with self.store._locked():
            with self.assertRaisesRegex(CertificateJobError,'certificate_changed'):other.commit(action['certificate'])
        self.assertFalse(self.store.path.exists())

    def test_restore_settings_is_revision_checked_and_backed_up(self):
        empty_backup=self.manager.execute(self.manager.prepare('certbackup'))['result']['backup']
        self.manager.execute(self.create())
        original=self.store.read()
        name=self.manager.execute(self.manager.prepare('certbackup'))['result']['backup']
        edited=self.manager.execute(self.manager.prepare('certjobset panel '+json.dumps({'email':'new@example.invalid'})))
        action=self.manager.prepare('certrestore '+name+' '+self.store.read()['revision'])
        self.assertEqual('new@example.invalid',self.store.read()['jobs'][0]['tls']['email'])
        restored=self.manager.execute(action)
        self.assertEqual(original['jobs'],self.store.read()['jobs'])
        self.assertIsNone(restored['safety_backup'])
        listed=self.manager.execute(self.manager.prepare('certbackups'))
        self.assertEqual(2,len(listed))
        self.assertEqual({'name','size'},set(listed[0]))
        empty=self.manager.prepare('certrestore '+empty_backup)
        self.manager.execute(empty)
        self.assertEqual([],self.store.read()['jobs'])
        self.api.request.assert_not_called()

    def test_restore_rejects_traversal_corruption_and_stale_confirmation(self):
        self.manager.execute(self.create())
        name=self.manager.execute(self.manager.prepare('certbackup'))['result']['backup']
        for invalid_name in ['../config.json','config.json','/etc/passwd']:
            with self.assertRaises(AdminError):self.manager.prepare('certrestore '+invalid_name)
        action=self.manager.prepare('certrestore '+name)
        self.manager.execute(self.manager.prepare('certjobset panel '+json.dumps({'email':'new@example.invalid'})))
        with self.assertRaisesRegex(AdminError,'certificate_changed'):self.manager.execute(action)
        path=self.store.state/'backups'/name
        path.write_text('{"config":{}}')
        with self.assertRaises(AdminError):self.manager.prepare('certrestore '+path.name)


if __name__=='__main__':unittest.main()
