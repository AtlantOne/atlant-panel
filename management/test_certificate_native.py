"""Opt-in tests against a compiled agent; never issue certificates or bind ports."""
import json
import os
from pathlib import Path
import unittest

from atlantctl import AdminError
import test_control


@unittest.skipUnless(os.environ.get('ATLANT_CERT_AGENT_TEST_BINARY'),'Set ATLANT_CERT_AGENT_TEST_BINARY to a compiled certificate agent')
class NativeCertificateHTTPTests(unittest.TestCase):
    setUp=test_control.HTTPTests.setUp
    cleanup=test_control.HTTPTests.cleanup
    call=test_control.HTTPTests.call
    login=test_control.HTTPTests.login

    def test_native_certificate_create_edit_restore_and_delete_over_http(self):
        self.manager.certificates.binary=Path(os.environ['ATLANT_CERT_AGENT_TEST_BINARY']).resolve()
        auth=self.login()
        def execute(command):
            status,_,raw=self.call('/control/prepare',{'command':command},auth)
            self.assertEqual(200,status,raw)
            token=json.loads(raw)['confirmation']
            status,_,raw=self.call('/control/commit',{'confirmation':token,'confirm':True},auth)
            self.assertEqual(200,status,raw)
            return json.loads(raw)['result']
        options={'mode':'acme-domain','host':'panel.example.invalid','email':'','accept_terms':True,'staging':True}
        execute('certjobcreate panel '+json.dumps(options))
        current=self.manager.certificates.read()
        options['host']='second.example.invalid'
        edited=execute('certjobset panel '+json.dumps({'host':options['host'],'revision':current['revision']}))
        execute('certrestore '+edited['safety_backup']+' '+self.manager.certificates.read()['revision'])
        self.assertEqual('panel.example.invalid',self.manager.certificates.read()['jobs'][0]['tls']['host'])
        execute('certjobdelete panel '+self.manager.certificates.read()['revision'])
        self.assertEqual([],self.manager.certificates.read()['jobs'])
        self.assertFalse(self.api.calls)
        self.assertFalse(list(self.manager.certificates.state.glob('.candidate-*')))
        self.assertFalse((self.manager.certificates.state/'bundles').exists())

    def test_native_validator_rejects_duplicate_identity_without_mutation(self):
        self.manager.certificates.binary=Path(os.environ['ATLANT_CERT_AGENT_TEST_BINARY']).resolve()
        options={'mode':'acme-domain','host':'panel.example.invalid','email':'','accept_terms':True,'staging':True}
        self.manager.execute(self.manager.prepare('certjobcreate first '+json.dumps(options)))
        before=self.manager.certificates.path.read_bytes()
        with self.assertRaisesRegex(AdminError,'certificate_invalid'):
            self.manager.prepare('certjobcreate second '+json.dumps(options))
        self.assertEqual(before,self.manager.certificates.path.read_bytes())

