import http.client
import json
from pathlib import Path
import ssl
import subprocess
import tempfile
import threading
import datetime as dt
import base64
from functools import lru_cache
import unittest
from unittest.mock import Mock

from atlantctl import Manager

from control.security import password_record
from control.server import PanelServer
from control.tls import CertificateReloader, validated_context, from_panel_settings, agent_status


@lru_cache(maxsize=1)
def certificate_pairs():
    root=Path(__file__).resolve().parent.parent
    fixtures=subprocess.run(['go','run',str(root/'tests/controlcert/main.go')],cwd=root,capture_output=True,text=True,check=True,timeout=60)
    return json.loads(fixtures.stdout)


class CertificateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pairs=certificate_pairs()

    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.certificate=Path(self.tmp.name)/'cert.pem'
        self.key=Path(self.tmp.name)/'key.pem'
        self.replace('first')

    def replace(self,name):
        self.certificate.write_text(self.pairs[name]['certificate'])
        self.key.write_text(self.pairs[name]['key'])
        self.key.chmod(0o600)

    def test_memory_handshake_checks_ip_domain_expiry_and_pair(self):
        for host in ('localhost','127.0.0.1'):
            context,details=validated_context(host,self.certificate,self.key)
            self.assertEqual(ssl.TLSVersion.TLSv1_2,context.minimum_version)
            self.assertEqual(host,details['host'])
        for name in ('wrong','expired'):
            self.replace(name)
            with self.assertRaises(ssl.SSLError):validated_context('127.0.0.1',self.certificate,self.key)
        self.replace('first')
        self.key.write_text(self.pairs['second']['key'])
        with self.assertRaises(ssl.SSLError):validated_context('127.0.0.1',self.certificate,self.key)

    def test_failed_rotation_retains_last_valid_context(self):
        manager=CertificateReloader('127.0.0.1',self.certificate,self.key)
        previous=manager.context
        self.key.write_text('interrupted write')
        publish=Mock()
        self.assertFalse(manager.reload(publish))
        publish.assert_not_called()
        self.assertIs(previous,manager.context)
        self.assertTrue(manager.status()['error'])
        self.replace('second')
        self.assertTrue(manager.reload(publish))
        self.assertIsNot(previous,manager.context)
        self.assertFalse(manager.status()['error'])
        self.assertNotIn('PRIVATE KEY',json.dumps(manager.status()))

    def test_cli_uses_same_certificate_validation_without_requiring_core_api(self):
        manager=Manager({'state_dir':self.tmp.name,'panel':{'origin':'https://127.0.0.1','cert_file':str(self.certificate),'key_file':str(self.key)}},api=Mock())
        action=manager.prepare('paneltls')
        self.assertFalse(action['write'])
        self.assertEqual('127.0.0.1',manager.execute(action)['host'])
        manager.api.request.assert_not_called()
        self.replace('wrong')
        with self.assertRaises(ssl.SSLError):manager.execute(action)

    def test_automatic_panel_modes_read_atomic_bundle_and_agent_state(self):
        for fixture,host,mode in [('public','8.8.8.8','acme-ip'),('domain','panel.example.test','acme-domain')]:
            context={'Host':host,'Mode':mode,'Directory':'https://acme-v02.api.letsencrypt.org/directory'}
            payload=base64.encodebytes(json.dumps(context).encode()).decode()
            bundle=Path(self.tmp.name)/'subscription.pem'
            bundle.write_text(self.pairs[fixture]['certificate']+self.pairs[fixture]['key']+'-----BEGIN ATLANT CERTIFICATE CONTEXT-----\n'+payload+'-----END ATLANT CERTIFICATE CONTEXT-----\n')
            bundle.chmod(0o600)
            report={'version':1,'updated_at':dt.datetime.now(dt.timezone.utc).isoformat(),'jobs':{'agent':{'phase':'running','listening':True},'panel':{'host':host,'mode':mode,'error':''}}}
            (Path(self.tmp.name)/'status.json').write_text(json.dumps(report))
            settings={'origin':'https://'+host,'tls':{'mode':mode,'host':host,'cache_dir':self.tmp.name,'accept_terms':True},'certificate_agent':{'state_dir':self.tmp.name,'job_id':'panel'}}
            manager=from_panel_settings(settings)
            self.assertEqual(mode,manager.status()['mode'])
            self.assertFalse(manager.status()['error'])
            previous=manager.context
            bundle.write_text(bundle.read_text().replace(payload,base64.encodebytes(json.dumps(dict(context,Directory='https://wrong-ca.invalid/directory')).encode()).decode()))
            self.assertFalse(manager.reload(Mock()))
            self.assertIs(previous,manager.context)
            settings['tls']['staging']=True
            with self.assertRaises(ValueError):from_panel_settings(settings)

    def test_agent_failure_and_stale_state_are_not_reported_as_renewal_success(self):
        path=Path(self.tmp.name)/'status.json'
        self.assertTrue(agent_status(self.tmp.name,'panel','example.test')['error'])
        report={'version':1,'updated_at':dt.datetime.now(dt.timezone.utc).isoformat(),'jobs':{'agent':{'phase':'stopped'},'panel':{'host':'example.test'}}}
        path.write_text(json.dumps(report))
        self.assertIn('not running',agent_status(self.tmp.name,'panel','example.test')['error'])
        report['updated_at']=(dt.datetime.now(dt.timezone.utc)-dt.timedelta(minutes=5)).isoformat()
        path.write_text(json.dumps(report))
        self.assertIn('stale',agent_status(self.tmp.name,'panel','example.test')['error'])

    def test_real_https_listener_accepts_rotated_certificate_without_restart(self):
        manager=CertificateReloader('127.0.0.1',self.certificate,self.key)
        server=PanelServer(('127.0.0.1',0),'https://127.0.0.1:0',Mock(),password_record('test-password-long-enough'),manager.context)
        server.authority='127.0.0.1:'+str(server.server_port)
        thread=threading.Thread(target=server.serve_forever,daemon=True)
        thread.start()
        try:
            for fixture in ('first','second'):
                self.replace(fixture)
                self.assertTrue(manager.reload(lambda context:setattr(server,'context',context)))
                client_context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                client_context.verify_flags|=ssl.VERIFY_X509_PARTIAL_CHAIN
                client_context.load_verify_locations(cafile=self.certificate)
                connection=http.client.HTTPSConnection('127.0.0.1',server.server_port,context=client_context,timeout=5)
                connection.request('GET','/control/languages')
                response=connection.getresponse()
                self.assertEqual(200,response.status)
                self.assertIn('zh',json.loads(response.read()))
                connection.close()
        finally:
            server.shutdown();server.server_close();thread.join(timeout=3)


if __name__=='__main__':unittest.main()
