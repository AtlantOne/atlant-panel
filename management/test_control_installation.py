import hashlib
import json
import os
from pathlib import Path
import socket
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from control.installation import Installer, UNITS, check_agent, source_files


class PackageTests(unittest.TestCase):
    def test_source_inventory_excludes_runtime_and_test_code(self):
        files=source_files(Path(__file__).parent)
        self.assertIn(Path('atlantctl.py'),files)
        self.assertIn(Path('control/web/app.js'),files)
        self.assertIn(Path('control/web/QRCODE-LICENSE.txt'),files)
        self.assertFalse(any('test_' in str(path) or '__pycache__' in path.parts or path.suffix=='.json' for path in files))
        self.assertNotIn(Path('atlant_control_demo.py'),files)

    def test_binary_integrity_and_architecture_are_both_required(self):
        with tempfile.TemporaryDirectory() as folder:
            binary=Path(folder)/'agent'
            binary.write_bytes(b'\x7fELF\x02\x01'+b'\0'*12+(62).to_bytes(2,'little'))
            digest=hashlib.sha256(binary.read_bytes()).hexdigest()
            check_agent(binary,digest,'x86_64')
            with self.assertRaises(ValueError):check_agent(binary,'0'*64,'x86_64')
            with self.assertRaises(ValueError):check_agent(binary,digest,'aarch64')


@unittest.skipUnless(os.name=='posix' and hasattr(os,'geteuid') and os.geteuid()==0,'Linux root filesystem transaction tests')
class InstallTransactionTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='atlant-install-test-');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.binary=self.root/'agent'
        self.binary.write_bytes(b'\x7fELF\x02\x01'+b'\0'*12+(62).to_bytes(2,'little'))
        self.digest=hashlib.sha256(self.binary.read_bytes()).hexdigest()
        self.core=self.root/'core.json';self.core.write_text('{"api_secret":"test-only-secret","wire_version":7}')
        self.core.chmod(0o600);self.original=self.core.read_bytes()
        self.definition='[Service]\nExecStart=/test/atlant -c '+str(self.core)+'\n'
        self.fingerprint=hashlib.sha256(self.definition.encode()).hexdigest()
        self.runtime={'api_url':'http://127.0.0.1:8080','api_key':'test-only-secret','config':str(self.core),
                      'binary':'/test/atlant','cwd':'/test','unit':'atlant_vpn.service','pid':12,'definition':self.fingerprint,'overridden_fields':['sni']}
        self.failure=None;self.calls=[]
        def run(argv,**kwargs):
            self.calls.append(argv)
            if self.failure and self.failure(argv):return SimpleNamespace(returncode=1,stdout='controlled failure')
            stdout=self.definition if argv[1]=='cat' else 'not-found\n' if '--property=LoadState' in argv else ''
            return SimpleNamespace(returncode=0,stdout=stdout)
        self.installer=Installer(Path(__file__).parent,self.binary,self.digest,root=self.root,run=run)
        self.installer.account=Mock(return_value=(os.geteuid(),os.getegid()))
        self.installer.health=Mock()
        self.installer.verify_api=Mock()
        with patch('control.installation.inspect_unit',return_value=self.runtime),patch('control.installation.API') as api:
            self.plan=self.installer.preflight()
        with socket.socket() as listener:
            listener.bind(('127.0.0.1',0));self.port=listener.getsockname()[1]

    def install(self):return self.installer.install(self.plan,'operator','long-test-password-only',self.port)

    def assert_core_untouched(self):
        self.assertEqual(self.original,self.core.read_bytes())
        mutations=[call for call in self.calls if call[0]=='/usr/bin/systemctl' and call[1] in {'start','stop','restart','enable','disable'}]
        self.assertFalse(any('atlant_vpn.service' in call for call in mutations))
        self.assertFalse(any('start' in call and 'atlant-cert-agent.service' in call for call in mutations))

    def test_initial_install_uses_real_paths_and_does_not_start_ca_or_touch_vpn(self):
        result=self.install()
        self.assertTrue(result['installed'])
        config=json.loads((self.installer.config/'client.json').read_text())
        self.assertEqual('http://127.0.0.1:'+str(self.port),config['panel']['origin'])
        helper=json.loads((self.installer.config/'helper.json').read_text())
        self.assertEqual(['sni'],helper['runtime_registration']['overridden_fields'])
        self.assertEqual(0o640,(self.installer.config/'client.json').stat().st_mode&0o777)
        self.assertEqual(0o600,(self.installer.state/'credentials.json').stat().st_mode&0o777)
        for unit in UNITS:self.assertTrue((self.installer.units/unit).is_file())
        helper_unit=(self.installer.units/'atlant-control-helper.service').read_text()
        self.assertIn('ProtectSystem=full',helper_unit)
        self.assertIn('ReadWritePaths='+json.dumps(str(self.core.parent))+' '+json.dumps(str(self.installer.config)),helper_unit)
        self.installer.health.assert_called_once_with(self.port,result['transaction'])
        self.assert_core_untouched()

    def test_failed_panel_start_quarantines_only_new_components(self):
        self.failure=lambda argv:argv[1:]==['start','atlant-control.service']
        with self.assertRaises(RuntimeError):self.install()
        self.assertFalse(self.installer.app.exists());self.assertFalse(self.installer.config.exists())
        journals=list(self.installer.installer_state.glob('*.json'))
        journal=json.loads(journals[0].read_text())
        self.assertEqual('rolled-back',journal['phase'])
        self.assertTrue(journal['quarantine'])
        for entry in journal['quarantine']:self.assertTrue(Path(entry['saved']).exists())
        self.assert_core_untouched()

    def test_stop_failure_retains_components_instead_of_moving_live_service_files(self):
        self.failure=lambda argv:argv[1:]==['start','atlant-control.service'] or argv[1:]==['stop','atlant-control-helper.service']
        with self.assertRaises(RuntimeError):self.install()
        self.assertTrue(self.installer.app.exists());self.assertTrue(self.installer.config.exists())
        journal=json.loads(next(self.installer.installer_state.glob('*.json')).read_text())
        self.assertEqual('rollback-incomplete',journal['phase']);self.assertEqual([],journal['quarantine'])
        self.assert_core_untouched()

    def test_wrong_health_response_rolls_back_before_enable(self):
        self.installer.health.side_effect=RuntimeError('wrong instance')
        with self.assertRaises(RuntimeError):self.install()
        self.assertFalse(any(call[1]=='enable' for call in self.calls))
        self.assert_core_untouched()

    def test_changed_unit_after_plan_prevents_any_installation_files(self):
        self.definition+='\n# changed\n'
        with self.assertRaises(ValueError):self.install()
        self.assertFalse(self.installer.app.exists());self.assertFalse(self.installer.config.exists())
        self.installer.account.assert_not_called()
