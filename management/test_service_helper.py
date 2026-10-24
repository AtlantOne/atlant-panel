import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

from atlantctl import Manager, private_write
from control.service_helper import Actions, Helper
from control.service_client import request


class ServiceActionsTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.config=self.root/'core.json'
        self.original={'sni':'www.example.test','up_mbps':0,'api_secret':'test-only-core-secret','wire_version':7,'users_file':'users.db'}
        private_write(self.config,self.original)
        self.settings={'core_unit':'atlant_vpn.service','core_config':str(self.config),'state_dir':str(self.root/'state')}
        self.run=Mock(return_value=Mock(returncode=0,stdout='ActiveState=active\nSubState=running\nMainPID=123\n'))
        self.actions=Actions(self.settings,self.run)

    def test_service_control_can_only_call_fixed_unit_without_shell(self):
        for command in ['status','start','stop','restart']:
            self.assertEqual('active',self.actions.execute(command,None)['active'])
        for call in self.run.call_args_list:
            self.assertEqual('/usr/bin/systemctl',call.args[0][0])
            self.assertIn('atlant_vpn.service',call.args[0])
            self.assertNotIn('shell',call.kwargs)
        for command in ['reboot','shell','start;reboot','configdelete']:
            with self.assertRaises(ValueError):self.actions.execute(command,None)
        for command in [None,[],{}]:
            with self.assertRaises(ValueError):self.actions.execute(command,None)
        self.assertEqual('active',self.actions.execute('status',None)['active'])
        with self.assertRaises(ValueError):self.actions.execute('stop',{'unit':'other.service'})
        for unit in ['ssh.service','atlant;reboot.service','../atlant.service','atlant.service --force']:
            with self.assertRaises(ValueError):Actions(dict(self.settings,core_unit=unit))

    def test_config_write_preserves_secrets_and_creates_private_backup(self):
        prepared=self.actions.execute('configcheck',{'down_mbps':250,'advertise_addr':'[2001:db8::1]:1026'})
        result=self.actions.execute('configsave',prepared)
        saved=json.loads(self.config.read_text())
        self.assertEqual('test-only-core-secret',saved['api_secret'])
        self.assertEqual(7,saved['wire_version'])
        self.assertEqual(250,saved['down_mbps'])
        self.assertNotIn('safety_backup',result)
        self.assertFalse((self.root/'state'/'config-backups').exists())
        self.assertNotIn('secret',json.dumps(result))
        audit=(self.root/'state'/'audit.jsonl').read_text()
        self.assertNotIn('test-only-core-secret',audit)
        self.assertEqual(['begin','done'],[json.loads(line)['event'] for line in audit.splitlines()])
        self.run.assert_not_called()

    def test_live_journal_is_scoped_bounded_and_read_only(self):
        self.run.return_value=Mock(returncode=0,stdout='\n'.join(str(i) for i in range(70)))
        result=self.actions.execute('logs',{'lines':50})
        self.assertEqual([str(i) for i in range(20,70)],result['logs'])
        self.assertEqual(['/usr/bin/journalctl','--unit=atlant_vpn.service','--lines=50','--output=cat','--no-pager','--quiet'],self.run.call_args.args[0])
        self.assertFalse((self.root/'state'/'audit.jsonl').exists())
        self.actions.gate.acquire()
        try:self.assertEqual(result,self.actions.execute('logs',{'lines':50}))
        finally:self.actions.gate.release()
        for body in [None,{'lines':True},{'lines':0},{'lines':201},{'lines':50,'unit':'ssh.service'}]:
            with self.assertRaises(ValueError):self.actions.execute('logs',body)
        self.run.return_value=Mock(returncode=0,stdout=('界'*10000+'\n')*50)
        self.assertLess(len(json.dumps(self.actions.execute('logs',{'lines':50})).encode()),15001)

    def test_stale_config_or_bad_fields_never_change_disk(self):
        prepared=self.actions.execute('configcheck',{'sni':'new.example.test'})
        private_write(self.config,dict(self.original,up_mbps=100))
        before=self.config.read_bytes()
        with self.assertRaises(ValueError):self.actions.execute('configsave',prepared)
        for body in [{'api_secret':'changed'},{'wire_version':2},{'listen':':80'},{'up_mbps':True},{'down_mbps':-1},
                     {'sni':'example.test\n;reboot'},{'advertise_addr':'example.test:99999'},{'advertise_addr':'x;reboot:443'}]:
            with self.assertRaises(ValueError):self.actions.execute('configcheck',body)
        self.assertEqual(before,self.config.read_bytes())

    def test_backup_failure_prevents_core_configuration_write(self):
        action=self.actions.execute('configcheck',{'up_mbps':42})
        with patch('control.service_helper.private_write',side_effect=OSError('full')):
            with self.assertRaises(OSError):self.actions.execute('configsave',action)
        self.assertEqual(self.original,json.loads(self.config.read_text()))

    def test_busy_helper_rejects_instead_of_queueing_late_stop(self):
        self.actions.gate.acquire()
        try:
            with self.assertRaises(RuntimeError):self.actions.execute('stop',None)
        finally:self.actions.gate.release()
        self.run.assert_not_called()

    def test_audit_failure_prevents_service_mutation(self):
        self.actions.audit=Mock(side_effect=OSError('audit unavailable'))
        with self.assertRaises(OSError):self.actions.execute('stop',None)
        self.run.assert_not_called()

    def test_certificate_agent_actions_use_only_its_fixed_service(self):
        self.actions.execute('cert-start',None)
        self.assertEqual(['/usr/bin/systemctl','start','atlant-cert-agent.service'],self.run.call_args_list[0].args[0])
        self.assertIn('atlant-cert-agent.service',(self.root/'state'/'audit.jsonl').read_text())
        with self.assertRaises(ValueError):self.actions.execute('cert-start',{'unit':'other.service'})

    def test_registered_flag_override_and_changed_unit_are_rejected(self):
        registration={'definition':'a'*64,'overridden_fields':['sni']}
        actions=Actions(dict(self.settings,runtime_registration=registration),self.run,root_owned=True)
        with patch('control.service_helper.unit_definition',return_value=('',registration['definition'])):
            with self.assertRaisesRegex(ValueError,'overrides'):actions.execute('configcheck',{'sni':'new.example.test'})
        with patch('control.service_helper.unit_definition',return_value=('','b'*64)):
            with self.assertRaisesRegex(ValueError,'definition changed'):actions.execute('configcheck',{'up_mbps':50})
        self.assertEqual(self.original,json.loads(self.config.read_text()))

    def test_certificate_service_cli_uses_confirmation_without_core_backup(self):
        api=Mock();api.request.side_effect=AssertionError('Core must not be needed')
        manager=Manager({'state_dir':self.temp.name,'service_socket':'/run/test-only.sock'},api=api)
        action=manager.prepare('certservice start')
        self.assertTrue(action['write'])
        with patch('control.service_client.request',side_effect=lambda path,action,body:self.actions.execute(action,body)):
            manager.execute(action)
        self.assertEqual(['/usr/bin/systemctl','start','atlant-cert-agent.service'],self.run.call_args_list[0].args[0])
        api.request.assert_not_called()

    def test_manager_socket_path_does_not_require_running_core_for_service_or_config(self):
        api=Mock();api.request.side_effect=AssertionError('Core is stopped')
        manager=Manager({'state_dir':self.temp.name,'service_socket':'/run/test-only.sock'},api=api)
        with patch('control.service_client.request',side_effect=lambda path,action,body:self.actions.execute(action,body)):
            manager.execute(manager.prepare('service start'))
            result=manager.execute(manager.prepare('configsave {"up_mbps":42}'))
        self.assertTrue(result['result']['configuration_saved'])
        self.assertEqual(42,json.loads(self.config.read_text())['up_mbps'])
        api.request.assert_not_called()


@unittest.skipUnless(hasattr(socket,'SO_PEERCRED'),'Linux peer-credential integration')
class HelperSocketTests(unittest.TestCase):
    def test_real_unix_socket_authenticates_uid_and_rejects_foreign_uid(self):
        for offset in [0,1]:
            with tempfile.TemporaryDirectory(prefix='atlant-helper-') as folder:
                path=Path(folder)/'control.sock';stop=threading.Event()
                actions=Mock();actions.execute.return_value={'active':'test-only'}
                helper=Helper(path,os.geteuid()+offset,None,actions,allow_root=False)
                errors=[];ready=threading.Event()
                def serve():
                    try:helper.serve(stop,on_ready=ready.set)
                    except BaseException as error:errors.append(error)
                thread=threading.Thread(target=serve);thread.start()
                try:
                    self.assertTrue(ready.wait(3),'Helper socket did not become ready')
                    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
                        client.settimeout(2);client.connect(str(path))
                        client.sendall(b'{"action":"status","body":null}\n')
                        try:response=client.recv(16384)
                        except ConnectionResetError:response=b''
                    if offset:
                        self.assertEqual(b'',response);actions.execute.assert_not_called()
                    else:
                        self.assertTrue(json.loads(response)['ok'])
                        actions.execute.assert_called_once_with('status',None)
                        if os.geteuid()==0:self.assertEqual({'active':'test-only'},request(str(path),'status'))
                        else:
                            with self.assertRaises(PermissionError):request(str(path),'status')
                finally:
                    stop.set();thread.join(timeout=3)
                self.assertFalse(thread.is_alive());self.assertEqual([],errors)
                self.assertFalse(path.exists())
