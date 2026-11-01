"""Preservation and failure paths for SSH-triggered server updates."""
import importlib.util
import json
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest
from unittest import mock
from contextlib import closing

ASSETS=Path(__file__).resolve().parents[1]/'client/remoteadmin/assets'


def load(name):
    spec=importlib.util.spec_from_file_location('update_test_'+name.replace('-','_'),ASSETS/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


class DockerUpdateTests(unittest.TestCase):
    def test_replacement_keeps_persistent_data_and_stopped_core(self):
        installer=load('install')
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);data=root/'data';data.mkdir()
            (data/'client.json').write_text('{"core_enabled":false}')
            (data/'server.key').write_bytes(b'unchanged-server-identity')
            before={path.name:path.read_bytes() for path in data.iterdir()}
            calls=[]
            original={'Id':'old-id','State':{'Running':True}}
            with mock.patch.object(installer,'managed_container',return_value=original),mock.patch.object(installer,'run',side_effect=lambda argv,*args:calls.append(argv)),mock.patch.object(installer,'wait_existing') as health:
                installer.update_container(root,'test:new',{'core_commit':'a'*40,'panel_commit':'b'*40})
            health.assert_called_once_with(data)
            launch=next(argv for argv in calls if argv[:2]==['docker','run'])
            self.assertIn('type=bind,src='+str(data)+',dst=/data',launch)
            self.assertEqual(before,{path.name:path.read_bytes() for path in data.iterdir()})
            self.assertEqual(json.loads((root/'deployment.json').read_text())['image'],'test:new')

    def test_stopped_container_is_not_started_by_update(self):
        installer=load('install')
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'data').mkdir();calls=[]
            with mock.patch.object(installer,'managed_container',return_value={'Id':'old','State':{'Running':False}}),mock.patch.object(installer,'run',side_effect=lambda argv,*args:calls.append(argv)),mock.patch.object(installer,'wait_existing') as health:
                installer.update_container(root,'test:new',{'core_commit':'a'*40,'panel_commit':'b'*40})
            health.assert_not_called()
            self.assertTrue(any(argv[:2]==['docker','create'] for argv in calls))
            self.assertFalse(any(argv[:2] in (['docker','run'],['docker','start']) for argv in calls))

    def test_failed_health_restores_previous_container(self):
        installer=load('install')
        with tempfile.TemporaryDirectory() as directory:
            calls=[]
            candidate=subprocess.CompletedProcess([],0,json.dumps([{'Config':{'Image':'test:new'}}]),'')
            with mock.patch.object(installer,'managed_container',return_value={'Id':'old','State':{'Running':True}}),mock.patch.object(installer,'run',side_effect=lambda argv,*args:calls.append(argv)),mock.patch.object(installer,'wait_existing',side_effect=RuntimeError('candidate failed')),mock.patch.object(installer.subprocess,'run',return_value=candidate):
                with self.assertRaisesRegex(RuntimeError,'previous container restored'):
                    installer.update_container(Path(directory),'test:new',{'core_commit':'a'*40,'panel_commit':'b'*40})
            self.assertIn(['docker','rm','-f',installer.CONTAINER],calls)
            self.assertEqual(calls[-1],['docker','start',installer.CONTAINER])

    def test_other_containers_cannot_be_claimed_by_name(self):
        installer=load('install')
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(installer,'inspect_container',return_value={'Mounts':[]}):
                with self.assertRaisesRegex(ValueError,'data volume'):
                    installer.managed_container(Path(directory))


class NativeUpdateTests(unittest.TestCase):
    def scenario(self,directory):
        base=Path(directory);stage=base/'stage';stage.mkdir();native=base/'native';native.mkdir()
        source=stage/'panel/management';source.mkdir(parents=True);(source/'atlantctl.py').write_text('# new panel source')
        for name in ('atlant-server','atlant-cert-agent'):(stage/name).write_bytes(b'new executable')
        binary=native/'atlant-server';binary.write_bytes(b'old executable');binary.chmod(0o755)
        key=native/'server.key';key.write_bytes(b'existing private server key');key.chmod(0o600)
        database=native/'users.db'
        with closing(sqlite3.connect(database)) as db:
            db.executescript('PRAGMA application_id=0x41544c55; PRAGMA user_version=1; CREATE TABLE users(name TEXT); INSERT INTO users VALUES (\'existing-user\');')
        config=native/'core.json';config.write_text(json.dumps({'users_file':str(database),'server_key_file':str(key),'wire_version':7}));config.chmod(0o600)
        info={'binary':str(binary),'config':str(config),'cwd':str(native),'unit':'atlant-test.service','definition':'f'*64,'api_url':'http://127.0.0.1:19001','api_key':'test-api-key','overridden_fields':[]}
        return stage,base/'registration',info

    def test_native_update_retains_data_and_does_not_start_stopped_service(self):
        updater=load('native-update');installer=load('install')
        with tempfile.TemporaryDirectory() as directory:
            stage,registration,info=self.scenario(directory)
            data=Path(info['cwd']);before={path.name:path.read_bytes() for path in data.iterdir() if path.name!='atlant-server'};calls=[]
            def run(argv,*_):
                calls.append(argv)
                if argv[:2]==['docker','cp']:Path(argv[-1]).write_bytes(b'new executable')
            with mock.patch.object(updater,'private',side_effect=Path),mock.patch.object(updater,'discover',return_value=info),mock.patch.object(updater,'running',return_value=False):
                updater.update(stage,registration,'test:image',{'core_commit':'a'*40,'panel_commit':'b'*40},run,installer.check_database,lambda _:None)
            self.assertEqual(Path(info['binary']).read_bytes(),b'new executable')
            self.assertEqual(before,{path.name:path.read_bytes() for path in data.iterdir() if path.name!='atlant-server'})
            self.assertFalse(any(argv[0]=='systemctl' for argv in calls))
            self.assertTrue((registration/'native.json').is_file())
            self.assertFalse(list(data.glob('*.previous-*')))

    def test_native_start_failure_rolls_back_binary_without_changing_users(self):
        updater=load('native-update');installer=load('install')
        with tempfile.TemporaryDirectory() as directory:
            stage,registration,info=self.scenario(directory);data=Path(info['cwd'])
            before={path.name:path.read_bytes() for path in data.iterdir()};starts=0
            def run(argv,*_):
                nonlocal starts
                if argv[:2]==['docker','cp']:Path(argv[-1]).write_bytes(b'new executable')
                if argv[:2]==['systemctl','start']:
                    starts+=1
                    if starts==1:raise RuntimeError('candidate startup failed')
            with mock.patch.object(updater,'private',side_effect=Path),mock.patch.object(updater,'discover',return_value=info),mock.patch.object(updater,'running',return_value=True),mock.patch.object(updater.subprocess,'run',return_value=subprocess.CompletedProcess([],0)):
                with self.assertRaisesRegex(RuntimeError,'previous application restored'):
                    updater.update(stage,registration,'test:image',{'core_commit':'a'*40,'panel_commit':'b'*40},run,installer.check_database,lambda _:None)
            self.assertEqual(before,{path.name:path.read_bytes() for path in data.iterdir()})
            self.assertEqual(starts,2)


if __name__=='__main__':unittest.main()
