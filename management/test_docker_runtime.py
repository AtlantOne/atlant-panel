import importlib.util
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

ASSETS=Path(__file__).resolve().parents[1]/'client/remoteadmin/assets'

def load(name):
    spec=importlib.util.spec_from_file_location('docker_'+name,ASSETS/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


class RuntimeTests(unittest.TestCase):
    def test_old_managed_install_enables_missing_subscription_accounting(self):
        runtime=load('runtime')
        with tempfile.TemporaryDirectory() as directory:
            folder=Path(directory);path=folder/'core.json'
            original={'sni':'example.com','subscriptions':{'enabled':False}}
            path.write_text(json.dumps(original))
            runtime.Core(folder).prepare_subscription_accounting()
            self.assertEqual(dict(original,quota={'coordinator':True}),json.loads(path.read_text()))
            unchanged=path.read_bytes()
            runtime.Core(folder).prepare_subscription_accounting()
            self.assertEqual(unchanged,path.read_bytes())

    def test_explicit_quota_policy_and_remote_worker_are_preserved(self):
        runtime=load('runtime')
        with tempfile.TemporaryDirectory() as directory:
            folder=Path(directory);path=folder/'core.json'
            for quota in ({'coordinator':False},{'endpoint':'https://example.com','node_id':'worker'},{}):
                path.write_text(json.dumps({'quota':quota}))
                original=path.read_bytes()
                runtime.Core(folder).prepare_subscription_accounting()
                self.assertEqual(original,path.read_bytes())

    def test_stop_choice_persisted_without_touching_core_config(self):
        runtime=load('runtime')
        with tempfile.TemporaryDirectory() as directory:
            folder=Path(directory);(folder/'client.json').write_text('{"core_enabled":true}')
            core=runtime.Core(folder)
            core.stop()
            self.assertFalse(json.loads((folder/'client.json').read_text())['core_enabled'])
            core.set_enabled(True);core.stop(persist=False)
            self.assertTrue(json.loads((folder/'client.json').read_text())['core_enabled'])

    def test_service_actions_and_config_save(self):
        runtime=load('runtime')
        with tempfile.TemporaryDirectory() as directory:
            folder=Path(directory);(folder/'core.json').write_text(json.dumps({'sni':'example.com'}))
            core=mock.Mock();core.folder=folder;core.lock=__import__('threading').RLock()
            manager=runtime.ContainerManager.__new__(runtime.ContainerManager);manager.core=core
            manager.helper_call('restart');core.stop.assert_called_once();core.start.assert_called_once()
            checked=manager.helper_call('configcheck',{'log_level':'warn'})
            manager.helper_call('configsave',checked)
            self.assertEqual(json.loads((folder/'core.json').read_text())['log_level'],'warn')
            with self.assertRaises(runtime.AdminError):manager.helper_call('configsave',{'api_secret':'replacement'})
            with self.assertRaises(runtime.AdminError):manager.helper_call('configsave',checked)
            with self.assertRaises(runtime.AdminError):manager.helper_call('arbitrary-shell')


if __name__=='__main__':unittest.main()
