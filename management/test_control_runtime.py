from pathlib import Path
import tempfile
import unittest

from control.runtime import derive, flags, public_runtime, definition_command


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.cwd=self.root/'cwd';self.bin=self.root/'bin'
        self.cwd.mkdir();self.bin.mkdir();self.exe=self.bin/'atlant_server'
        self.exe.write_bytes(b'test fixture')

    def test_go_config_priority_and_relative_paths(self):
        (self.cwd/'config.json').write_text('{}');(self.cwd/'explicit.json').write_text('{}');(self.bin/'server_config.json').write_text('{}')
        for args,name in [([],self.cwd/'config.json'),(['-config-file','explicit.json'],self.cwd/'explicit.json'),
                          (['--config-file=ignored.json','-c=explicit.json'],self.cwd/'explicit.json')]:
            result,_=derive([str(self.exe)]+args,self.cwd,self.exe)
            self.assertEqual(str(name),result['config'])
        (self.cwd/'config.json').unlink()
        result,_=derive([str(self.exe)],self.cwd,self.exe)
        self.assertEqual(str(self.bin/'server_config.json'),result['config'])

    def test_only_real_nonzero_overrides_are_reported(self):
        (self.cwd/'config.json').write_text('{}')
        result,_=derive([str(self.exe),'-sni','donor.example','-up-mbps=0','-down-mbps=50'],self.cwd,self.exe)
        self.assertEqual(['sni','down_mbps'],result['overridden_fields'])

    def test_unknown_url_and_positional_configuration_are_rejected(self):
        for args in [['-config','atlant://secret'],['-cmd','getlink user'],['-unknown','value'],['positional','-c','file'],['-debug','true'],['-c']]:
            with self.assertRaises(ValueError):flags(['server']+args)

    def test_public_report_never_contains_api_secret(self):
        self.assertEqual({'pid':1},public_runtime({'pid':1,'api_key':'test-only-secret'}))

    def test_unit_definition_reset_and_command_boundaries(self):
        text='[Service]\nWorkingDirectory=/root\nExecStart=/old\n[Install]\nExecStart=/ignored\n[Service]\nExecStart=\nExecStart=/root/atlant_server -c /root/config.json\n'
        self.assertEqual((['/root/atlant_server','-c','/root/config.json'],'/root'),definition_command(text))
        for command in ['/bin/sh -c "$COMMAND"','@/root/server custom-name','/root/server %i','/root/server \\\n -c config.json']:
            with self.assertRaises(ValueError):definition_command('[Service]\nExecStart='+command)
