import contextlib
import io
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
import atlantctl


class DefaultCLILanguageTest(unittest.TestCase):
    def test_cli_help_does_not_offer_operations_owned_by_web_panel(self):
        text=atlantctl.panel_cli_help('en')
        for command in ('inboundcreate','subscribercreate','usercreate','subcreate','configsave','service status'):
            self.assertNotIn('\n'+command,text)
        self.assertIn('logs [LINES]',text)

    def test_vpn_commands_are_rejected_before_manager_or_api_access(self):
        for command in ('users','inbounds','subcreate','configsave','service'):
            with patch('sys.argv',['atlantctl',command]), patch('atlantctl.load_config',return_value={'language':'en'}), patch('atlantctl.Manager') as manager, contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):atlantctl.main()
            manager.assert_not_called()

    def test_panel_language_is_not_used_as_cli_default(self):
        with tempfile.TemporaryDirectory() as directory:
            output = io.StringIO()
            with patch('sys.argv', ['atlantctl','help']), patch('atlantctl.load_config',return_value={'language':'ru','state_dir':directory}), contextlib.redirect_stdout(output):
                atlantctl.main()
            self.assertIn('Atlant management commands.', output.getvalue())

    def test_unconfigured_cli_defaults_to_english_even_on_russian_host(self):
        with tempfile.TemporaryDirectory() as directory:
            output = io.StringIO()
            argv = ['atlantctl', '--config', str(Path(directory)/'missing.json'), 'help']
            with patch('sys.argv', argv), patch('locale.getlocale', return_value=('ru_RU','UTF-8')), contextlib.redirect_stdout(output):
                atlantctl.main()
            self.assertIn('Atlant management commands.', output.getvalue())

    def test_explicit_language_still_overrides_default(self):
        output = io.StringIO()
        with patch('sys.argv', ['atlantctl', '--lang', 'zh', 'help']), contextlib.redirect_stdout(output):
            atlantctl.main()
        self.assertIn('Atlant 管理命令', output.getvalue())


if __name__ == '__main__':
    unittest.main()
