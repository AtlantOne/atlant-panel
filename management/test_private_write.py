import errno
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from atlantctl import private_write, replace_private_file


class PrivateWriteTests(unittest.TestCase):
    def test_transient_windows_reader_is_retried(self):
        error = PermissionError('reader holds target')
        error.winerror = 32
        with patch('atlantctl.os.replace', side_effect=[error, None]) as replace, patch('atlantctl.time.sleep') as sleep:
            replace_private_file('candidate', 'target')
        self.assertEqual(2, replace.call_count)
        sleep.assert_called_once_with(0.01)

    def test_permanent_error_preserves_old_file_and_removes_candidate(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'settings.json'
            private_write(path, {'original': True})
            with patch('atlantctl.os.replace', side_effect=OSError(errno.ENOSPC, 'full')):
                with self.assertRaises(OSError): private_write(path, {'original': False})
            self.assertEqual({'original': True}, json.loads(path.read_text()))
            self.assertEqual([path], list(Path(folder).iterdir()))

    def test_windows_permission_failure_has_deadline(self):
        error = PermissionError('not transient')
        error.winerror = 5
        with patch('atlantctl.os.replace', side_effect=error) as replace, patch('atlantctl.time.monotonic', side_effect=[0, 0, 2]), patch('atlantctl.time.sleep'):
            with self.assertRaises(PermissionError): replace_private_file('candidate', 'target')
        self.assertEqual(2, replace.call_count)
