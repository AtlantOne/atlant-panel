import os
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch

from control.notify import ready


class NotifyTests(unittest.TestCase):
    def test_standalone_process_does_not_require_systemd(self):
        with patch.dict(os.environ,{},clear=True):ready()

    def test_invalid_notification_addresses_are_rejected(self):
        for address in ['relative','/tmp/with\0nul','@'+'a'*108]:
            with patch('control.notify.os.environ',{'NOTIFY_SOCKET':address}):
                with self.assertRaises(ValueError):ready()

    @unittest.skipUnless(hasattr(socket,'SO_PEERCRED'),'Linux systemd datagram transport')
    def test_real_readiness_datagram_contains_no_credentials(self):
        with tempfile.TemporaryDirectory(prefix='atlant-notify-') as folder:
            path=Path(folder)/'notify'
            with socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM) as receiver:
                receiver.settimeout(2);receiver.bind(str(path))
                with patch.dict(os.environ,{'NOTIFY_SOCKET':str(path)}):ready()
                self.assertEqual(b'READY=1',receiver.recv(1024))
