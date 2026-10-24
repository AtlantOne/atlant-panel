import tempfile
import os
from pathlib import Path
import unittest
from unittest.mock import Mock
from atlantctl import Manager, AdminError, private_write

class BackupActionsTests(unittest.TestCase):
    def test_full_active_store_is_archived_without_losing_copies(self):
        with tempfile.TemporaryDirectory() as directory:
            manager=Manager({'state_dir':directory},api=Mock())
            folder=Path(directory)/'backups';folder.mkdir()
            names=[f'backup-20261023T000000Z-{i:08x}.json' for i in range(500)]
            for name in names:private_write(folder/name,{'users':{},'preserved':name})
            os.utime(folder/names[-1],(1,1))
            manager.archive_backups()
            archived=list((Path(directory)/'backup-archive').glob('*.json'))
            self.assertEqual(1,len(archived))
            self.assertEqual(499,len(list(folder.glob('*.json'))))
            name=archived[0].name
            self.assertEqual(names[-1],name)
            self.assertIn(name,manager.execute(manager.prepare('backups'))['backups'])
            self.assertIn(name,archived[0].read_text())
            manager.execute(manager.prepare('backupremove data '+name))
            self.assertFalse(archived[0].exists())
            manager.execute(manager.prepare('backuprecover data '+name))
            self.assertTrue((folder/name).is_file())

    def test_delete_is_recoverable_and_never_calls_core(self):
        with tempfile.TemporaryDirectory() as directory:
            api=Mock();api.request.side_effect=AssertionError('Local backup operation must not contact core')
            manager=Manager({'state_dir':directory},api=api)
            name='backup-20261022T120000Z-12345678.json'
            path=Path(directory)/'backups'/name
            path.parent.mkdir();private_write(path,{'users':{}})
            manager.execute(manager.prepare('backupremove data '+name))
            self.assertFalse(path.exists())
            self.assertEqual([{'kind':'data','name':name}],manager.execute(manager.prepare('backuptrash')))
            manager.execute(manager.prepare('backuprecover data '+name))
            self.assertTrue(path.is_file())
            self.assertEqual([],manager.execute(manager.prepare('backuptrash')))
            api.request.assert_not_called()

    def test_path_traversal_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            manager=Manager({'state_dir':directory},api=Mock())
            for command in ['backupremove data ../config.json','backupremove unknown backup-123-12345678.json','backuprecover panel /etc/passwd']:
                with self.assertRaises(AdminError):manager.prepare(command)

if __name__=='__main__':unittest.main()
