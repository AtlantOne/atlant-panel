"""Cross-process locks for private control-plane settings."""
from contextlib import contextmanager
import os
import stat
from pathlib import Path


class SettingsBusy(Exception):
    pass


@contextmanager
def private_lock(path):
    path=Path(path)
    path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    if path.parent.is_symlink() or path.is_symlink():
        raise ValueError('Linked settings directory or lock')
    fd=os.open(path,os.O_CREAT|os.O_RDWR|getattr(os,'O_NOFOLLOW',0),0o600)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):raise ValueError('Settings lock is not a regular file')
        if os.name=='posix' and os.geteuid()==0:
            info=path.parent.stat();os.fchown(fd,info.st_uid,info.st_gid)
        try:
            if os.name=='nt':
                import msvcrt
                if not os.fstat(fd).st_size:os.write(fd,b'\0')
                os.lseek(fd,0,os.SEEK_SET)
                msvcrt.locking(fd,msvcrt.LK_NBLCK,1)
            else:
                import fcntl
                fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except OSError:raise SettingsBusy() from None
        yield
    finally:
        os.close(fd)
