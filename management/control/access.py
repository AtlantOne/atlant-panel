"""Private, persistent panel entry path and terminal-only credential management."""
import getpass
import json
import os
from pathlib import Path
import re
import secrets

from control.i18n import message
from control.security import password_record


def entry_path(state):
    state=Path(state);state.mkdir(parents=True,exist_ok=True,mode=0o700)
    path=state/'entry-path.json'
    if state.is_symlink() or path.is_symlink():raise ValueError('Unsafe panel entry path')
    try:
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    except FileExistsError:pass
    else:
        with os.fdopen(fd,'w',encoding='utf-8') as stream:
            credentials=state/'credentials.json'
            if os.name=='posix' and credentials.exists():
                info=credentials.stat();os.fchown(stream.fileno(),info.st_uid,info.st_gid)
            json.dump({'version':1,'path':'/'+secrets.token_urlsafe(24)+'/'},stream)
            stream.flush();os.fsync(stream.fileno())
    if path.stat().st_size>1024 or (os.name=='posix' and path.stat().st_mode&0o077):raise ValueError('Unsafe panel entry file')
    record=json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(record,dict) or record.get('version')!=1 or not isinstance(record.get('path'),str) or not re.fullmatch(r'/[A-Za-z0-9_-]{32}/',record['path']):raise ValueError('Invalid panel entry file')
    return record['path']


def read_credentials(path):
    path=Path(path)
    if path.is_symlink() or path.stat().st_size>4096 or (os.name=='posix' and path.stat().st_mode&0o077):raise ValueError('Unsafe credentials file')
    record=json.loads(path.read_text(encoding='utf-8'))
    if isinstance(record,dict):record.setdefault('username','admin')
    if not isinstance(record,dict) or record.get('version')!=1 or not isinstance(record.get('username'),str) or not re.fullmatch(r'[A-Za-z0-9_.@-]{1,64}',record['username']) or any(not isinstance(record.get(key),str) or not re.fullmatch(r'[0-9a-f]{64}',record[key]) for key in ('salt','digest')):raise ValueError('Invalid credentials')
    return record


def set_password(state,lang,writer,ask=input,hidden=getpass.getpass):
    path=Path(state)/'credentials.json'
    if path.is_symlink():raise ValueError('Unsafe credentials path')
    previous=json.loads(path.read_text(encoding='utf-8')) if path.exists() else {}
    username=ask(message('login_prompt',lang,default=previous.get('username','admin'))).strip() or previous.get('username','admin')
    first=hidden(message('new_password',lang)+': ')
    if first!=hidden(message('repeat_password',lang)+': '):raise ValueError(message('password_mismatch',lang))
    owner=None
    if os.name=='posix' and path.exists():
        info=path.stat();owner=(info.st_uid,info.st_gid)
    writer(path,password_record(first,username),owner=owner)
