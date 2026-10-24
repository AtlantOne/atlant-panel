"""Private, local subscription-link vault. Never sent to ordinary list views."""
import os
import base64
import hashlib
import hmac
from pathlib import Path
import re
import sqlite3
from urllib.parse import urlsplit


def validated_link(value):
    if not isinstance(value,str) or len(value)>2048 or any(ord(c)<33 for c in value):
        raise ValueError('invalid')
    parts=urlsplit(value)
    if parts.scheme!='https' or not parts.hostname or parts.username or parts.password or parts.query or parts.fragment or not re.fullmatch(r'.*/sub/[A-Za-z0-9_-]{43}',parts.path):
        raise ValueError('invalid')
    return value


def verify(api, sid, url):
    """Match a pasted bearer token to its subscription, without fetching its URL."""
    validated_link(url)
    try:snapshot=api.request('GET','/api/backup')
    except Exception as error:
        if getattr(error,'status_code',None)!=409:raise
        snapshot=api.request('GET','/api/backup/sqlite')
    if snapshot.get('format')=='sqlite3-base64-v1':
        raw=base64.b64decode(snapshot.get('database',''),validate=True)
        if len(raw)>32*1024*1024 or not raw.startswith(b'SQLite format 3\x00'):raise ValueError('invalid')
        db=sqlite3.connect(':memory:')
        try:
            db.deserialize(raw)
            row=db.execute('SELECT token_hash FROM subscriptions WHERE id=?',(sid,)).fetchone()
            expected=row[0] if row else ''
        finally:db.close()
    else:expected=next((s.get('token_hash','') for s in snapshot.get('subscriptions',[]) if s.get('id')==sid),'')
    token=urlsplit(url).path.rsplit('/',1)[-1]
    raw=base64.urlsafe_b64decode(token+'=')
    if len(raw)!=32 or not hmac.compare_digest(hashlib.sha256(raw).hexdigest(),expected):raise ValueError('invalid')


def access(state, sid, url=None):
    if not re.fullmatch(r'[a-f0-9]{32}',sid):raise ValueError('invalid')
    folder=Path(state);folder.mkdir(parents=True,exist_ok=True,mode=0o700)
    path=folder/'subscription-links.db'
    if folder.is_symlink() or path.is_symlink():raise ValueError('invalid')
    fd=os.open(path,os.O_CREAT|os.O_RDWR,0o600);os.close(fd)
    if os.name=='posix':os.chmod(path,0o600)
    from contextlib import closing
    with closing(sqlite3.connect(path,timeout=5)) as db, db:
        db.execute('CREATE TABLE IF NOT EXISTS links(subscription_id TEXT PRIMARY KEY,url TEXT NOT NULL)')
        if url is not None:
            validated_link(url)
            db.execute('INSERT INTO links VALUES(?,?) ON CONFLICT(subscription_id) DO UPDATE SET url=excluded.url',(sid,url))
        row=db.execute('SELECT url FROM links WHERE subscription_id=?',(sid,)).fetchone()
        return row[0] if row else ''
