"""Durable panel pairing and narrowly scoped, authenticated peer requests."""
import base64
from contextlib import closing, contextmanager
import hashlib
import hmac
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import sqlite3
import ssl
import threading
import time
from urllib.parse import urlsplit


class PeerError(Exception):
    pass


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def identifier(value):
    if not isinstance(value,str) or not re.fullmatch('[0-9a-f]{32}',value):raise PeerError('peer_invalid')
    return value


def secret(value):
    if not isinstance(value,str) or not re.fullmatch('[0-9a-f]{64}',value):raise PeerError('peer_invalid')
    return value


def origin(value):
    if not isinstance(value,str) or len(value)>512:raise PeerError('peer_https_required')
    try:
        p=urlsplit(value)
        if p.scheme!='https' or not p.hostname or p.username or p.password or p.path or p.query or p.fragment or '%' in p.hostname or not 1<=(p.port or 443)<=65535:raise ValueError()
        p.hostname.encode('ascii')
    except (ValueError,UnicodeError):raise PeerError('peer_https_required') from None
    return value


class PeerHTTP:
    def __init__(self,ca_file=None,allow_private=False):
        self.context=ssl.create_default_context(cafile=ca_file)
        self.context.minimum_version=ssl.TLSVersion.TLSv1_2
        self.allow_private=allow_private

    def request(self,url,path,data):
        p=urlsplit(origin(url));port=p.port or 443
        addresses=socket.getaddrinfo(p.hostname,port,type=socket.SOCK_STREAM)
        if not addresses:raise PeerError('peer_unavailable')
        for _,_,_,_,address in addresses:
            ip=ipaddress.ip_address(address[0])
            if ip.is_multicast or ip.is_unspecified or (not self.allow_private and not ip.is_global):raise PeerError('peer_address_rejected')
        resolved=addresses[0][4]
        address=(resolved[0],resolved[1])
        context=self.context
        class PinnedConnection(http.client.HTTPSConnection):
            def connect(connection):
                raw=socket.create_connection(address,connection.timeout)
                try:connection.sock=context.wrap_socket(raw,server_hostname=p.hostname)
                except BaseException:raw.close();raise
        connection=PinnedConnection(p.hostname,port,timeout=5,context=context)
        try:
            connection.request('POST',path,canonical(data),{'Content-Type':'application/json','Host':p.netloc})
            response=connection.getresponse();body=response.read((1<<20)+1)
            if response.status!=200 or len(body)>1<<20:raise PeerError('peer_unavailable')
            result=json.loads(body,parse_constant=lambda _:(_ for _ in ()).throw(ValueError()))
            if not isinstance(result,dict):raise PeerError('peer_invalid')
            return result
        except (OSError,ValueError,http.client.HTTPException):raise PeerError('peer_unavailable') from None
        finally:connection.close()


class Peers:
    def __init__(self,state,origin_provider,ca_file=None,allow_private=False,clock=time.time):
        self.state=Path(state)/'peer-links';self.path=self.state/'state.db'
        self.origin_provider,self.clock=origin_provider,clock
        self.live_origin=None
        self.http=PeerHTTP(ca_file,allow_private)
        self.limit_lock=threading.Lock();self.attempts={}

    @contextmanager
    def db(self):
        self.state.mkdir(mode=0o700,parents=True,exist_ok=True)
        if self.state.is_symlink() or self.path.is_symlink() or not self.state.is_absolute():raise PeerError('peer_storage')
        if os.name=='posix' and self.state.stat().st_mode&0o022:raise PeerError('peer_storage')
        fd=os.open(self.path,os.O_CREAT|os.O_RDWR|getattr(os,'O_NOFOLLOW',0),0o600)
        try:
            info=os.fstat(fd)
            if info.st_size>16<<20 or (os.name=='posix' and info.st_mode&0o077):raise PeerError('peer_storage')
        finally:os.close(fd)
        db=sqlite3.connect(self.path,timeout=5,isolation_level=None)
        db.row_factory=sqlite3.Row
        try:
            db.execute('PRAGMA synchronous=FULL');db.execute('PRAGMA foreign_keys=ON')
            db.executescript('''CREATE TABLE IF NOT EXISTS meta(id INTEGER PRIMARY KEY CHECK(id=1),panel TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS invites(id TEXT PRIMARY KEY,hash TEXT NOT NULL,expires INTEGER NOT NULL,state TEXT NOT NULL,claim TEXT UNIQUE,candidate TEXT,candidate_origin TEXT,auth_hash TEXT);
CREATE TABLE IF NOT EXISTS outgoing(id TEXT PRIMARY KEY,remote TEXT NOT NULL,origin TEXT NOT NULL,auth TEXT NOT NULL,expires INTEGER NOT NULL,state TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS peers(id TEXT PRIMARY KEY,origin TEXT NOT NULL,role TEXT NOT NULL,in_key TEXT NOT NULL,out_key TEXT NOT NULL,state TEXT NOT NULL,created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS nonces(peer TEXT NOT NULL,nonce TEXT NOT NULL,expires INTEGER NOT NULL,PRIMARY KEY(peer,nonce));''')
            db.executescript('''CREATE TABLE IF NOT EXISTS grants(peer TEXT PRIMARY KEY,generation TEXT NOT NULL,inbounds_write INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS admin_jobs(peer TEXT NOT NULL,id TEXT NOT NULL,generation TEXT NOT NULL,issued INTEGER NOT NULL,hash TEXT NOT NULL,state TEXT NOT NULL,result TEXT,PRIMARY KEY(peer,id));
CREATE TABLE IF NOT EXISTS sent_jobs(peer TEXT NOT NULL,id TEXT NOT NULL,generation TEXT NOT NULL,issued INTEGER NOT NULL,command TEXT NOT NULL,state TEXT NOT NULL,result TEXT,PRIMARY KEY(peer,id));''')
            db.execute('INSERT OR IGNORE INTO meta VALUES(1,?)',(secrets.token_hex(16),))
            db.execute('BEGIN IMMEDIATE')
            yield db
            db.commit()
        except BaseException:db.rollback();raise
        finally:db.close()

    def advertised_origin(self):return self.live_origin() if callable(self.live_origin) else self.live_origin or self.origin_provider()

    def current_origin(self):return origin(self.advertised_origin())

    @staticmethod
    def panel_id(db):return db.execute('SELECT panel FROM meta WHERE id=1').fetchone()[0]

    def backup(self):
        with self.db() as source:
            self.panel_id(source)
        snapshots=list(self.state.glob('backup-*.db'))
        if len(snapshots)>=500 or sum(path.stat().st_size for path in snapshots)>256*1024*1024:raise PeerError('peer_limit')
        target=self.state/('backup-'+str(int(self.clock()))+'-'+secrets.token_hex(8)+'.db')
        fd=os.open(target,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600);os.close(fd)
        # A separate read connection avoids backing up an open write transaction.
        with closing(sqlite3.connect(self.path)) as source,closing(sqlite3.connect(target)) as destination:source.backup(destination)
        return str(target)

    def info(self):
        with self.db() as db:
            now=int(self.clock())
            active=[dict(row) for row in db.execute('SELECT id,origin,role,state,created FROM peers ORDER BY created')]
            for peer in active:
                grant=db.execute('SELECT inbounds_write FROM grants g JOIN peers p ON p.id=g.peer AND g.generation=p.in_key WHERE g.peer=?',(peer['id'],)).fetchone()
                peer['inbounds_write']=bool(grant and grant[0])
            incoming=[dict(row) for row in db.execute("SELECT claim AS id,candidate AS remote,candidate_origin AS origin,expires FROM invites WHERE state='pending' AND expires>?",(now,))]
            outgoing=[dict(row) for row in db.execute("SELECT id,remote,origin,expires,state FROM outgoing WHERE state='pending' AND expires>?",(now,))]
            return {'panel_id':self.panel_id(db),'origin':self.advertised_origin(),'peers':active,'incoming':incoming,'outgoing':outgoing}

    def invite(self):
        url=self.current_origin();now=int(self.clock())
        with self.db() as db:
            db.execute('DELETE FROM invites WHERE expires<?',(now-86400,))
            if db.execute('SELECT count(*) FROM invites').fetchone()[0]>=256:raise PeerError('peer_limit')
            key=secrets.token_hex(32);invitation=secrets.token_hex(16)
            db.execute("INSERT INTO invites(id,hash,expires,state) VALUES(?,?,?,'open')",(invitation,digest(key),now+300))
            payload={'version':1,'origin':url,'panel':self.panel_id(db),'invite':invitation,'secret':key,'expires':now+300}
        encoded=base64.urlsafe_b64encode(canonical(payload)).decode().rstrip('=')
        return {'link':'atlant-pair://v1/'+encoded,'expires':now+300}

    def parse_invite(self,link):
        try:
            if not isinstance(link,str) or not link.startswith('atlant-pair://v1/') or len(link)>4096:raise ValueError()
            text=link[len('atlant-pair://v1/'):]
            if not re.fullmatch('[A-Za-z0-9_-]+',text):raise ValueError()
            data=json.loads(base64.urlsafe_b64decode(text+'='*(-len(text)%4)))
            if not isinstance(data,dict) or set(data)!={'version','origin','panel','invite','secret','expires'} or data['version']!=1 or type(data['expires']) is not int:raise ValueError()
            origin(data['origin']);identifier(data['panel']);identifier(data['invite']);secret(data['secret'])
            if not int(self.clock())<data['expires']<=int(self.clock())+600:raise PeerError('peer_expired')
            return data
        except (ValueError,TypeError,KeyError):raise PeerError('peer_invalid') from None

    def join(self,link):
        invitation=self.parse_invite(link);local_origin=self.current_origin()
        with self.db() as db:
            local=self.panel_id(db)
            if local==invitation['panel'] or local_origin==invitation['origin']:raise PeerError('peer_invalid')
            db.execute("DELETE FROM outgoing WHERE expires<?",(int(self.clock())-86400,))
            if db.execute('SELECT count(*) FROM outgoing').fetchone()[0]>=256:raise PeerError('peer_limit')
            claim,auth=secrets.token_hex(16),secrets.token_hex(32)
            db.execute("INSERT INTO outgoing VALUES(?,?,?,?,?,'pending')",(claim,invitation['panel'],invitation['origin'],auth,invitation['expires']))
        result=self.http.request(invitation['origin'],'/peer/claim',{'invite':invitation['invite'],'secret':invitation['secret'],'panel':invitation['panel'],'candidate':local,'origin':local_origin,'claim':claim,'auth':auth})
        if result.get('panel')!=invitation['panel'] or result.get('claim')!=claim:raise PeerError('peer_invalid')
        return {'pending':True,'claim':claim,'remote':invitation['panel'],'origin':invitation['origin']}

    def allow_attempt(self,address):
        now=self.clock()
        with self.limit_lock:
            self.attempts={key:[stamp for stamp in values if stamp>now-60] for key,values in self.attempts.items() if values[-1]>now-60}
            count=sum(map(len,self.attempts.values()))
            if len(self.attempts.get(address,[]))>=6 or count>=120 or (address not in self.attempts and len(self.attempts)>=512):raise PeerError('peer_limit')
            self.attempts.setdefault(address,[]).append(now)

    def claim(self,data):
        if set(data)!={'invite','secret','panel','candidate','origin','claim','auth'}:raise PeerError('peer_invalid')
        identifier(data['invite']);identifier(data['panel']);identifier(data['candidate']);identifier(data['claim']);secret(data['secret']);secret(data['auth']);origin(data['origin'])
        with self.db() as db:
            local=self.panel_id(db)
            row=db.execute('SELECT * FROM invites WHERE id=?',(data['invite'],)).fetchone()
            if data['panel']!=local or data['candidate']==local or not row or row['expires']<=self.clock() or not hmac.compare_digest(row['hash'],digest(data['secret'])):raise PeerError('peer_expired')
            if row['state']!='open':
                if row['state']!='pending' or row['claim']!=data['claim'] or row['candidate']!=data['candidate'] or row['candidate_origin']!=data['origin'] or not hmac.compare_digest(row['auth_hash'],digest(data['auth'])):raise PeerError('peer_used')
            else:db.execute("UPDATE invites SET state='pending',claim=?,candidate=?,candidate_origin=?,auth_hash=? WHERE id=?",(data['claim'],data['candidate'],data['origin'],digest(data['auth']),data['invite']))
            return {'panel':local,'claim':data['claim'],'pending':True}

    def approve(self,claim):
        identifier(claim)
        with self.db() as db:
            row=db.execute("SELECT * FROM invites WHERE claim=? AND state='pending'",(claim,)).fetchone()
            if not row or row['expires']<=self.clock():raise PeerError('peer_expired')
            existing=db.execute('SELECT state FROM peers WHERE id=?',(row['candidate'],)).fetchone()
            if existing and existing['state']!='revoked':raise PeerError('peer_exists')
            if not existing and db.execute('SELECT count(*) FROM peers').fetchone()[0]>=256:raise PeerError('peer_limit')
            # An old claim must never retrieve keys from a later pairing generation.
            db.execute("UPDATE invites SET state='revoked',auth_hash='' WHERE candidate=? AND state='approved'",(row['candidate'],))
            db.execute('INSERT INTO peers VALUES(?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET origin=excluded.origin,role=excluded.role,in_key=excluded.in_key,out_key=excluded.out_key,state=excluded.state,created=excluded.created',
                (row['candidate'],row['candidate_origin'],'primary',secrets.token_hex(32),secrets.token_hex(32),'approved',int(self.clock())))
            db.execute("UPDATE invites SET state='approved' WHERE claim=?",(claim,))
            return {'approved':True,'remote':row['candidate']}

    def reject(self,claim):
        identifier(claim)
        with self.db() as db:
            if db.execute("UPDATE invites SET state='rejected',auth_hash='' WHERE claim=? AND state='pending'",(claim,)).rowcount!=1:raise PeerError('peer_used')
        return {'rejected':True}

    def cancel(self,claim):
        identifier(claim)
        with self.db() as db:
            if db.execute("UPDATE outgoing SET state='cancelled',auth='' WHERE id=? AND state='pending'",(claim,)).rowcount!=1:raise PeerError('peer_used')
        return {'cancelled':True}

    def result(self,data):
        if set(data)!={'claim','auth','panel'}:raise PeerError('peer_invalid')
        identifier(data['claim']);secret(data['auth']);identifier(data['panel'])
        with self.db() as db:
            row=db.execute('SELECT * FROM invites WHERE claim=?',(data['claim'],)).fetchone()
            if data['panel']!=self.panel_id(db) or not row or row['expires']<=self.clock() or not hmac.compare_digest(row['auth_hash'] or '',digest(data['auth'])):raise PeerError('peer_expired')
            response={'panel':self.panel_id(db),'claim':data['claim'],'pending':row['state']=='pending'}
            if row['state'] not in ('pending','approved'):raise PeerError('peer_used')
            if row['state']=='approved':
                peer=db.execute("SELECT * FROM peers WHERE id=? AND state!='revoked'",(row['candidate'],)).fetchone()
                if not peer:raise PeerError('peer_revoked')
                response.update(in_key=peer['out_key'],out_key=peer['in_key'])
            return response

    def finish(self,claim):
        identifier(claim)
        with self.db() as db:
            row=db.execute("SELECT * FROM outgoing WHERE id=? AND state='pending'",(claim,)).fetchone()
            if not row or row['expires']<=self.clock():raise PeerError('peer_expired')
            row=dict(row)
        data=self.http.request(row['origin'],'/peer/result',{'claim':claim,'auth':row['auth'],'panel':row['remote']})
        if data.get('panel')!=row['remote'] or data.get('claim')!=claim:raise PeerError('peer_invalid')
        if data.get('pending'):return {'pending':True}
        secret(data.get('in_key'));secret(data.get('out_key'))
        with self.db() as db:
            current=db.execute("SELECT state FROM outgoing WHERE id=?",(claim,)).fetchone()
            if not current or current['state']!='pending':raise PeerError('peer_used')
            existing=db.execute('SELECT state FROM peers WHERE id=?',(row['remote'],)).fetchone()
            if existing and existing['state']!='revoked':raise PeerError('peer_exists')
            if not existing and db.execute('SELECT count(*) FROM peers').fetchone()[0]>=256:raise PeerError('peer_limit')
            db.execute('INSERT INTO peers VALUES(?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET origin=excluded.origin,role=excluded.role,in_key=excluded.in_key,out_key=excluded.out_key,state=excluded.state,created=excluded.created',
                (row['remote'],row['origin'],'follower',data['in_key'],data['out_key'],'connected',int(self.clock())))
            db.execute("UPDATE outgoing SET state='complete',auth='' WHERE id=?",(claim,))
        return {'connected':True,'remote':row['remote']}

    def peer(self,remote):
        identifier(remote)
        with self.db() as db:
            row=db.execute("SELECT * FROM peers WHERE id=? AND state!='revoked'",(remote,)).fetchone()
            if not row:raise PeerError('peer_revoked')
            return dict(row),self.panel_id(db)

    @staticmethod
    def signature(key,data):return hmac.new(bytes.fromhex(key),canonical(data),hashlib.sha256).hexdigest()

    def call(self,remote,operation):
        peer,local=self.peer(remote)
        return self.send_call(peer,local,operation)

    def grant(self,remote,enabled):
        if type(enabled) is not bool:raise PeerError('peer_invalid')
        with self.db() as db:
            peer=db.execute("SELECT * FROM peers WHERE id=? AND state!='revoked'",(identifier(remote),)).fetchone()
            if not peer or peer['role']!='follower':raise PeerError('peer_forbidden')
            db.execute('INSERT OR REPLACE INTO grants VALUES(?,?,?)',(remote,peer['in_key'],int(enabled)))
        return {'inbounds_write':enabled}

    @staticmethod
    def admin_command(command):
        if not isinstance(command,str) or len(command.encode())>32768 or command.partition(' ')[0] not in {'inboundcreate','inboundset','inbounddelete','inboundapply'}:raise PeerError('peer_forbidden')
        return command

    def jobs(self,remote):
        self.peer(remote)
        with self.db() as db:
            return {'jobs':[dict(row) for row in db.execute('SELECT id,issued,state FROM sent_jobs WHERE peer=? ORDER BY issued DESC LIMIT 256',(remote,))]}

    def admin(self,remote,command):
        self.admin_command(command);peer,local=self.peer(remote)
        if peer['role']!='primary':raise PeerError('peer_forbidden')
        request=secrets.token_hex(16);now=int(self.clock())
        with self.db() as db:
            db.execute('DELETE FROM sent_jobs WHERE issued<?',(now-172800,))
            if db.execute('SELECT count(*) FROM sent_jobs').fetchone()[0]>=256:raise PeerError('peer_limit')
            db.execute("INSERT INTO sent_jobs VALUES(?,?,?,?,?,'prepared',NULL)",(remote,request,peer['out_key'],now,command))
        return self.retry(remote,request)

    def retry(self,remote,request):
        identifier(request);peer,local=self.peer(remote)
        with self.db() as db:
            row=db.execute('SELECT * FROM sent_jobs WHERE peer=? AND id=?',(remote,request)).fetchone()
            if not row or row['generation']!=peer['out_key']:raise PeerError('peer_expired')
            if row['state']=='done':return json.loads(row['result'])
            if not 0<=int(self.clock())-row['issued']<=86400:raise PeerError('peer_expired')
            body={'request_id':request,'issued':row['issued'],'command':row['command']}
        try:result=self.send_call(peer,local,'admin',body)
        except PeerError:
            with self.db() as db:db.execute("UPDATE sent_jobs SET state='unknown' WHERE peer=? AND id=?",(remote,request))
            return {'request_id':request,'uncertain':True}
        if result.get('uncertain'):
            return result
        with self.db() as db:db.execute("UPDATE sent_jobs SET state='done',result=? WHERE peer=? AND id=?",(canonical(result).decode(),remote,request))
        return result

    def send_call(self,peer,local,operation,extra=None):
        body={'sender':local,'recipient':peer['id'],'timestamp':int(self.clock()),'nonce':secrets.token_hex(16),'operation':operation}
        if extra:body.update(extra)
        data=dict(body,signature=self.signature(peer['out_key'],body))
        response=self.http.request(peer['origin'],'/peer/call',data)
        signature=response.pop('signature',None)
        if set(response)!={'sender','recipient','nonce','result'} or not isinstance(signature,str) or not hmac.compare_digest(signature,self.signature(peer['in_key'],response)) or response.get('sender')!=peer['id'] or response.get('recipient')!=local or response.get('nonce')!=body['nonce']:raise PeerError('peer_invalid')
        if operation=='admin' and not isinstance(response['result'],dict):raise PeerError('peer_invalid')
        return response['result']

    def receive(self,data,read,write=None):
        admin=data.get('operation')=='admin'
        fields={'sender','recipient','timestamp','nonce','operation','signature'}|({'request_id','issued','command'} if admin else set())
        if set(data)!=fields or type(data['timestamp']) is not int or abs(self.clock()-data['timestamp'])>60:raise PeerError('peer_invalid')
        identifier(data['sender']);identifier(data['recipient']);identifier(data['nonce']);secret(data['signature'])
        peer,local=self.peer(data['sender'])
        payload={key:value for key,value in data.items() if key!='signature'}
        if data['recipient']!=local or not hmac.compare_digest(data['signature'],self.signature(peer['in_key'],payload)):raise PeerError('peer_invalid')
        operation=data['operation']
        allowed={'status','revoke'}|({'inbounds','appliedinbounds','admin'} if peer['role']=='follower' else set())
        if not isinstance(operation,str) or operation not in allowed:raise PeerError('peer_forbidden')
        if admin:
            identifier(data['request_id']);self.admin_command(data['command'])
            if write is None or type(data['issued']) is not int or not 0<=int(self.clock())-data['issued']<=86400:raise PeerError('peer_expired')
        cached=None
        with self.db() as db:
            current=db.execute('SELECT * FROM peers WHERE id=?',(data['sender'],)).fetchone()
            if not current or current['state']=='revoked' or current['in_key']!=peer['in_key']:raise PeerError('peer_revoked')
            if admin:
                grant=db.execute('SELECT * FROM grants WHERE peer=? AND generation=? AND inbounds_write=1',(data['sender'],peer['in_key'])).fetchone()
                if not grant:raise PeerError('peer_forbidden')
                db.execute('DELETE FROM admin_jobs WHERE issued<?',(int(self.clock())-172800,))
                job=db.execute('SELECT * FROM admin_jobs WHERE peer=? AND id=?',(data['sender'],data['request_id'])).fetchone()
                command_hash=digest(data['command'])
                if job:
                    if job['generation']!=peer['in_key'] or job['hash']!=command_hash or job['issued']!=data['issued']:raise PeerError('peer_invalid')
                    cached=json.loads(job['result']) if job['state']=='done' else {'request_id':data['request_id'],'uncertain':True}
                else:
                    if db.execute('SELECT count(*) FROM admin_jobs').fetchone()[0]>=256:raise PeerError('peer_limit')
                    db.execute("INSERT INTO admin_jobs VALUES(?,?,?,?,?,'running',NULL)",(data['sender'],data['request_id'],peer['in_key'],data['issued'],command_hash))
            db.execute('DELETE FROM nonces WHERE expires<?',(int(self.clock()),))
            if db.execute('SELECT count(*) FROM nonces WHERE peer=?',(data['sender'],)).fetchone()[0]>=1024 or db.execute('SELECT count(*) FROM nonces').fetchone()[0]>=8192:raise PeerError('peer_limit')
            try:db.execute('INSERT INTO nonces VALUES(?,?,?)',(data['sender'],data['nonce'],int(self.clock())+120))
            except sqlite3.IntegrityError:raise PeerError('peer_used') from None
            if operation=='revoke':
                db.execute("UPDATE peers SET state='revoked',in_key='',out_key='' WHERE id=?",(data['sender'],))
                db.execute("UPDATE invites SET state='revoked',auth_hash='' WHERE candidate=? AND state='approved'",(data['sender'],))
            else:db.execute("UPDATE peers SET state='connected' WHERE id=?",(data['sender'],))
        if admin:
            if cached is not None:result=cached
            else:
                # Commit intent before the side effect. A crash leaves an uncertain job,
                # never an automatically repeated write across two independent databases.
                result=write(data['sender'],data['command'])
                encoded=canonical(result)
                if len(encoded)>65536:raise PeerError('peer_limit')
                with self.db() as db:db.execute("UPDATE admin_jobs SET state='done',result=? WHERE peer=? AND id=?",(encoded.decode(),data['sender'],data['request_id']))
        else:result={'revoked':True} if operation=='revoke' else read(operation)
        if operation=='inbounds' and isinstance(result,dict):
            with self.db() as db:
                grant=db.execute('SELECT inbounds_write FROM grants WHERE peer=? AND generation=?',(data['sender'],peer['in_key'])).fetchone()
            result=dict(result,peer_inbounds_write=bool(grant and grant[0]))
        response={'sender':local,'recipient':data['sender'],'nonce':data['nonce'],'result':result}
        return dict(response,signature=self.signature(peer['out_key'],response))

    def revoke(self,remote):
        peer,local=self.peer(remote)
        with self.db() as db:
            db.execute("UPDATE peers SET state='revoked',in_key='',out_key='' WHERE id=?",(remote,))
            db.execute("UPDATE invites SET state='revoked',auth_hash='' WHERE candidate=? AND state='approved'",(remote,))
        notified=False
        try:self.send_call(peer,local,'revoke');notified=True
        except PeerError:pass
        return {'revoked':True,'remote_notified':notified}
