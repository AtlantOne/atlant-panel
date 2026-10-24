"""Narrow root service for Atlant. Its socket authenticates Linux peer UIDs."""
import argparse
import datetime as dt
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import struct
import subprocess
import threading

from atlantctl import private_write
from control.runtime import unit_definition, inspect_unit
from control.notify import ready


class Actions:
    def __init__(self,settings,run=subprocess.run,root_owned=False):
        self.unit=settings['core_unit']
        if not re.fullmatch(r'atlant[-_A-Za-z0-9]*\.service',self.unit):raise ValueError('Only an Atlant service unit is allowed')
        self.config=Path(settings['core_config']);self.state=Path(settings['state_dir'])
        if not self.config.is_absolute() or not self.state.is_absolute():raise ValueError('Absolute paths required')
        self.run=run;self.lock=threading.Lock();self.gate=threading.BoundedSemaphore(1);self.root_owned=root_owned
        self.registration=settings.get('runtime_registration')
        if root_owned and (not isinstance(self.registration,dict) or set(self.registration)!={'definition','overridden_fields'}):
            raise ValueError('Verified runtime registration required')
        if root_owned and (not re.fullmatch(r'[0-9a-f]{64}',str(self.registration['definition'])) or not isinstance(self.registration['overridden_fields'],list) or set(self.registration['overridden_fields'])-{'sni','up_mbps','down_mbps'}):
            raise ValueError('Invalid runtime registration')

    def check_runtime(self,patch):
        if not self.root_owned:return
        if unit_definition(self.unit,self.run)[1]!=self.registration['definition']:raise ValueError('VPN service definition changed; reconcile installation first')
        if set(patch)&set(self.registration['overridden_fields']):raise ValueError('A service flag overrides a requested configuration field')
        pid=self.run(['/usr/bin/systemctl','show',self.unit,'--property=MainPID','--value'],capture_output=True,text=True,timeout=10,check=False)
        if pid.returncode or not pid.stdout.strip().isdigit():raise ValueError('Runtime state unavailable')
        if int(pid.stdout.strip())>0:
            actual=inspect_unit(self.unit,self.run)
            if Path(actual['config'])!=self.config.resolve() or actual['overridden_fields']!=self.registration['overridden_fields']:
                raise ValueError('Running core no longer matches registration')

    @staticmethod
    def patch(value):
        if not isinstance(value,dict) or not value or set(value)-{'sni','advertise_addr','up_mbps','down_mbps','log_level'}:raise ValueError('Unsupported configuration fields')
        for key,entry in value.items():
            if key=='log_level' and entry not in {'debug','info','warn','error','none'}:raise ValueError('Invalid logging level')
            if key in {'up_mbps','down_mbps'}:
                if type(entry) is not int or not 0<=entry<=1000000:raise ValueError('Invalid speed limit')
            elif key=='sni':
                if not isinstance(entry,str) or len(entry)>253 or '.' not in entry or not all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?',part) for part in entry.rstrip('.').split('.')):raise ValueError('Invalid SNI')
            elif key=='advertise_addr':
                if not isinstance(entry,str) or len(entry)>320:raise ValueError('Invalid advertised endpoint')
                if not entry:continue
                host,sep,port=entry.rpartition(':')
                if not sep or not port.isascii() or not port.isdigit() or not 1<=int(port)<=65535:raise ValueError('Invalid advertised port')
                try:ipaddress.ip_address(host.strip('[]'))
                except ValueError:
                    if not all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?',part) for part in host.split('.')):raise ValueError('Invalid advertised host')
        return dict(value)

    def read_config(self):
        if self.config.is_symlink() or not self.config.is_file() or self.config.stat().st_size>1024*1024:raise ValueError('Unsafe core configuration')
        info=self.config.stat()
        if self.root_owned and (info.st_uid!=0 or info.st_mode&0o137):raise ValueError('Core configuration must be root-owned and private')
        raw=self.config.read_bytes()
        data=json.loads(raw)
        if not isinstance(data,dict):raise ValueError('Invalid core configuration')
        return data,hashlib.sha256(raw).hexdigest()

    def audit(self,action,event):
        if self.state.is_symlink():raise ValueError('Unsafe helper state')
        self.state.mkdir(parents=True,mode=0o700,exist_ok=True)
        path=self.state/'audit.jsonl'
        if path.is_symlink():raise ValueError('Unsafe helper audit file')
        if path.exists() and path.stat().st_size>2*1024*1024:
            os.replace(path,self.state/'audit.previous.jsonl')
        fd=os.open(path,os.O_CREAT|os.O_WRONLY|os.O_APPEND,0o600)
        with os.fdopen(fd,'w',encoding='utf-8') as stream:
            stream.write(json.dumps({'time':dt.datetime.now(dt.timezone.utc).isoformat(),'operation':action,'event':event,'unit':'atlant-cert-agent.service' if action.startswith('cert-') else self.unit})+'\n')
            stream.flush();os.fsync(stream.fileno())

    def execute(self,action,body):
        if not isinstance(action,str):raise ValueError('Invalid service action')
        if action=='logs':return self.journal(body)
        if not self.gate.acquire(blocking=False):raise RuntimeError('Another service operation is in progress')
        mutating=action in {'start','stop','restart','configsave','cert-start','cert-stop','cert-restart'}
        try:
            if mutating:self.audit(action,'begin')
            result=self._execute(action,body)
            if mutating:self.audit(action,'done')
            return result
        finally:self.gate.release()

    def journal(self,body):
        if not isinstance(body,dict) or set(body)!={'lines'} or type(body['lines']) is not int or not 1<=body['lines']<=200:
            raise ValueError('Invalid journal line limit')
        result=self.run(['/usr/bin/journalctl','--unit='+self.unit,'--lines='+str(body['lines']),'--output=cat','--no-pager','--quiet'],capture_output=True,text=True,timeout=3,check=False)
        if result.returncode:raise RuntimeError('Service journal unavailable')
        payload={'logs':[line[:2048] for line in result.stdout.splitlines()[-body['lines']:]],'source':'journal'}
        # Keep the helper response within its existing 16 KiB protocol limit.
        while payload['logs'] and len(json.dumps(payload).encode())>15000:payload['logs'].pop(0)
        return payload

    def _execute(self,action,body):
        with self.lock:
            if action in {'status','start','stop','restart','cert-status','cert-start','cert-stop','cert-restart'}:
                if body is not None:raise ValueError('Unexpected service arguments')
                operation=action.removeprefix('cert-');unit='atlant-cert-agent.service' if action.startswith('cert-') else self.unit
                if operation!='status':
                    result=self.run(['/usr/bin/systemctl',operation,unit],capture_output=True,timeout=45,check=False)
                    if result.returncode:raise RuntimeError('Service operation failed')
                result=self.run(['/usr/bin/systemctl','show',unit,'--property=ActiveState,SubState,MainPID'],capture_output=True,text=True,timeout=10,check=False)
                if result.returncode:raise RuntimeError('Service status unavailable')
                values=dict(line.split('=',1) for line in result.stdout.splitlines() if '=' in line)
                return {'active':values.get('ActiveState','unknown'),'state':values.get('SubState','unknown'),'pid':int(values.get('MainPID','0'))}
            if action=='configcheck':
                patch=self.patch(body);self.check_runtime(patch);_,revision=self.read_config()
                return {'patch':patch,'revision':revision}
            if action=='configinfo':
                if body is not None:raise ValueError('Unexpected configuration info arguments')
                verified=self.root_owned and unit_definition(self.unit,self.run)[1]==self.registration['definition']
                data,_=self.read_config()
                return {'verified':verified,'overridden_fields':self.registration['overridden_fields'] if self.registration else [],'log_level':data.get('log_level','error')}
            if action=='configsave':
                if not isinstance(body,dict) or set(body)!={'patch','revision'}:raise ValueError('Revision required')
                patch=self.patch(body['patch']);self.check_runtime(patch);current,revision=self.read_config()
                if body['revision']!=revision:raise ValueError('Core configuration changed')
                if self.state.is_symlink():raise ValueError('Unsafe helper state')
                owner=(self.config.stat().st_uid,self.config.stat().st_gid) if self.root_owned else None
                private_write(self.config,dict(current,**patch),permissions=self.config.stat().st_mode&0o777,owner=owner)
                return {'configuration_saved':True,'activation':'core-restart-required'}
            raise ValueError('Unsupported service action')


class Helper:
    def __init__(self,path,uid,gid,actions,allow_root=True):
        self.path=Path(path);self.uid,self.gid,self.actions=uid,gid,actions
        self.slots=threading.BoundedSemaphore(4)
        self.socket=None
        self.allowed_uids={uid,0} if allow_root else {uid}

    def handle(self,connection):
        try:
            connection.settimeout(3)
            _,uid,_=struct.unpack('3i',connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
            if uid not in self.allowed_uids:return
            with connection.makefile('rb') as stream:raw=stream.readline(8193)
            if len(raw)>8192 or not raw.endswith(b'\n'):return
            try:
                command=json.loads(raw,parse_constant=lambda _:(_ for _ in ()).throw(ValueError()))
                if not isinstance(command,dict) or set(command)!={'action','body'}:raise ValueError()
                result=self.actions.execute(command['action'],command['body'])
                response={'ok':True,'result':result}
            except (ValueError,TypeError,KeyError,OSError,RuntimeError,subprocess.TimeoutExpired):
                response={'ok':False}
            connection.sendall(json.dumps(response,allow_nan=False).encode()+b'\n')
        except OSError:pass
        finally:
            connection.close();self.slots.release()

    def serve(self,stop,on_ready=None):
        self.path.parent.mkdir(parents=True,mode=0o750,exist_ok=True)
        if self.path.is_symlink() or self.path.exists():raise ValueError('Helper socket already exists; refusing to replace it')
        listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        self.socket=listener
        identity=None
        try:
            listener.bind(str(self.path))
            info=self.path.stat();identity=(info.st_dev,info.st_ino)
            if self.gid is not None:os.chown(self.path,0,self.gid)
            os.chmod(self.path,0o660)
            listener.listen(4);listener.settimeout(0.2)
            if on_ready:on_ready()
            while not stop.is_set():
                try:connection,_=listener.accept()
                except socket.timeout:continue
                if not self.slots.acquire(blocking=False):connection.close();continue
                threading.Thread(target=self.handle,args=(connection,),daemon=True).start()
        finally:
            listener.close()
            if identity is not None:
                try:
                    info=self.path.lstat()
                    if (info.st_dev,info.st_ino)==identity:self.path.unlink()
                except FileNotFoundError:pass


def main():
    import signal
    import grp
    import pwd
    parser=argparse.ArgumentParser(description='Restricted Atlant service helper (Linux)')
    parser.add_argument('--config',default='/etc/atlant-control/helper.json')
    args=parser.parse_args()
    if not hasattr(socket,'SO_PEERCRED') or os.geteuid()!=0:parser.error('Root and Linux peer credentials required')
    config=Path(args.config);info=config.stat()
    if config.is_symlink() or info.st_uid!=0 or info.st_mode&0o077 or info.st_size>16384:parser.error('Helper configuration must be root-owned mode 0600')
    settings=json.loads(config.read_text())
    uid=pwd.getpwnam(settings['runtime_user']).pw_uid
    gid=grp.getgrnam(settings['runtime_group']).gr_gid
    if uid==0:parser.error('The panel must use a non-root account')
    stop=threading.Event()
    for signum in (signal.SIGTERM,signal.SIGINT):signal.signal(signum,lambda *_:stop.set())
    Helper('/run/atlant-control-helper/control.sock',uid,gid,Actions(settings,root_owned=True)).serve(stop,on_ready=ready)
