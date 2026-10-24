"""Shared CLI/panel operations for the independent certificate agent."""
from contextlib import contextmanager
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import tempfile


class CertificateJobError(Exception):
    pass


class CertificateJobs:
    def __init__(self, settings, default_state, writer, validator=None):
        self.state=Path(settings.get('state_dir',Path(default_state)/'certificates'))
        self.binary=Path(settings.get('binary','/usr/local/libexec/atlant-cert-agent'))
        self.path=self.state/'config.json'
        self.write,self.validator=writer,validator
        if not self.state.is_absolute():
            raise CertificateJobError('certificate_invalid')

    def available(self):
        return self.validator is not None or self.binary.is_absolute() and self.binary.is_file() and os.access(self.binary,os.X_OK)

    def _directory(self):
        self.state.mkdir(parents=True,exist_ok=True,mode=0o700)
        if self.state.is_symlink() or not self.state.is_dir():
            raise CertificateJobError('certificate_invalid')

    @staticmethod
    def revision(config):
        return hashlib.sha256(json.dumps(config,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()).hexdigest()

    def _read(self):
        if self.path.is_symlink():
            raise CertificateJobError('certificate_invalid')
        if not self.path.exists():
            return {'state_dir':str(self.state),'challenge_listen':':80','jobs':[]}
        if self.state.is_symlink() or self.path.is_symlink() or not self.path.is_file() or self.path.stat().st_size>64*1024:
            raise CertificateJobError('certificate_invalid')
        try:
            config=json.loads(self.path.read_text(encoding='utf-8'),parse_constant=lambda value:(_ for _ in ()).throw(ValueError()))
        except (ValueError,UnicodeError):
            raise CertificateJobError('certificate_invalid') from None
        self._shape(config)
        return config

    def read(self):
        config=self._read()
        from control.tls import agent_status
        result=dict(config,revision=self.revision(config),manager_available=self.available())
        result['jobs']=[dict(job,status=agent_status(str(self.state),job['id'],job['tls']['host'])) for job in config['jobs']]
        return result

    def backups(self):
        folder=self.state/'backups'
        if folder.is_symlink():raise CertificateJobError('certificate_invalid')
        return [{'name':path.name,'size':path.stat().st_size} for path in sorted(folder.glob('cert-config-*.json'),reverse=True)
                if not path.is_symlink() and path.is_file()][:200]

    def prepare_restore(self,name,expected=None):
        if not isinstance(name,str) or not re.fullmatch(r'cert-config-\d{8}T\d{6}Z-[a-f0-9]{8}\.json',name):
            raise CertificateJobError('certificate_invalid')
        path=self.state/'backups'/name
        if path.parent.is_symlink() or path.is_symlink() or not path.is_file() or path.stat().st_size>64*1024:
            raise CertificateJobError('certificate_invalid')
        try:
            saved=json.loads(path.read_text(encoding='utf-8'))
        except (ValueError,UnicodeError):
            raise CertificateJobError('certificate_invalid') from None
        if not isinstance(saved,dict) or set(saved)!={'exists','config'} or type(saved['exists']) is not bool:
            raise CertificateJobError('certificate_invalid')
        current=self._read();revision=self.revision(current)
        if expected is not None and expected!=revision:raise CertificateJobError('certificate_changed')
        self._validate(saved['config'])
        return {'revision':revision,'config':saved['config']}

    def _shape(self,config):
        if not isinstance(config,dict) or set(config)!={'state_dir','challenge_listen','jobs'} or config['state_dir']!=str(self.state) or not isinstance(config['jobs'],list) or len(config['jobs'])>16:
            raise CertificateJobError('certificate_invalid')
        if not isinstance(config['challenge_listen'],str) or len(config['challenge_listen'])>256:
            raise CertificateJobError('certificate_invalid')
        names=set()
        for job in config['jobs']:
            if not isinstance(job,dict) or set(job)!={'id','tls'} or not isinstance(job['id'],str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}',job['id']) or job['id']=='agent' or job['id'] in names:
                raise CertificateJobError('certificate_invalid')
            names.add(job['id'])
            options=job['tls']
            if not isinstance(options,dict) or set(options)-{'mode','host','cache_dir','email','accept_terms','staging'}:
                raise CertificateJobError('certificate_invalid')
            if options.get('mode') not in ('acme-ip','acme-domain') or options.get('accept_terms') is not True or type(options.get('staging')) is not bool:
                raise CertificateJobError('certificate_invalid')
            for key,maximum in [('host',253),('email',254)]:
                if not isinstance(options.get(key),str) or len(options[key])>maximum or any(c in options[key] for c in '\r\n\t'):
                    raise CertificateJobError('certificate_invalid')
            if options.get('cache_dir')!=str(self.state/'bundles'/job['id']):
                raise CertificateJobError('certificate_invalid')

    def _validate(self,config):
        self._shape(config)
        if not self.available():
            raise CertificateJobError('certificate_helper_missing')
        if self.validator is not None:
            self.validator(config)
            return
        self._directory()
        fd,path=tempfile.mkstemp(prefix='.candidate-',suffix='.json',dir=self.state)
        try:
            with os.fdopen(fd,'w',encoding='utf-8') as stream:
                json.dump(config,stream,allow_nan=False)
            try:
                result=subprocess.run([str(self.binary),'--check','--config',path],capture_output=True,timeout=15,check=False)
            except (OSError,subprocess.TimeoutExpired):
                raise CertificateJobError('certificate_helper_missing') from None
            if result.returncode:
                raise CertificateJobError('certificate_invalid')
        finally:
            Path(path).unlink(missing_ok=True)

    def prepare(self,command,identifier,patch=None,expected=None):
        if not isinstance(identifier,str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}',identifier) or identifier=='agent':
            raise CertificateJobError('certificate_invalid')
        config=self._read();revision=self.revision(config)
        if expected is not None and expected!=revision:
            raise CertificateJobError('certificate_changed')
        current=next((job for job in config['jobs'] if job['id']==identifier),None)
        if command=='certjobcreate' and current is not None:
            raise CertificateJobError('certificate_exists')
        if command in {'certjobset','certjobdelete'} and current is None:
            raise CertificateJobError('certificate_missing')
        if command=='certjobdelete':
            config['jobs']=[job for job in config['jobs'] if job['id']!=identifier]
        else:
            if not isinstance(patch,dict) or not patch or set(patch)-{'mode','host','email','accept_terms','staging'}:
                raise CertificateJobError('certificate_invalid')
            options=dict(current['tls']) if current else {'mode':'acme-domain','host':'','email':'','accept_terms':False,'staging':False,'cache_dir':str(self.state/'bundles'/identifier)}
            options.update(patch)
            if isinstance(options.get('host'),str):options['host']=options['host'].strip().lower()
            if current:current['tls']=options
            else:config['jobs'].append({'id':identifier,'tls':options})
        self._validate(config)
        return {'revision':revision,'config':config}

    def prepare_listener(self,address,expected=None):
        import ipaddress
        config=self._read();revision=self.revision(config)
        if expected is not None and expected!=revision:raise CertificateJobError('certificate_changed')
        try:
            host,port=address.rsplit(':',1)
            if not port.isascii() or not port.isdigit() or not 1<=int(port)<=65535:raise ValueError()
            if port!='80' and not ipaddress.ip_address(host.strip('[]')).is_loopback:raise ValueError()
        except (ValueError,AttributeError):raise CertificateJobError('certificate_invalid') from None
        config['challenge_listen']=address
        self._validate(config)
        return {'revision':revision,'config':config}

    @contextmanager
    def _locked(self):
        self._directory()
        path=self.state/'.settings.lock'
        if path.is_symlink():raise CertificateJobError('certificate_invalid')
        fd=os.open(path,os.O_CREAT|os.O_RDWR,0o600)
        try:
            if os.name=='nt':
                import msvcrt
                if not os.fstat(fd).st_size:os.write(fd,b'\0')
                os.lseek(fd,0,os.SEEK_SET)
                try:msvcrt.locking(fd,msvcrt.LK_NBLCK,1)
                except OSError:raise CertificateJobError('certificate_changed') from None
            else:
                import fcntl
                try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
                except OSError:raise CertificateJobError('certificate_changed') from None
            yield
        finally:
            os.close(fd)

    def commit(self,action):
        with self._locked():
            current=self._read()
            if self.revision(current)!=action['revision']:
                raise CertificateJobError('certificate_changed')
            self._validate(action['config'])
            self.write(self.path,action['config'])
            return {'configuration_saved':True,'agent_reload':'automatic-when-running'}

    def backup(self):
        with self._locked():
            current=self._read()
            folder=self.state/'backups';folder.mkdir(mode=0o700,exist_ok=True)
            if len(list(folder.glob('cert-config-*.json')))>=200:raise CertificateJobError('certificate_backup_full')
            name='cert-config-'+dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+secrets.token_hex(4)+'.json'
            self.write(folder/name,{'exists':self.path.exists(),'config':current})
            return name
