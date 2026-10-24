"""First installation of the independent panel, without changing the VPN unit."""
import hashlib
import http.client
import json
import os
from pathlib import Path
import platform
import secrets
import shutil
import socket
import subprocess

from atlantctl import API, private_write
from control.runtime import inspect_unit, public_runtime, unit_definition
from control.security import password_record


UNITS=('atlant-control-helper.service','atlant-control.service','atlant-cert-agent.service')


def source_files(source):
    source=Path(source)
    result=[]
    for path in sorted(source.rglob('*')):
        relative=path.relative_to(source)
        if '__pycache__' in relative.parts or path.name.startswith('test_') or path.name=='atlant_control_demo.py':continue
        if path.is_symlink():raise ValueError('Linked management sources are not accepted')
        if path.is_file() and (relative in {Path('LICENSE'),Path('LICENSING.md')} or path.name=='QRCODE-LICENSE.txt' or path.suffix=='.py' or relative.parts[0]=='control' and path.suffix in {'.js','.css','.html'} or relative.parts[0]=='systemd' and path.suffix=='.service'):
            result.append(relative)
    if Path('atlantctl.py') not in result or Path('control/server.py') not in result:raise ValueError('Incomplete management source tree')
    return result


def check_agent(path,digest,machine=None):
    path=Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size>64*1024*1024:raise ValueError('Invalid agent binary')
    if not isinstance(digest,str) or len(digest)!=64 or hashlib.sha256(path.read_bytes()).hexdigest()!=digest.lower():raise ValueError('Agent SHA-256 mismatch')
    header=path.read_bytes()[:20]
    expected={'x86_64':62,'amd64':62,'aarch64':183,'arm64':183}.get(machine or platform.machine().lower())
    if expected is None or len(header)<20 or header[:6]!=b'\x7fELF\x02\x01' or int.from_bytes(header[18:20],'little')!=expected:
        raise ValueError('Agent must be a native 64-bit Linux ELF')


class Installer:
    def __init__(self,source,agent,digest,unit='atlant_vpn.service',root=Path('/'),run=subprocess.run):
        self.source,self.agent,self.digest=Path(source),Path(agent),digest
        self.root=Path(root);self.run=run;self.unit=unit
        if unit in UNITS:raise ValueError('The existing VPN must be a separate service')
        self.app=self.root/'opt/atlant-control'
        self.config=self.root/'etc/atlant-control'
        self.state=self.root/'var/lib/atlant-control'
        self.helper_state=self.root/'var/lib/atlant-control-helper'
        self.installer_state=self.root/'var/lib/atlant-control-installer'
        self.command=self.root/'usr/local/bin/atlant'
        self.units=self.root/'etc/systemd/system'

    def preflight(self):
        check_agent(self.agent,self.digest)
        files=source_files(self.source)
        for path in [self.app,self.config,self.state,self.helper_state,self.command,*[self.units/name for name in UNITS]]:
            if path.exists() or path.is_symlink():raise ValueError('An installation target already exists; refusing to overwrite it')
            for parent in path.parents:
                if parent.is_symlink():raise ValueError('Linked installation parent')
                if parent.exists() and (parent.stat().st_uid!=0 or parent.stat().st_mode&0o022):raise ValueError('Installation parents must be root-owned and not group/world writable')
                if parent==self.root:break
        runtime=inspect_unit(self.unit,self.run)
        config=Path(runtime['config']);info=config.stat()
        if info.st_uid!=0 or info.st_mode&0o137:raise ValueError('The actual core configuration must be root-owned and private')
        self.verify_api(runtime)
        for unit in UNITS:
            result=self.run(['/usr/bin/systemctl','show',unit,'--property=LoadState','--value'],capture_output=True,text=True,timeout=10,check=False)
            if result.stdout.strip() not in {'not-found',''}:raise ValueError('A target service name is already in use')
        return {'runtime':runtime,'files':files}

    def verify_api(self,runtime):
        API(runtime).request('GET','/api/status')

    def public_plan(self,plan):
        return {'runtime':public_runtime(plan['runtime']),'application':str(self.app),'config':str(self.config),
                'panel_state':str(self.state),'services':list(UNITS),'agent_sha256':self.digest,
                'vpn_restart':False,'certificate_issuance':False,'initial_access':'loopback-http'}

    def account(self):
        import pwd
        import grp
        try:group=grp.getgrnam('atlant-control')
        except KeyError:
            self.checked(['/usr/sbin/groupadd','--system','atlant-control'])
            group=grp.getgrnam('atlant-control')
        try:user=pwd.getpwnam('atlant-control')
        except KeyError:
            self.checked(['/usr/sbin/useradd','--system','--gid','atlant-control','--home-dir',str(self.state),'--no-create-home','--shell','/usr/sbin/nologin','atlant-control'])
            user=pwd.getpwnam('atlant-control')
        if user.pw_uid==0 or user.pw_gid!=group.gr_gid or user.pw_shell not in {'/usr/sbin/nologin','/sbin/nologin','/bin/false'}:
            raise ValueError('Existing runtime account does not match the restricted account')
        if user.pw_dir!=str(self.state) or set(os.getgrouplist('atlant-control',group.gr_gid))!={group.gr_gid}:
            raise ValueError('Runtime account must have the managed home and no supplementary groups')
        return user.pw_uid,group.gr_gid

    def checked(self,argv):
        result=self.run(argv,capture_output=True,timeout=50,check=False)
        if result.returncode:raise RuntimeError('Installation service operation failed')

    def health(self,port,instance):
        connection=http.client.HTTPConnection('127.0.0.1',port,timeout=5)
        try:
            connection.request('GET','/control/health')
            response=connection.getresponse();raw=response.read(4097)
            if response.status!=200 or len(raw)>4096 or json.loads(raw)!= {'status':'ready','instance':instance}:
                raise RuntimeError('The new panel did not confirm its installation identity')
        finally:connection.close()

    def install(self,plan,login,password,port=9090,language='en'):
        record=password_record(password,login)
        if type(port) is not int or not 1024<=port<=65535:raise ValueError('Initial loopback port must be 1024–65535')
        with socket.socket() as probe:probe.bind(('127.0.0.1',port))
        if unit_definition(self.unit,self.run)[1]!=plan['runtime']['definition']:raise ValueError('The VPN unit changed after preflight')
        self.verify_api(plan['runtime'])
        uid,gid=self.account()
        transaction=secrets.token_hex(12);created=[];started=[];quarantine=[];stage=None
        if self.installer_state.is_symlink():raise ValueError('Linked installer state')
        self.installer_state.mkdir(parents=True,mode=0o700,exist_ok=True)
        if self.installer_state.stat().st_uid!=0 or self.installer_state.stat().st_mode&0o077:raise ValueError('Installer state must be root-owned mode 0700')
        journal=self.installer_state/(transaction+'.json')
        def save(phase):private_write(journal,{'transaction':transaction,'phase':phase,'created':[str(path) for path in created],
                                           'units':list(UNITS),'runtime_account_preserved':True,'quarantine':quarantine})
        save('preparing')
        try:
            self.app.parent.mkdir(parents=True,exist_ok=True)
            stage=self.app.parent/('.atlant-control-stage-'+transaction)
            stage.mkdir(mode=0o700)
            for relative in plan['files']:
                source=self.source/relative
                if source.is_symlink() or not source.is_file():raise ValueError('Management sources changed after preflight')
                target=stage/'management'/relative
                target.parent.mkdir(parents=True,exist_ok=True,mode=0o755)
                shutil.copyfile(source,target);os.chmod(target,0o644)
            (stage/'libexec').mkdir(mode=0o755)
            binary=stage/'libexec/atlant-cert-agent';shutil.copyfile(self.agent,binary)
            check_agent(binary,self.digest);os.chmod(binary,0o755)
            manifest={str(path.relative_to(stage)):hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(stage.rglob('*')) if path.is_file()}
            private_write(stage/'MANIFEST.json',manifest)
            if self.app.exists():raise ValueError('Application target appeared during installation')
            os.chmod(stage,0o755);stage.rename(self.app);stage=None;created.append(self.app);save('application-installed')
            for path,owner,mode in [(self.config,(0,gid),0o750),(self.state,(uid,gid),0o700),(self.helper_state,(0,gid),0o700)]:
                path.mkdir(parents=True,exist_ok=False,mode=mode);created.append(path);os.chown(path,*owner);os.chmod(path,mode);save('directories-created')
            runtime=plan['runtime']
            client={'api_url':runtime['api_url'],'api_key':runtime['api_key'],'state_dir':str(self.state),'instance':transaction,
                    'service_socket':'/run/atlant-control-helper/control.sock','language':language,
                    'certificate_agent':{'state_dir':str(self.state/'certificates'),'binary':str(self.app/'libexec/atlant-cert-agent')},
                    'panel':{'listen':'127.0.0.1','port':port,'origin':f'http://127.0.0.1:{port}','state_dir':str(self.state)}}
            private_write(self.config/'client.json',client);os.chown(self.config/'client.json',0,gid);os.chmod(self.config/'client.json',0o640)
            private_write(self.config/'helper.json',{'runtime_user':'atlant-control','runtime_group':'atlant-control','core_unit':self.unit,
                'core_config':runtime['config'],'state_dir':str(self.helper_state),
                'runtime_registration':{'definition':runtime['definition'],'overridden_fields':runtime['overridden_fields']}})
            private_write(self.state/'credentials.json',record);os.chown(self.state/'credentials.json',uid,gid)
            from control.access import entry_path
            prefix=entry_path(self.state)
            certs=self.state/'certificates';certs.mkdir(mode=0o700);os.chown(certs,uid,gid)
            private_write(certs/'config.json',{'state_dir':str(certs),'challenge_listen':':80','jobs':[]});os.chown(certs/'config.json',uid,gid)
            self.units.mkdir(parents=True,exist_ok=True)
            for name in UNITS:
                target=self.units/name
                if target.exists() or target.is_symlink():raise ValueError('Unit target appeared during installation')
                text=(self.source/'systemd'/name).read_text()
                text=text.replace('/opt/atlant-control',str(self.app)).replace('/etc/atlant-control',str(self.config)).replace('/var/lib/atlant-control',str(self.state))
                if name=='atlant-control-helper.service':
                    # Atomic saves need the parent directory writable. Keep /etc
                    # read-only except for the two explicitly registered scopes.
                    writable=[str(Path(runtime['config']).parent),str(self.config)]
                    text=text.replace('ProtectSystem=full\n','ProtectSystem=full\nReadWritePaths='+' '.join(json.dumps(path) for path in dict.fromkeys(writable))+'\n')
                if name=='atlant-cert-agent.service':text=text.replace('/usr/local/libexec/atlant-cert-agent',str(self.app/'libexec/atlant-cert-agent'))
                # Unit files are authored in the repository; this is not a shell command.
                fd=os.open(target,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o644)
                with os.fdopen(fd,'w') as stream:stream.write(text)
                created.append(target);save('units-installed')
            self.command.parent.mkdir(parents=True,exist_ok=True)
            fd=os.open(self.command,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o755)
            with os.fdopen(fd,'w') as stream:stream.write('#!/usr/bin/python3 -I\nimport sys\nsys.path.insert(0,'+repr(str(self.app/'management'))+')\nfrom atlantctl import main\nmain()\n')
            created.append(self.command);save('configured')
            self.checked(['/usr/bin/systemd-analyze','verify',*[str(self.units/name) for name in UNITS]])
            self.checked(['/usr/bin/systemctl','daemon-reload'])
            for name in UNITS[:2]:
                started.append(name);self.checked(['/usr/bin/systemctl','start',name]);self.checked(['/usr/bin/systemctl','is-active','--quiet',name])
            self.health(port,transaction)
            self.checked(['/usr/bin/systemctl','enable',*UNITS[:2]])
            save('installed')
            return {'installed':True,'url':client['panel']['origin']+prefix,'username':login,'transaction':transaction,'agent_started':False,'vpn_restarted':False}
        except BaseException:
            stopped=True
            for name in reversed(started):
                try:
                    result=self.run(['/usr/bin/systemctl','stop',name],capture_output=True,timeout=50,check=False)
                    if result.returncode:stopped=False
                    else:self.run(['/usr/bin/systemctl','disable',name],capture_output=True,timeout=15,check=False)
                except (OSError,subprocess.TimeoutExpired):stopped=False
            if not stopped:
                save('rollback-incomplete')
                raise RuntimeError('New component could not be stopped; installation files retained for recovery')
            for path in reversed(created):
                if path.exists() or path.is_symlink():
                    destination=path.parent/('.atlant-control-failed-'+transaction+'-'+path.name)
                    if destination.exists() or destination.is_symlink():raise RuntimeError('Quarantine path occupied')
                    path.rename(destination);quarantine.append({'source':str(path),'saved':str(destination)})
            if stage is not None and stage.exists():
                destination=stage.parent/('.atlant-control-failed-'+transaction+'-stage')
                stage.rename(destination);quarantine.append({'source':str(stage),'saved':str(destination)})
            self.run(['/usr/bin/systemctl','daemon-reload'],capture_output=True,timeout=15,check=False)
            save('rolled-back')
            raise
