"""Durable HTTPS/listener settings, independent from VPN configuration and keys."""
import copy
import datetime as dt
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import secrets
from urllib.parse import urlsplit

from control.files import private_lock, SettingsBusy
from control.tls import from_panel_settings


class PanelSettingsError(Exception):
    pass


class PanelSettings:
    fields={'listen','port','origin','tls','certificate_agent'}

    def __init__(self,base,state,certificates,writer):
        self.base=copy.deepcopy(base)
        self.state=Path(state)
        if not self.state.is_absolute():raise PanelSettingsError('panel_settings_invalid')
        self.path=self.state/'panel-settings.json'
        self.certificates,self.write=certificates,writer

    def _read(self):
        if self.state.is_symlink() or self.path.is_symlink():raise PanelSettingsError('panel_settings_invalid')
        if not self.path.exists():return {}
        if not self.path.is_file() or self.path.stat().st_size>16384:raise PanelSettingsError('panel_settings_invalid')
        try:settings=json.loads(self.path.read_text(encoding='utf-8'))
        except (ValueError,UnicodeError):raise PanelSettingsError('panel_settings_invalid') from None
        if not isinstance(settings,dict) or set(settings)-self.fields:raise PanelSettingsError('panel_settings_invalid')
        return settings

    @staticmethod
    def revision(settings):
        return hashlib.sha256(json.dumps(settings,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()

    def effective(self,settings=None):
        settings=self._read() if settings is None else settings
        merged=copy.deepcopy(self.base)
        # TLS is replaced as a unit: never resurrect legacy paths from the base
        # configuration when switching to an automatic certificate or HTTP.
        if 'tls' in settings:
            merged.pop('cert_file',None);merged.pop('key_file',None)
            merged.pop('certificate_agent',None)
        merged.update(copy.deepcopy(settings))
        merged.setdefault('listen','127.0.0.1');merged.setdefault('port',9090)
        merged.setdefault('origin','http://127.0.0.1:9090')
        return merged

    def read(self):
        settings=self._read();merged=self.effective(settings)
        return {'settings':{key:value for key,value in merged.items() if key in self.fields or key in {'cert_file','key_file'}},
                'revision':self.revision(merged),'saved':self.path.exists(),'activation':'panel-restart-required'}

    def validate(self,panel):
        try:
            if not isinstance(panel.get('listen'),str):raise ValueError()
            bind=ipaddress.ip_address(panel['listen'])
            if type(panel.get('port')) is not int or not 1<=panel['port']<=65535:raise ValueError()
            origin=panel.get('origin')
            if not isinstance(origin,str) or len(origin)>1024:raise ValueError()
            url=urlsplit(origin)
            if origin!=url.scheme+'://'+url.netloc or any(not char.isprintable() for char in origin):raise ValueError()
            if url.scheme not in {'http','https'} or not url.hostname or url.username or url.password or url.path or url.query or url.fragment or url.port!=panel['port'] and not (url.port is None and panel['port']==(443 if url.scheme=='https' else 80)):
                raise ValueError()
            if url.scheme=='http':
                if not bind.is_loopback or not ipaddress.ip_address(url.hostname).is_loopback or from_panel_settings(panel) is not None:raise ValueError()
            else:
                agent=panel.get('certificate_agent')
                if isinstance(agent,dict) and agent.get('state_dir')==str(self.certificates.state):
                    jobs=self.certificates.read()['jobs']
                    job=next((job for job in jobs if job['id']==agent.get('job_id')),None)
                    if job is None or job['tls']!=panel.get('tls'):raise ValueError()
                if from_panel_settings(panel) is None:raise ValueError()
        except (ValueError,KeyError,TypeError,OSError) as error:
            raise PanelSettingsError('panel_settings_invalid') from error

    def prepare(self,patch):
        if not isinstance(patch,dict) or set(patch)-{'listen','port','origin','mode','cert_file','key_file','job_id','revision'}:
            raise PanelSettingsError('panel_settings_invalid')
        current=self.read()
        if patch.get('revision') is not None and patch['revision']!=current['revision']:
            raise PanelSettingsError('panel_settings_changed')
        if not all(key in patch for key in ('listen','port','origin','mode')):raise PanelSettingsError('panel_settings_invalid')
        candidate={key:patch[key] for key in ('listen','port','origin')}
        if patch['mode']=='loopback-http':
            if set(patch)&{'cert_file','key_file','job_id'}:raise PanelSettingsError('panel_settings_invalid')
            candidate['tls']={'mode':'manual'}
        elif patch['mode']=='manual':
            if 'job_id' in patch:raise PanelSettingsError('panel_settings_invalid')
            for key in ('cert_file','key_file'):
                path=patch.get(key)
                if not isinstance(path,str) or len(path)>1024 or not Path(path).is_absolute():raise PanelSettingsError('panel_settings_invalid')
            candidate['tls']={key:patch[key] for key in ('mode','cert_file','key_file')}
        elif patch['mode']=='agent':
            if set(patch)&{'cert_file','key_file'}:raise PanelSettingsError('panel_settings_invalid')
            jobs=self.certificates.read()['jobs']
            job=next((job for job in jobs if job['id']==patch.get('job_id')),None)
            if job is None:raise PanelSettingsError('certificate_missing')
            candidate['tls']=copy.deepcopy(job['tls'])
            candidate['certificate_agent']={'state_dir':str(self.certificates.state),'job_id':job['id']}
        else:raise PanelSettingsError('panel_settings_invalid')
        self.validate(self.effective(candidate))
        return {'revision':current['revision'],'settings':candidate}

    def backups(self):
        folder=self.state/'panel-backups'
        if folder.is_symlink():raise PanelSettingsError('panel_settings_invalid')
        return [path.name for path in sorted(folder.glob('panel-settings-*.json'),reverse=True) if not path.is_symlink() and path.is_file()][:200]

    def prepare_restore(self,name,expected=None):
        if not re.fullmatch(r'panel-settings-\d{8}T\d{6}Z-[a-f0-9]{8}\.json',name):raise PanelSettingsError('panel_settings_invalid')
        path=self.state/'panel-backups'/name
        if path.parent.is_symlink() or path.is_symlink() or not path.is_file() or path.stat().st_size>16384:raise PanelSettingsError('panel_settings_invalid')
        try:saved=json.loads(path.read_text(encoding='utf-8'))
        except (ValueError,UnicodeError):raise PanelSettingsError('panel_settings_invalid') from None
        if not isinstance(saved,dict) or set(saved)!={'settings'} or not isinstance(saved['settings'],dict) or set(saved['settings'])-self.fields:raise PanelSettingsError('panel_settings_invalid')
        current=self.read()
        if expected is not None and expected!=current['revision']:raise PanelSettingsError('panel_settings_changed')
        self.validate(self.effective(saved['settings']))
        return {'revision':current['revision'],'settings':saved['settings']}

    def commit(self,action):
        try:
            with private_lock(self.state/'.panel-settings.lock'):
                if self.read()['revision']!=action['revision']:raise PanelSettingsError('panel_settings_changed')
                self.validate(self.effective(action['settings']))
                self.write(self.path,action['settings'])
                return {'configuration_saved':True,'activation':'panel-restart-required'}
        except SettingsBusy:raise PanelSettingsError('panel_settings_changed') from None

    def backup(self):
        try:
            with private_lock(self.state/'.panel-settings.lock'):
                folder=self.state/'panel-backups'
                if folder.is_symlink():raise PanelSettingsError('panel_settings_invalid')
                folder.mkdir(mode=0o700,exist_ok=True)
                if len(list(folder.glob('panel-settings-*.json')))>=200:raise PanelSettingsError('panel_backup_full')
                name='panel-settings-'+dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+secrets.token_hex(4)+'.json'
                self.write(folder/name,{'settings':self._read()})
                return name
        except SettingsBusy:raise PanelSettingsError('panel_settings_changed') from None
