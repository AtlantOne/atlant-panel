"""Interactive terminal UI over the same operations used by the web panel."""
import json
import shlex

from control.i18n import MESSAGES, error_message, message


def saved_language(state, fallback):
    from pathlib import Path
    path=Path(state)/'console-preferences.json'
    try:
        if path.is_symlink() or path.stat().st_size>4096:return fallback
        value=json.loads(path.read_text(encoding='utf-8')).get('language')
        return value if value in ('en','ru','zh') else fallback
    except (OSError,ValueError,AttributeError):return fallback


class Console:
    def __init__(self, manager, lang='en', read=input, write=print):
        self.manager, self.lang, self.read, self.write = manager, lang, read, write

    def text(self, key):
        aliases={'up_bytes':'upload','down_bytes':'download','expires_at':'expires','not_after':'certificate_expiry','configuration_error':'error'}
        key=aliases.get(key,key)
        return message(key, self.lang) if key in MESSAGES else key.replace('_',' ')

    def ask(self, key, default=None):
        prompt = self.text(key) + (f' [{self.scalar(default)}]' if default is not None else '') + ': '
        value = self.read(prompt).strip()
        return value if value or default is None else default

    def choose(self, title, choices):
        self.write('\nAtlant Control · ' + self.text(title))
        for index, (label, _) in enumerate(choices, 1):
            self.write(f'  {index}. {self.text(label)}')
        self.write('  0. ' + self.text('back'))
        value = self.read('> ').strip()
        if value == '0': return None
        if not value.isascii() or not value.isdigit() or not 1 <= int(value) <= len(choices):
            self.write(self.text('invalid'))
            return False
        return choices[int(value)-1][1]

    def run_command(self, command, show=True, reveal=False):
        from atlantctl import AdminError
        action = self.manager.prepare(command)
        if action['secret'] and not reveal:
            raise AdminError('forbidden')
        label=(message(action['label_key'],self.lang)+' · '+action['target']) if action.get('label_key') else action['label']
        if action['write'] and self.read(message('confirm',self.lang,operation=label)) != 'yes':
            self.write(self.text('cancelled'))
            return None
        result = self.manager.execute(action)
        if show: self.describe(result)
        return result

    def describe(self, result, depth=0):
        """Readable nested details, without dumping configuration JSON."""
        if isinstance(result, dict):
            notice='peer_uncertain' if result.get('uncertain') else 'peer_operation_failed' if result.get('ok') is False else 'peer_revoked_offline' if result.get('remote_notified') is False else 'peer_pending_notice' if result.get('pending') is True else 'peer_connected_notice' if result.get('connected') is True else 'peer_approved_notice' if result.get('approved') is True else None
            if notice:self.write(self.text(notice))
            for key,value in result.items():
                if isinstance(value,(list,dict)):
                    self.write('  '*depth + self.text(key) + ':')
                    self.describe(value,depth+1)
                else:
                    self.write('  '*depth + self.text(key) + ': ' + self.scalar(value))
        elif isinstance(result,list):
            if not result:self.write('  '*depth + self.text('empty'))
            for value in result:
                self.write('  '*depth + '—')
                self.describe(value,depth+1)
        else:self.write('  '*depth + self.scalar(result))

    def scalar(self, value):
        if value is True:return self.text('enabled')
        if value is False:return self.text('disabled')
        if value is None:return '—'
        # API and user strings must not inject terminal control sequences.
        return ''.join(char if char.isprintable() else ' ' for char in str(value))

    def guarded(self, action):
        from atlantctl import AdminError
        try:action()
        except AdminError as error:self.write(error_message(error,self.lang))
        except (ValueError,OSError,KeyError,TypeError):self.write(self.text('invalid'))

    def run(self):
        self.write(self.text('gpl_notice'))
        actions=[('panel_settings',self.panel_menu),('certificates',self.certificates),
                 ('logs',self.logs_menu),('language',self.languages),
                 ('license',lambda:self.run_command('license'))]
        try:
            while True:
                self.guarded(self.show_panel_link)
                action=self.choose('control_plane',actions)
                if action is None:return
                if action:self.guarded(action)
        except (EOFError,KeyboardInterrupt):self.write('\n'+self.text('cancelled'))

    def core_settings(self):
        while True:
            action=self.choose('core_settings',[('legacy_accounts',self.users),('groups',lambda:self.run_command('groups'))])
            if action is None:return
            if action:self.guarded(action)

    def logs_menu(self, lines=50):
        while True:
            action=self.choose('logs',[
                ('show_logs',lambda:self.run_command('logs '+str(lines))),
                ('change_log_level',self.change_log_level),
                ('show_log_path',self.show_log_path)])
            if action is None:return
            if action:self.guarded(action)

    def change_log_level(self):
        info=self.run_command('configinfo',False)
        if not info.get('verified') or 'log_level' in info.get('overridden_fields',[]):
            self.write(self.text('cli_log_level_unavailable'));return
        self.write(self.text('log_level')+': '+self.scalar(info.get('log_level','error')))
        level=self.choose('change_log_level',[(key,value) for key,value in [
            ('log_debug','debug'),('log_info','info'),('log_warn','warn'),('log_error','error'),('log_none','none')]])
        if not level:return
        self.write(self.text('log_level_notice'))
        result=self.run_command('configsave '+json.dumps({'log_level':level}),False)
        if result is None:return
        # Saving the level does not implicitly interrupt active VPN sessions.
        if self.read(self.text('cli_log_restart'))=='yes':
            self.describe(self.manager.execute(self.manager.prepare('service restart')))

    def show_log_path(self):
        from pathlib import Path
        import re
        unit='atlant_vpn.service'
        try:
            candidate=json.loads(Path('/etc/atlant-control/helper.json').read_text(encoding='utf-8')).get('core_unit',unit)
            if isinstance(candidate,str) and re.fullmatch(r'atlant[-_A-Za-z0-9]*\.service',candidate):unit=candidate
        except (OSError,ValueError,AttributeError):pass
        self.write(self.text('cli_journal_path'))
        for folder in ('/var/log/journal','/run/log/journal'):
            if Path(folder).is_dir():self.write(folder)
        self.write('journalctl -u '+unit+' -n 50 --no-pager')

    def panel_password(self):
        from control.access import set_password
        from atlantctl import private_write
        set_password(self.manager.panel_settings.state,self.lang,private_write,ask=self.read)
        self.write(self.text('cli_password_saved'))

    def show_panel_link(self):
        value=self.run_command('panelurl',False,reveal=True)
        self.write(self.text('saved_panel_link')+': '+self.scalar(value))

    def panel_menu(self):
        while True:
            self.guarded(self.show_panel_link)
            action=self.choose('panel_settings',[
                ('panel_port',self.panel_port),('panel_address',self.panel_settings),
                ('panelpassword',self.panel_password),
                ('panel_backups',self.panel_backups),('apply_panel_settings',self.restart_panel)])
            if action is None:return
            if action:self.guarded(action)

    def panel_port(self):
        from urllib.parse import urlsplit
        data=self.run_command('panelsettings',False);current=data['settings']
        value=self.ask('port',str(current['port']))
        if not value.isascii() or not value.isdigit() or not 1<=int(value)<=65535:raise ValueError()
        parsed=urlsplit(current['origin']);host=parsed.hostname
        if ':' in host:host='['+host+']'
        patch={'listen':current['listen'],'port':int(value),'origin':parsed.scheme+'://'+host+':'+str(int(value)),'revision':data['revision']}
        tls=current.get('tls',{});agent=current.get('certificate_agent',{})
        if parsed.scheme=='http':patch['mode']='loopback-http'
        elif agent.get('job_id'):patch.update(mode='agent',job_id=agent['job_id'])
        else:patch.update(mode='manual',cert_file=tls.get('cert_file',current.get('cert_file')),key_file=tls.get('key_file',current.get('key_file')))
        self.write(self.text('panel_saved_notice'))
        self.write(self.scalar(current['origin'])+' → '+patch['origin'])
        self.run_command('panelset '+json.dumps(patch))

    def restart_panel(self):
        import subprocess
        if self.read(self.text('panel_restart_confirm'))!='yes':self.write(self.text('cancelled'));return
        try:
            for args in (['systemctl','restart','atlant-control.service'],['systemctl','is-active','--quiet','atlant-control.service']):
                result=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=25,check=False)
                if result.returncode:self.write(self.text('panel_restart_failed'));return
        except (OSError,subprocess.TimeoutExpired):self.write(self.text('panel_restart_failed'));return
        self.write(self.text('panel_restart_done'))
        self.show_panel_link()

    def servers(self):
        while True:
            action=self.choose('nodes',[('refresh',lambda:self.run_command('peers')),
                ('remotecatalogs',lambda:self.run_command('remotecatalogs')),
                ('peerinvite',lambda:self.run_command('peerinvite',reveal=True)),
                ('peerjoin',lambda:self.run_command('peerjoin '+shlex.quote(self.ask('pairing_link')))),
                ('peerapprove',lambda:self.peer_selection('incoming','peerapprove')),
                ('peerreject',lambda:self.peer_selection('incoming','peerreject')),
                ('peerfinish',lambda:self.peer_selection('outgoing','peerfinish')),
                ('peercancel',lambda:self.peer_selection('outgoing','peercancel')),
                ('peercatalog',lambda:self.peer_selection('peers','peercatalog')),
                ('peer_manage',lambda:self.peer_selection('peers','manage')),
                ('peer_allow_writes',lambda:self.peer_selection('peers','allow')),
                ('peer_deny_writes',lambda:self.peer_selection('peers','deny')),
                ('peerjobs',lambda:self.peer_selection('peers','jobs')),
                ('peersync',lambda:self.peer_selection('peers','peersync')),
                ('peerrevoke',lambda:self.peer_selection('peers','peerrevoke'))])
            if action is None:return
            if action:self.guarded(action)

    def peer_selection(self,section,command):
        records=self.run_command('peers',False)[section]
        if section=='peers':records=[record for record in records if record['state']!='revoked']
        if not records:raise ValueError()
        self.write(self.text('pairing_notice'))
        for index,record in enumerate(records,1):self.write(f"{index}. {self.scalar(record.get('remote') or record['id'])} · {self.scalar(record['origin'])}")
        value=self.read('> ').strip()
        if not value.isascii() or not value.isdigit() or not 1<=int(value)<=len(records):raise ValueError()
        remote=records[int(value)-1]['id']
        if command=='manage':return self.inbounds(remote)
        if command in ('allow','deny'):return self.run_command('peergrant '+remote+' '+('true' if command=='allow' else 'false'))
        if command=='jobs':
            jobs=self.run_command('peerjobs '+remote)['jobs']
            pending=[job for job in jobs if job['state']!='done']
            if not pending:return
            for index,job in enumerate(pending,1):self.write(f"{index}. {job['id']}")
            value=self.ask('peerretry')
            if not value.isascii() or not value.isdigit() or not 1<=int(value)<=len(pending):raise ValueError()
            return self.run_command('peerretry '+remote+' '+pending[int(value)-1]['id'])
        self.run_command(command+' '+remote)

    def subscribers(self):
        while True:
            action=self.choose('subscriptions',[('refresh',lambda:self.run_command('subscriptions')),('create_subscriber',lambda:self.edit_subscriber(False)),('edit_subscriber',lambda:self.edit_subscriber(True)),('disconnect',lambda:self.subscriber_action('subkick')),('rekey',lambda:self.subscriber_action('subrekey')),('migrate_subscriptions',self.migrate_subscriptions)])
            if action is None:return
            if action:self.guarded(action)

    def subscriber_action(self,command):
        records=[record for record in self.run_command('subscriptions',False) if record.get('managed')]
        if not records:raise ValueError()
        for index,record in enumerate(records,1):self.write(f"{index}. {self.scalar(record['title'])}")
        value=self.read('> ').strip()
        if not value.isascii() or not value.isdigit() or not 1<=int(value)<=len(records):raise ValueError()
        self.run_command(command+' '+records[int(value)-1]['id'])

    def migrate_subscriptions(self):
        plan=self.run_command('submigration',False)
        self.write(self.text('migration_notice'))
        for index,item in enumerate(plan['items'],1):
            self.write(f"{index}. {self.scalar(item['title'])} · {item['converted_profiles']} / {item['preserved_profiles']}")
            for reason in item['blockers']:self.write('  '+self.text(reason))
        if not any(item['eligible'] for item in plan['items']):self.write(self.text('migration_empty'));return
        value=self.ask('select_migrations','')
        if not value:return
        indices=[part.strip() for part in value.split(',')]
        if len(indices)>100 or len(set(indices))!=len(indices):raise ValueError()
        selected=[]
        for value in indices:
            if not value.isascii() or not value.isdigit() or not 1<=int(value)<=len(plan['items']):raise ValueError()
            item=plan['items'][int(value)-1]
            if not item['eligible']:raise ValueError()
            selected.append(item['id'])
        self.run_command('submigrate '+plan['revision']+' '+' '.join(selected))

    def edit_subscriber(self,edit):
        import datetime as dt
        from atlantctl import quota_bytes, quota_input
        catalog=self.run_command('inbounds',False)
        current=None
        if edit:
            records=self.run_command('subscriptions',False)
            for index,record in enumerate(records,1):self.write(f"{index}. {self.scalar(record['title'])}")
            choice=self.read('> ').strip()
            if not choice.isascii() or not choice.isdigit() or not 1<=int(choice)<=len(records):raise ValueError()
            current=records[int(choice)-1]
        current=current or {'title':'','enabled':True,'expires_at':0,'update_hours':1,'total_limit':0,'inbound_refs':[]}
        patch={'title':self.ask('title',current['title'])}
        enabled=self.ask('enabled','true' if current['enabled'] else 'false').lower()
        if enabled not in ('true','false'):raise ValueError()
        patch['enabled']=enabled=='true'
        if not edit or current.get('managed'):
            value=self.ask('subscriber_ip_limit',str(current.get('ip_limit',0)))
            if not value.isascii() or not value.isdigit() or not 0<=int(value)<=10000:raise ValueError()
            patch['ip_limit']=int(value)
            patch['note']=self.ask('note',current.get('note',''))
            if len(patch['note'].encode('utf-8'))>4096:raise ValueError()
        expiry=dt.datetime.fromtimestamp(current['expires_at'],dt.timezone.utc).isoformat() if current['expires_at'] else ''
        expiry=self.ask('expires',expiry)
        parsed=dt.datetime.fromisoformat(expiry.replace('Z','+00:00')) if expiry else None
        if parsed is not None and parsed.tzinfo is None:raise ValueError()
        patch['expires_at']=int(parsed.timestamp()) if parsed else 0
        patch['update_hours']=int(self.ask('update_hours',str(current['update_hours'])))
        if not 1<=patch['update_hours']<=168:raise ValueError()
        shared='true' if current.get('total_limit') is not None else self.ask('shared','false').lower()
        if shared not in ('true','false'):raise ValueError()
        if shared=='true':patch['total_limit']=quota_bytes(self.ask('gib',quota_input(current.get('total_limit',0))))
        self.write(self.text('subscriber_connections_notice'))
        local=catalog['server_id'];records=catalog['inbounds']
        for index,record in enumerate(records,1):
            spec=record['settings'];self.write(f"{index}. {self.scalar(spec['name'])} · {self.scalar(spec.get('advertise_addr') or spec['listen'])}")
        selected={ref['inbound_id'] for ref in current.get('inbound_refs',[]) if ref['server_id']==local}
        defaults=','.join(str(index) for index,record in enumerate(records,1) if record['settings']['id'] in selected)
        values=self.ask('connections',defaults)
        indices=[value.strip() for value in values.split(',')] if values else []
        if any(not value.isascii() or not value.isdigit() or not 1<=int(value)<=len(records) for value in indices):raise ValueError()
        if len(set(indices))!=len(indices):raise ValueError()
        patch['inbound_refs']=[ref for ref in current.get('inbound_refs',[]) if ref['server_id']!=local]+[{'server_id':local,'inbound_id':records[int(value)-1]['settings']['id']} for value in indices]
        if (not edit and not patch['inbound_refs']) or (patch['inbound_refs'] and shared!='true'):raise ValueError()
        if edit:
            patch['revision']=current['revision'];command='subset '+current['id']+' '+json.dumps(patch)
        else:command='subscribercreate '+json.dumps(patch)
        self.run_command(command,reveal=not edit)

    def inbound_catalog(self,remote=''):
        return self.run_command('peercatalog '+remote if remote else 'inbounds',False)

    def inbound_write(self,command,remote=''):
        return self.run_command('peerexecute '+remote+' '+shlex.quote(command) if remote else command)

    def inbounds(self,remote=''):
        while True:
            action=self.choose('inbounds',[
                ('refresh',lambda:self.describe(self.inbound_catalog(remote))),
                ('create',lambda:self.edit_inbound(False,remote)),('edit',lambda:self.edit_inbound(True,remote)),
                ('delete',lambda:self.delete_inbound(remote)),('apply_inbounds',lambda:self.apply_inbounds(remote))])
            if action is None:return
            if action:self.guarded(action)

    def selected_inbound(self,catalog):
        records=catalog['inbounds']
        if not records:raise ValueError()
        self.write(self.text('inbounds'))
        for index,record in enumerate(records,1):
            settings=record['settings']
            self.write(f"{index}. {self.scalar(settings['name'])} [{self.scalar(settings['id'])}]")
        value=self.read('> ').strip()
        if not value.isascii() or not value.isdigit() or not 1<=int(value)<=len(records):raise ValueError()
        return dict(records[int(value)-1]['settings'])

    def edit_inbound(self,edit,remote=''):
        from atlantctl import INBOUND_TUNING
        catalog=self.inbound_catalog(remote)
        settings=self.selected_inbound(catalog) if edit else {'id':self.ask('inbound_id'),'name':'','enabled':True,'listen':'0.0.0.0:1026','advertise_addr':'','sni':'','transports':['tcp','xhttp','quic'],'wire_version':7,'xhttp_path':'/api/v1/sync','up_mbps':0,'down_mbps':0}
        self.write(self.text('inbound_key_notice'))
        for key in ('name','listen','advertise_addr','sni','xhttp_path'):
            settings[key]=self.ask(key,settings.get(key,''))
        enabled=self.ask('enabled','true' if settings['enabled'] else 'false').lower()
        if enabled not in ('true','false'):raise ValueError()
        settings['enabled']=enabled=='true'
        transports=[]
        for transport in ('tcp','xhttp','quic'):
            value=self.ask('transport_'+transport,'true' if transport in settings['transports'] else 'false').lower()
            if value not in ('true','false'):raise ValueError()
            if value=='true':transports.append(transport)
        if not transports:raise ValueError()
        settings['transports']=transports
        for key in ('up_mbps','down_mbps'):
            settings[key]=int(self.ask(key,str(settings.get(key,0))))
            if not 0<=settings[key]<=1000000:raise ValueError()
        advanced=self.ask('transport_tuning','false').lower()
        if advanced not in ('true','false'):raise ValueError()
        if advanced=='true':
            self.write(self.text('tuning_defaults'))
            for section,fields in INBOUND_TUNING.items():
                tuning=dict(settings.get(section,{}));self.write(self.text(section+'_tuning'))
                for key,label,maximum in fields:
                    value=self.ask(label,str(tuning.get(key,0)))
                    if not value.isascii() or not value.isdigit() or not 0<=int(value)<=maximum:raise ValueError()
                    tuning[key]=int(value)
                if section=='quic':
                    value=self.ask('quic_disable_pacer','true' if tuning.get('disable_pacer',False) else 'false').lower()
                    if value not in ('true','false'):raise ValueError()
                    tuning['disable_pacer']=value=='true'
                elif tuning.get('max_connection_window_kb'):self.write(self.text('yamux_legacy_window_notice'))
                settings[section]=tuning
        self.inbound_write(('inboundset' if edit else 'inboundcreate')+' '+str(catalog['revision'])+' '+json.dumps(settings),remote)

    def delete_inbound(self,remote=''):
        catalog=self.inbound_catalog(remote)
        settings=self.selected_inbound(catalog)
        self.inbound_write(f"inbounddelete {catalog['revision']} {settings['id']}",remote)

    def apply_inbounds(self,remote=''):
        catalog=self.inbound_catalog(remote)
        self.write(self.text('inbounds_apply_notice'))
        self.inbound_write(f"inboundapply {catalog['revision']}",remote)

    def users(self):
        while True:
            action=self.choose('users',[
                ('refresh',lambda:self.run_command('usersall')),
                ('create',self.create_user),
                ('edit',self.edit_user),
                *[(label,lambda command=command:self.run_command(command+' '+shlex.quote(self.ask('name'))))
                  for label,command in [('enable','enable'),('disable','disable'),('disconnect','kick'),('reset_traffic','reset'),('delete','delete')]]])
            if action is None:return
            if action:self.guarded(action)

    def create_user(self):
        from atlantctl import quota_bytes, quota_input
        import time
        name=self.ask('name');quota=quota_bytes(self.ask('gib','0'));days=int(self.ask('days','0'))
        if not 0<=days<=36500:raise ValueError()
        values={'name':name,'total_limit':quota,'expires_at':int(time.time())+days*86400 if days else 0,
                'enabled':True,'ip_limit':int(self.ask('ip_limit','0')),'note':self.ask('note','')}
        self.run_command('usercreate '+json.dumps(values))

    def edit_user(self):
        from atlantctl import quota_bytes, quota_input
        name=self.ask('name')
        user=self.run_command('user '+shlex.quote(name),False)
        if user.get('subscription_id'):
            self.write(self.text('shared_quota_note'))
            fields={'ip_limit':int(self.ask('ip_limit',str(user.get('ip_limit',0)))),'note':self.ask('note',user.get('note',''))}
        else:
            fields={'ip_limit':int(self.ask('ip_limit',str(user.get('ip_limit',0)))),'note':self.ask('note',user.get('note','')),
                    'total_limit':quota_bytes(self.ask('gib',quota_input(user.get('total_limit',0))))}
        self.run_command('set '+shlex.quote(name)+' '+json.dumps(fields))

    def certificates(self):
        self.write(self.text('certificate_job_notice'))
        while True:
            action=self.choose('certificates',[
                ('certificate_status',self.certificate_status),
                ('tls_domain',lambda:self.create_certificate('acme-domain')),
                ('tls_ip',lambda:self.create_certificate('acme-ip')),
                ('edit',self.edit_certificate),('stop_renewal',self.delete_certificate)])
            if action is None:return
            if action:self.guarded(action)

    def certificate_status(self):
        from urllib.parse import urlsplit
        from atlantctl import AdminError
        panel=self.run_command('panelsettings',False)['settings']
        self.write(self.text('panel_certificates')+': '+self.scalar(urlsplit(panel.get('origin','')).hostname)+' · '+self.scalar(panel.get('tls',{}).get('mode','manual')))
        try:
            subscription=self.run_command('tls',False)
            self.write(self.text('subscription_certificates')+': '+self.scalar(urlsplit(subscription.get('public_url','')).hostname)+' · '+self.scalar(subscription.get('tls',{}).get('mode','manual')))
        except AdminError:self.write(self.text('certificate_subscription_status_unavailable'))
        self.certificate_list()

    def certificate_list(self):
        result=self.run_command('certjobs',False)
        if not result['jobs']:self.write(self.text('empty'))
        for job in result['jobs']:
            self.write(self.scalar(job['tls']['host']))
            self.describe({'mode':job['tls']['mode'],'status':job['status']},1)

    def certificate_patch(self, mode, previous=None):
        import ipaddress
        import re
        previous=previous or {}
        listener=None
        if mode=='acme-ip':
            from atlantctl import AdminError, public_ip
            host=public_ip(previous.get('host',''))
            if not host:raise AdminError('certificate_ip_unavailable')
            self.write(self.text('certificate_detected_ip')+': '+self.scalar(host))
            current=previous.get('challenge_listen',':80')
            port=self.ask('certificate_check_port',current.rsplit(':',1)[-1])
            if not port.isascii() or not port.isdigit() or not 1<=int(port)<=65535:raise ValueError()
            listener=':80' if int(port)==80 else '127.0.0.1:'+str(int(port))
            if int(port)!=80:self.write(self.text('challenge_proxy_notice'))
        elif mode=='acme-domain':
            host=self.ask('domain',previous.get('host','')).strip().rstrip('.').encode('idna').decode('ascii').lower()
            try:ipaddress.ip_address(host)
            except ValueError:pass
            else:raise ValueError()
            if len(host)>253 or '.' not in host or not all(re.fullmatch(r'(?!-)[a-z0-9-]{1,63}(?<!-)',label) for label in host.split('.')):raise ValueError()
        else:raise ValueError()
        self.write('https://letsencrypt.org/repository/')
        if self.read(self.text('accept_terms')+' (yes/no): ').strip()!='yes':
            self.write(self.text('cancelled'));return None
        result={'mode':mode,'host':host,'email':previous.get('email',''),'staging':False,'accept_terms':True}
        if listener is not None:result['challenge_listen']=listener
        return result

    def create_certificate(self, mode):
        current=self.run_command('certjobs',False)
        defaults=current.get('defaults') or {}
        import secrets
        identifier=defaults.get('id') or 'https-'+secrets.token_hex(6)
        host=(defaults.get('ip') if mode=='acme-ip' else defaults.get('domain')) or defaults.get('host','')
        values=self.certificate_patch(mode,{'host':host,'email':defaults.get('email',''),'challenge_listen':current.get('challenge_listen',':80')})
        if values:
            if any(job['tls']['host']==values['host'] and job['tls']['mode']==mode for job in current['jobs']):
                self.write(self.text('certificate_host_exists'));return
            if values.get('challenge_listen',current.get('challenge_listen'))!=current.get('challenge_listen') and current['jobs']:
                self.write(self.text('certificate_listener_shared'))
            values['revision']=current['revision']
            self.run_command('certjobcreate '+identifier+' '+json.dumps(values))

    def selected_certificate(self):
        current=self.run_command('certjobs',False)
        if not current['jobs']:self.write(self.text('empty'));return None
        selected=self.choose('certificates',[(self.scalar(job['tls']['host'])+' · '+self.scalar(job['tls']['mode']),job) for job in current['jobs']])
        return (selected,current['revision']) if selected else None

    def edit_certificate(self):
        selected=self.selected_certificate()
        if selected is None:return
        job,revision=selected
        current=self.run_command('certjobs',False)
        values=self.certificate_patch(job['tls']['mode'],dict(job['tls'],challenge_listen=current.get('challenge_listen',':80')))
        if values is not None:
            values['revision']=revision
            self.run_command('certjobset '+job['id']+' '+json.dumps(values))

    def delete_certificate(self):
        selected=self.selected_certificate()
        if selected is None:return
        job,revision=selected
        self.run_command('certjobdelete '+job['id']+' '+revision)

    def certificate_backups(self):
        self.write(self.text('certificate_backup_notice'))
        self.run_command('certbackups')
        name=self.ask('name','')
        if not name:return
        current=self.run_command('certjobs',False)
        self.run_command('certrestore '+shlex.quote(name)+' '+current['revision'])

    def panel_settings(self):
        data=self.run_command('panelsettings',False);current=data['settings']
        self.write(self.text('panel_saved_notice'))
        mode=self.choose('mode',[('tls_manual','manual'),('tls_agent','agent'),('loopback_http','loopback-http')])
        if mode is None:return
        if mode is False:raise ValueError()
        patch={'listen':self.ask('listen',current['listen']),'port':int(self.ask('port',str(current['port']))),
               'origin':self.ask('public_url',current['origin']),'mode':mode,'revision':data['revision']}
        if mode=='manual':
            patch['cert_file']=self.ask('cert_file',current.get('tls',{}).get('cert_file',current.get('cert_file','')))
            patch['key_file']=self.ask('key_file',current.get('tls',{}).get('key_file',current.get('key_file','')))
        if mode=='agent':
            self.certificate_list();patch['job_id']=self.ask('certificate_job_id')
        self.run_command('panelset '+json.dumps(patch))

    def panel_backups(self):
        while True:
            action=self.choose('panel_backups',[('create',lambda:self.run_command('panelbackup')),('restore',self.restore_panel_backup)])
            if action is None:return
            if action:self.guarded(action)

    def restore_panel_backup(self):
        self.run_command('panelbackups')
        name=self.ask('name','')
        if name:
            current=self.run_command('panelsettings',False)
            self.run_command('panelrestore '+shlex.quote(name)+' '+current['revision'])

    def services(self,command='service'):
        while True:
            action=self.choose('certificate_service' if command=='certservice' else 'service',[(key,lambda op=op:self.run_command(command+' '+op)) for key,op in [('status','status'),('start_service','start'),('stop','stop'),('restart','restart')]])
            if action is None:return
            if action:self.guarded(action)

    def backups(self):
        while True:
            action=self.choose('backups',[('refresh',lambda:self.run_command('backups')),('create',lambda:self.run_command('backup')),('restore',lambda:self.run_command('restore '+shlex.quote(self.ask('name'))))])
            if action is None:return
            if action:self.guarded(action)

    def languages(self):
        value=self.read('1. English · 2. Русский · 3. 简体中文\n> ').strip()
        if value not in {'1','2','3'}:raise ValueError()
        from atlantctl import private_write
        selected=('en','ru','zh')[int(value)-1]
        private_write(self.manager.state/'console-preferences.json',{'language':selected})
        self.lang=selected
        self.manager.language=self.lang
