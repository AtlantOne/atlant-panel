"""Local, disposable panel preview. Never connects to a real VPN server."""
import argparse
import copy
from contextlib import nullcontext
import hashlib
import json
import os
from pathlib import Path
import secrets
import tempfile
import time

from atlantctl import AdminError, Manager, load_config, private_write
from control.security import password_record
from control.server import PanelServer


class DemoAPI:
    def __init__(self):
        self.groups = []
        self.quota_nodes = []
        self.users = {
            'demo': {'name': 'demo', 'enabled': True, 'total_limit': 10737418240,
                     'up_bytes': 134217728, 'down_bytes': 1073741824, 'expires_at': 0,
                     'ip_limit': 2, 'note': 'Local demo — no real credentials'},
            'phone': {'name': 'phone', 'enabled': True, 'total_limit': 0,
                      'up_bytes': 16777216, 'down_bytes': 268435456, 'expires_at': 0,
                      'ip_limit': 0, 'subscription_id': 'a' * 32, 'note': ''},
        }
        self.subscriptions = [{'id': 'a' * 32, 'user': 'phone', 'title': 'Demo subscription',
                               'enabled': True, 'expires_at': 0, 'update_hours': 1,
                               'nodes': [{'name':'Demo VDS','server':'192.0.2.8:1026','sni':'www.example.com','server_pub_key':'a'*64,'transport':'reality','wire_version':7}], 'total_limit': 10737418240,
                               'global_quota': {'total_limit': 10737418240, 'upload': 16777216,
                                                'download': 268435456, 'reserved': 4194304}}]
        self.tls = {'enabled': False, 'listen': ':443', 'public_url': 'https://vpn.example.com',
                    'tls': {'mode': 'acme-domain', 'host': 'vpn.example.com', 'accept_terms': False},
                    'status': {'listening': False, 'demo': True}}
        self.config = {'sni': 'www.example.com', 'listen': ':1026',
                       'advertise_addr': '192.0.2.8:1026', 'up_mbps': 0, 'down_mbps': 0,
                       'server_pub_key': 'a' * 64, 'wire_version': 7, 'demo': True}
        self.inbounds = {'initialized': True, 'revision': 1, 'applied_revision': 1, 'server_id': 'd'*32,
            'active': ['default'], 'running': True, 'editable': True, 'can_apply': True,
            'inbounds': [{'settings': {'id': 'default', 'name': 'Demo VDS',
                'enabled': True, 'listen': '0.0.0.0:1026', 'advertise_addr': '192.0.2.8:1026',
                'sni': 'www.example.com', 'transports': ['tcp', 'xhttp', 'quic'],
                'wire_version': 7, 'xhttp_path': '/api/v1/sync'}, 'server_pub_key': 'a' * 64}]}

    @staticmethod
    def revision(record):
        stable={key:value for key,value in record.items() if key not in {'revision','global_quota'}}
        return hashlib.sha256(json.dumps(stable,sort_keys=True).encode()).hexdigest()

    def migration_plan(self):
        items=[];changes={}
        for sub in self.subscriptions:
            nodes=[];refs=list(sub.get('inbound_refs',[]));converted=0;ids=[]
            for node in sub.get('nodes',[]):
                matches=[record for record in self.inbounds['inbounds'] if record['settings']['enabled'] and
                         node['server']==record['settings']['advertise_addr'] and node['sni']==record['settings']['sni'] and
                         node['server_pub_key']==record['server_pub_key'] and node['wire_version']==record['settings']['wire_version'] and
                         not node.get('pbk') and node.get('user',sub['user'])==sub['user']]
                if len(matches)!=1:nodes.append(node);continue
                converted+=1;identifier=matches[0]['settings']['id']
                ref={'server_id':self.inbounds['server_id'],'inbound_id':identifier}
                if ref not in refs:refs.append(ref);ids.append(identifier)
            if not converted:continue
            shared=sum(record['user']==sub['user'] for record in self.subscriptions)>1
            items.append({'id':sub['id'],'title':sub['title'],'eligible':not shared,'converted_profiles':converted,
                          'preserved_profiles':len(nodes),'inbound_ids':ids,'blockers':['migration_shared_owner'] if shared else []})
            updated=dict(sub,nodes=nodes,inbound_refs=refs,managed=True)
            owner=self.users[sub['user']];updated.setdefault('ip_limit',owner.get('ip_limit',0));updated.setdefault('note',owner.get('note',''))
            changes[sub['id']]=updated
        revision=hashlib.sha256(json.dumps([self.subscriptions,self.inbounds],sort_keys=True).encode()).hexdigest()
        return {'revision':revision,'items':items,'demo':True},changes

    def request(self, method, path, body=None, query=None):
        # Return copies: Manager may edit records while preparing confirmation.
        return copy.deepcopy(self._request(method, path, body or {}, query or {}))

    def _request(self, method, path, body, query):
        if path == '/api/control/catalogs' and method == 'GET': return []
        if path == '/api/inbounds' and method == 'GET': return self.inbounds
        if path in {'/api/inbounds', '/api/inbounds/apply'}:
            if body.get('revision') != self.inbounds['revision']: raise AdminError('invalid')
            if path.endswith('/apply'):
                self.inbounds['applied_revision'] = self.inbounds['revision']
                self.inbounds['active'] = [record['settings']['id'] for record in self.inbounds['inbounds'] if record['settings']['enabled']]
                return {'applied': True, 'applied_revision': self.inbounds['revision'], 'demo': True}
            settings = body.get('settings', {})
            identity = body.get('id') if method == 'DELETE' else settings.get('id')
            current = next((record for record in self.inbounds['inbounds'] if record['settings']['id'] == identity), None)
            if method == 'POST' and current or method != 'POST' and not current: raise AdminError('invalid')
            if method == 'DELETE':
                if identity == 'default': raise AdminError('invalid')
                self.inbounds['inbounds'].remove(current)
            elif method == 'PUT': current['settings'] = settings
            else: self.inbounds['inbounds'].append({'settings': settings, 'server_pub_key': secrets.token_hex(32)})
            self.inbounds['revision'] += 1
            return {'revision': self.inbounds['revision'], 'applied': False, 'demo': True}
        if path == '/api/status':
            return {'demo': True, 'status': 'local preview', 'users': len(self.users),
                    'uptime_seconds': 0, 'wire_version': 7, 'active_connections': 0}
        if path == '/api/online':
            return []
        if path == '/api/users':
            records = [record for name, record in sorted(self.users.items()) if query.get('search', '') in name]
            offset, limit = int(query.get('offset', 0)), int(query.get('limit', 8))
            return {'users': records[offset:offset + limit], 'total': len(records)}
        if path == '/api/user':
            record = dict(self.users.get(query.get('name'), {}))
            if not record:
                raise AdminError('Пользователь не найден.')
            record['link'] = 'atlant://192.0.2.8:1026?sni=www.example.com&wire_version=7'
            return record
        if path == '/api/backup':
            return {'version': 1, 'users': self.users, 'subscriptions': self.subscriptions, 'inbounds': self.inbounds, 'demo': True}
        if path == '/api/subscriptions/migrate':
            plan,changes=self.migration_plan()
            if method=='GET':return plan
            ids=body.get('ids',[]);eligible={item['id'] for item in plan['items'] if item['eligible']}
            if body.get('revision')!=plan['revision'] or not ids or len(ids)!=len(set(ids)) or not set(ids)<=eligible:raise AdminError('invalid')
            self.subscriptions=[changes[sub['id']] if sub['id'] in ids else sub for sub in self.subscriptions]
            return {'success':True,'migrated':len(ids),'demo':True}
        if path == '/api/subscriptions':
            if method == 'GET':
                for record in self.subscriptions:record['revision']=self.revision(record)
                return self.subscriptions
            if method == 'POST':
                record = dict(body, id=secrets.token_hex(16))
                record.setdefault('nodes',[])
                if record.get('inbound_refs') and not record.get('user'):
                    record['user']='sub-'+record['id'];record['managed']=True
                    self.users[record['user']]={'name':record['user'],'enabled':True,'total_limit':0,'up_bytes':0,'down_bytes':0,'expires_at':0,'ip_limit':0,'subscription_id':record['id']}
                if 'total_limit' in record:record['global_quota']={'total_limit':record['total_limit'],'upload':0,'download':0,'reserved':0}
                record['revision']=self.revision(record)
                self.subscriptions.append(record)
                return {'subscription': record, 'url': 'https://vpn.example.com/sub/demo-only'}
            if method == 'PUT':
                for index, old in enumerate(self.subscriptions):
                    if old['id'] == body.get('id'):
                        if body.get('revision')!=self.revision(old):raise AdminError('Subscription changed; reload')
                        record = dict(body)
                        if 'total_limit' in record:
                            usage = dict(old.get('global_quota') or {'upload': 0, 'download': 0, 'reserved': 0})
                            usage['total_limit'] = record['total_limit']
                            record['global_quota'] = usage
                        self.subscriptions[index] = record
                        record['revision']=self.revision(record)
                        return {'subscription': record}
            if method == 'DELETE':
                self.subscriptions = [record for record in self.subscriptions if record['id'] != query.get('id')]
                return {'success': True}
        if path.startswith('/api/user/') and method in {'POST', 'PUT', 'DELETE'}:
            name = body.get('name') or query.get('name')
            operation = path.rsplit('/', 1)[1]
            if operation in {'add','create'}:
                if operation=='create' and name in self.users: raise AdminError('Пользователь уже существует; создание отменено.')
                self.users[name] = dict({'up_bytes':0,'down_bytes':0,'note':'','ip_limit':0},**body)
            elif name not in self.users:
                raise AdminError('Пользователь не найден.')
            elif operation == 'kick':
                return {'success':True,'kicked':0,'demo':True}
            elif operation == 'regenerate-key':
                return {'success':True,'demo':True}
            elif operation == 'delete':
                del self.users[name]
            elif operation == 'update':
                self.users[name].update(body)
            elif operation in {'enable', 'disable'}:
                self.users[name]['enabled'] = operation == 'enable'
            elif operation == 'reset-traffic':
                self.users[name].update(up_bytes=0, down_bytes=0)
            elif operation != 'kick':
                raise AdminError('Unsupported demo action')
            return {'success': True, 'demo': True}
        if path.startswith('/api/users/bulk-') and method=='POST':
            operation=path.rsplit('bulk-',1)[1]
            for name in body.get('names',[]):
                if name not in self.users: raise AdminError('Пользователь не найден.')
            for name in body.get('names',[]):
                if operation=='delete':del self.users[name]
                elif operation=='reset-traffic':self.users[name].update(up_bytes=0,down_bytes=0)
                elif operation in {'enable','disable'}:self.users[name]['enabled']=operation=='enable'
                else:raise AdminError('Unsupported demo action')
            return {'success':True,'demo':True}
        if path=='/api/groups':
            if method=='GET':
                result=[]
                for group in self.groups:
                    group=dict(group);group['users']=[name for name in group['users'] if name in self.users]
                    group.update(up_bytes=sum(self.users[name]['up_bytes'] for name in group['users']),down_bytes=sum(self.users[name]['down_bytes'] for name in group['users']),online_users=0)
                    result.append(group)
                return result
            if method=='POST':
                if any(group['name'].lower()==body.get('name','').lower() for group in self.groups):raise AdminError('Invalid group fields')
                group=dict(body,id=secrets.token_hex(16),revision=1);group.setdefault('users',[]);self.groups.append(group)
            else:
                group=next((group for group in self.groups if group['id']==body['id']),None)
                if not group or group['revision']!=body['revision']:raise AdminError('Group changed; reload')
                if method=='DELETE':self.groups.remove(group);return {'success':True}
                group.update(body);group['revision']+=1
            for other in self.groups:
                if other['id']!=group['id']:
                    previous=other['users'];other['users']=[name for name in previous if name not in group['users']]
                    if previous!=other['users']:other['revision']+=1
            return {'success':True,'id':group['id']}
        if path == '/api/config':
            return self.config
        if path == '/api/config/update':
            self.config.update(body)
            return {'success': True, 'demo': True}
        if path == '/api/subscription-service':
            if method != 'GET':
                self.tls = dict(body, status={'demo': True, 'listening': False})
            return self.tls
        if path == '/api/quota/nodes':
            if method=='GET':return self.quota_nodes
            existing=next((node for node in self.quota_nodes if node['id']==body.get('id')),None)
            if method=='POST':
                if existing:raise AdminError('Duplicate demo node')
                self.quota_nodes.append(dict(body))
                return {'token':secrets.token_hex(32),'demo':True}
            if existing is None:raise AdminError('Узел квот не найден.')
            if method=='DELETE':existing['enabled']=False
            else:existing.update(body)
            return {'success':True,'demo':True}
        if path == '/api/quota/bindings':
            return [{'user': name, 'subscription': user['subscription_id']} for name,user in self.users.items() if user.get('subscription_id')]
        if path == '/api/subscription-account' and method == 'POST':
            sub=next((sub for sub in self.subscriptions if sub['id']==body.get('subscription')),None)
            user=self.users.get(body.get('user'))
            index=body.get('node',0)-1
            if not sub or not user or sub.get('total_limit') is None or not 0<=index<len(sub['nodes']):
                raise AdminError('Invalid demo subscription account')
            if user.get('subscription_id') not in (None,sub['id']):
                raise AdminError('Account already belongs to another subscription')
            user['subscription_id']=sub['id']
            base=sub['nodes'][index]
            if not any(node.get('user',sub['user'])==user['name'] and node['server']==base['server'] for node in sub['nodes']):
                sub['nodes'].append(dict(base,user=user['name'],name=user['name']+' · '+base['name']))
            return {'success':True,'demo':True}
        if path == '/api/logs':
            return {'logs': ['Local demonstration only. No connection to a VDS.',
                             'Changes affect disposable preview data only.']}
        raise AdminError('Unsupported demo action')


def demo_credentials(state):
    state=Path(state)
    if state.is_symlink():raise ValueError('Linked demo state directory')
    state.mkdir(parents=True,exist_ok=True,mode=0o700)
    path=state/'credentials.json'
    if path.is_symlink():raise ValueError('Linked demo credential file')
    if path.exists():
        if os.name=='posix' and path.stat().st_mode&0o077:raise ValueError('Demo credentials require mode 0600')
        return load_config(path),None
    password=secrets.token_urlsafe(16);record=password_record(password)
    private_write(path,record)
    return record,password


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=9090)
    parser.add_argument('--state-dir',help='Private persistent preview credentials/settings; VPN data stays disposable')
    args = parser.parse_args()
    with (nullcontext(str(Path(args.state_dir).absolute())) if args.state_dir else tempfile.TemporaryDirectory(prefix='atlant-control-demo-')) as state:
        record,password=demo_credentials(state)
        manager = Manager({'state_dir': state}, api=DemoAPI())
        # Never execute systemd/service helpers from the local demonstration.
        def demo_helper(action, body=None):
            raise AdminError('Service operations are disabled in the local demo')
        manager.helper_call = demo_helper
        from control.access import entry_path, read_credentials
        prefix=entry_path(state)
        server = PanelServer(('127.0.0.1', args.port), f'http://127.0.0.1:{args.port}',
                             manager, record, demonstration=True,
                             base_path=prefix,credential_loader=lambda:read_credentials(Path(state)/'credentials.json'))
        print(json.dumps({'url': server.origin+prefix, 'username': record.get('username','admin'), 'temporary_password': password,
                          'demo': True, 'connected_to_vds': False}), flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()


if __name__ == '__main__':
    main()
