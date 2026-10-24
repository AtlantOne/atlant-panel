import json
import io
import urllib.error
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock
from atlantctl import API, AdminError, Manager, clean, private_write

SID='a'*32

class FakeAPI:
    def __init__(self):self.calls=[];self.existing=False
    def request(self,method,path,body=None,query=None):
        self.calls.append((method,path,body,query))
        if path=='/api/backup':return {'users':{'owner':{'pbk':'b'*64}}}
        if path=='/api/users':return {'users':[{'name':'alice'}] if self.existing else [],'total':int(self.existing)}
        if path=='/api/subscriptions':
            if method=='GET':return [{'id':SID,'user':'alice','title':'Test','enabled':True,'expires_at':0,'update_hours':1,'nodes':[],'token_hash':''}]
            return {'success':True}
        return {'status':'ok','pbk':'b'*64,'link':'atlant://test?pbk='+('b'*64)}

class ManagementTests(unittest.TestCase):
    def test_http_error_response_is_closed_before_returning_safe_error(self):
        client=API({'api_url':'http://127.0.0.1:12345','api_key':'local-test-only'})
        body=io.BytesIO(b'private upstream diagnostic')
        failure=urllib.error.HTTPError('http://127.0.0.1:12345/api/test',409,'conflict',{},body)
        client.opener=Mock();client.opener.open.side_effect=failure
        with self.assertRaises(AdminError) as caught:client.request('GET','/api/test')
        self.assertEqual(409,caught.exception.status_code)
        self.assertTrue(body.closed)
        self.assertNotIn('private upstream diagnostic',str(caught.exception))
    def test_quota_editor_round_trip(self):
        from atlantctl import quota_bytes, quota_input
        self.assertEqual(quota_input(107374182), '0.1')
        for value in (0, 1, 2, 107374182, 1073741823, 1073741825, 987654321, 2**53-1):
            self.assertEqual(quota_bytes(quota_input(value)), value)

    def test_inbound_tuning_validation_rejects_ignored_or_conflicting_values(self):
        from atlantctl import validate_inbound_tuning
        validate_inbound_tuning({'quic':{'stream_receive_window_mb':12,'conn_receive_window_mb':48},'yamux':{'max_stream_window_kb':4096}})
        for settings in ({'quic':[]}, {'quic':{'unknown':1}}, {'quic':{'disable_pacer':1}},
                         {'quic':{'stream_receive_window_mb':True}}, {'quic':{'max_idle_timeout_sec':5}},
                         {'quic':{'stream_receive_window_mb':256}}, {'yamux':{'max_stream_window_kb':255}},
                         {'yamux':{'write_timeout_sec':3601}}):
            with self.subTest(settings=settings),self.assertRaises(AdminError): validate_inbound_tuning(settings)

    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.api=FakeAPI();self.manager=Manager({'state_dir':self.tmp.name},api=self.api)

    def test_api_rejects_remote_and_credentials(self):
        for url in ['http://example.com:8080','https://127.0.0.1','http://x:y@127.0.0.1','http://127.0.0.1/path','http://127.0.0.1?secret=x']:
            with self.subTest(url=url),self.assertRaises(AdminError):API({'api_url':url,'api_key':'secret'})

    def test_loopback_ipv6_supported(self):
        API({'api_url':'http://[::1]:8080','api_key':'secret'})

    def test_prepare_does_not_mutate(self):
        for command in ['delete alice','rekey alice','set alice {"total_limit":0}','bulk disable alice bob']:
            self.assertTrue(self.manager.prepare(command)['write'])
        self.assertFalse(any(method!='GET' for method,*_ in self.api.calls))

    def test_inbound_commands_bind_revision_and_disallow_keys(self):
        settings={'id':'first','name':'First','enabled':True,'listen':'127.0.0.1:1026','sni':'www.example.com','transports':['tcp','quic'],'wire_version':7}
        action=self.manager.prepare('inboundcreate 7 '+json.dumps(settings))
        self.assertEqual('/api/inbounds',action['path'])
        self.assertTrue(action['write'])
        self.assertEqual(7,action['body']['revision'])
        self.assertEqual('PUT',self.manager.prepare('inboundset 7 '+json.dumps(settings))['method'])
        self.assertEqual('DELETE',self.manager.prepare('inbounddelete 7 first')['method'])
        self.assertEqual('/api/inbounds/apply',self.manager.prepare('inboundapply 7')['path'])
        for command in ['inboundapply 0','inboundapply 7 extra','inbounddelete 7 ../x','inboundcreate 7 '+json.dumps(dict(settings,private_key='secret')),'inboundset 7 '+json.dumps(dict(settings,wire_version=4))]:
            with self.subTest(command=command),self.assertRaises(AdminError):self.manager.prepare(command)

    def test_deletion_does_not_create_an_automatic_backup(self):
        result=self.manager.execute(self.manager.prepare('delete alice'))
        self.assertEqual(['/api/user/delete'],[c[1] for c in self.api.calls])
        self.assertIsNone(result['safety_backup'])
        self.assertFalse((Path(self.tmp.name)/'backups').exists())
        self.assertNotIn('b'*64,json.dumps(result))

    def test_backup_failure_blocks_mutation(self):
        self.api.request=Mock(side_effect=AdminError('offline'))
        with self.assertRaises(AdminError):self.manager.execute(self.manager.prepare('delete alice'))
        self.assertEqual(1,self.api.request.call_count)

    def test_create_only_user_does_not_download_full_database(self):
        action=self.manager.prepare('usercreate {"name":"new","enabled":true}')
        result=self.manager.execute(action)
        self.assertIsNone(result['safety_backup'])
        self.assertFalse(any(path.startswith('/api/backup') for _,path,*_ in self.api.calls))
        self.assertTrue(any(path=='/api/user/create' for _,path,*_ in self.api.calls))

    def test_subscription_creation_and_ordinary_edits_do_not_download_backups(self):
        self.manager.execute(self.manager.prepare('subscribercreate {"title":"New","inbound_refs":[{"server_id":"'+SID+'","inbound_id":"default"}]}'))
        self.assertFalse(any(path.startswith('/api/backup') for _,path,*_ in self.api.calls))
        self.api.calls.clear()
        self.manager.execute(self.manager.prepare('subset '+SID+' {"title":"Updated"}'))
        self.assertFalse(any(path=='/api/backup' for _,path,*_ in self.api.calls))

    def test_backup_policy_is_explicit_for_destructive_operations(self):
        for command in ['set alice {"note":"edited"}','subset '+SID+' {"title":"New"}','groupcreate {"name":"Family","users":[]}', 'disable alice','enable alice','bulk disable alice']:
            self.assertFalse(self.manager.needs_database_backup(self.manager.prepare(command)),command)
        for command in ['delete alice','reset alice','rekey alice','bulk delete alice','bulk reset alice','subdelete '+SID,'subrotate '+SID]:
            self.assertFalse(self.manager.needs_database_backup(self.manager.prepare(command)),command)

    def test_user_list_loading_does_not_run_inside_prepare_mutation_lock(self):
        action=self.manager.prepare('usersall')
        self.assertEqual([],self.api.calls)
        self.manager.execute(action)
        self.assertEqual('/api/users',self.api.calls[0][1])

    def test_reserved_all_is_not_single_user(self):
        for command in ['reset all','kick all','add all']:
            with self.assertRaises(AdminError):self.manager.prepare(command)

    def test_existing_user_not_upserted(self):
        self.api.existing=True
        with self.assertRaises(AdminError):self.manager.prepare('add alice')
        self.assertTrue(all(c[0]=='GET' for c in self.api.calls))

    def test_quota_zero_and_expiry_explicit(self):
        a=self.manager.prepare('set alice {"total_limit":0,"expires_at":0}')
        self.assertEqual({'name':'alice','total_limit':0,'expires_at':0},a['body'])

    def test_no_nan_or_secret_fields_in_user_update(self):
        for text in ['set alice {"total_limit":NaN}','set alice {"pbk":"abc"}','set alice []','set alice {"name":"bob"}']:
            with self.assertRaises(AdminError):self.manager.prepare(text)

    def test_sub_update_preserves_nodes(self):
        a=self.manager.prepare('subset '+SID+' {"title":"New"}')
        self.assertEqual('PUT',a['method']);self.assertEqual([],a['body']['nodes'])
        self.assertNotIn('token_hash',a['body']);self.assertNotIn('rotate',a['body'])

    def test_endpoint_edit_preserves_credentials_and_revision_without_disclosing_them(self):
        secret='d'*64
        original={'id':SID,'user':'alice','revision':'e'*64,'title':'Test','enabled':True,'expires_at':0,'update_hours':1,
                  'nodes':[{'name':'Remote','server':'192.0.2.1:443','sni':'example.com','server_pub_key':'c'*64,'user':'remote','pbk':secret,'wire_version':7,'transport':'reality'}]}
        def request(method,path,body=None,query=None):
            if path=='/api/subscriptions':return [original]
            return {}
        self.api.request=request
        visible=self.manager.execute(self.manager.prepare('sub '+SID))
        self.assertNotIn(secret,json.dumps(visible))
        action=self.manager.prepare('nodeset '+SID+' 1 {"name":"Renamed"}')
        self.assertEqual(secret,action['body']['nodes'][0]['pbk'])
        self.assertEqual('Renamed',action['body']['nodes'][0]['name'])
        self.assertEqual('e'*64,action['body']['revision'])
        self.assertEqual('Remote',original['nodes'][0]['name'])
        stale=self.manager.prepare('nodeset '+SID+' 1 {"name":"Changed","revision":"'+('f'*64)+'"}')
        self.assertEqual('f'*64,stale['body']['revision'])
        self.assertNotIn('revision',stale['body']['nodes'][0])
        self.assertEqual('f'*64,self.manager.prepare('nodedel '+SID+' 1 '+('f'*64))['body']['revision'])
        cleared=self.manager.prepare('nodeset '+SID+' 1 {"pbk":""}')
        self.assertEqual('',cleared['body']['nodes'][0]['pbk'])
        for patch in ['{}','{"private_key":"bad"}']:
            with self.assertRaises(AdminError):self.manager.prepare('nodeset '+SID+' 1 '+patch)
        with self.assertRaises(AdminError):self.manager.prepare('nodeset '+SID+' 2 {"name":"Missing"}')

    def test_group_editor_revision_is_not_silently_replaced_by_fresh_read(self):
        self.api.request=Mock(return_value=[{'id':SID,'name':'Team','note':'','revision':4,'users':[]}])
        action=self.manager.prepare('groupset '+SID+' {"name":"Old editor","revision":2}')
        self.assertEqual(2,action['body']['revision'])

    def test_sub_rotation_explicit(self):
        a=self.manager.prepare('subrotate '+SID)
        self.assertTrue(a['body']['rotate']);self.assertTrue(a['secret'])

    def test_subscription_quota_is_shared_and_fractional(self):
        action=self.manager.prepare('subquota '+SID+' 0,1')
        self.assertEqual('/api/subscriptions',action['path'])
        self.assertEqual('PUT',action['method'])
        self.assertEqual(107374182,action['body']['total_limit'])
        self.assertEqual([],action['body']['nodes'])

    def test_quota_node_credentials_are_separate_and_secret(self):
        action=self.manager.prepare('quotaenroll vds-2 '+SID)
        self.assertTrue(action['secret'])
        self.assertEqual('/api/quota/nodes',action['path'])
        self.assertEqual([SID],action['body']['subscriptions'])
        self.assertEqual({'user':'alice','subscription':SID},self.manager.prepare('quotabind alice '+SID)['body'])
        with self.assertRaises(AdminError): self.manager.prepare('quotaenroll local '+SID)

    def test_quota_scope_edit_keeps_credentials_and_uses_put(self):
        self.api.request=Mock(return_value=[{'id':'vds-2','enabled':True,'subscriptions':[SID]}])
        action=self.manager.prepare('quotaset vds-2 {"enabled":false}')
        self.assertEqual('PUT',action['method'])
        self.assertEqual({'id':'vds-2','enabled':False,'subscriptions':[SID]},action['body'])
        self.assertFalse(action['secret'])
        for patch in ['{"token":"new-secret"}','{"enabled":"false"}','{"subscriptions":["invalid"]}']:
            with self.assertRaises(AdminError):self.manager.prepare('quotaset vds-2 '+patch)

    def test_subscription_account_attach_is_one_atomic_request(self):
        action=self.manager.prepare('subattach '+SID+' alice 1')
        self.assertEqual('/api/subscription-account',action['path'])
        self.assertEqual({'subscription':SID,'user':'alice','node':1},action['body'])
        self.assertTrue(action['write'])
        with self.assertRaises(AdminError):self.manager.prepare('subattach '+SID+' alice 0')
        with self.assertRaises(ValueError):self.manager.prepare('subattach '+SID+' alice NaN')

    def test_public_pin_is_visible_but_account_secrets_stay_redacted(self):
        data=clean({'server_pub_key':'c'*64,'pbk':'b'*64,'api_key':'secret'})
        self.assertEqual('c'*64,data['server_pub_key'])
        self.assertNotIn('b'*64,json.dumps(data))
        self.assertNotIn('secret',json.dumps(data))

    def test_account_choices_can_load_more_than_first_page(self):
        records=[{'name':'user'+str(index)} for index in range(105)]
        def request(method,path,body=None,query=None):
            offset=query['offset'];return {'users':records[offset:offset+query['limit']]}
        self.api.request=request
        result=self.manager.execute(self.manager.prepare('usersall'))
        self.assertEqual(105,result['total'])

    def test_quota_backup_falls_back_to_full_sqlite(self):
        import base64
        conflict=AdminError('conflict');conflict.status_code=409
        snapshot={'format':'sqlite3-base64-v1','database':base64.b64encode(b'SQLite format 3\x00'+b'fixture').decode(),'recovery':'coordinated-offline-only'}
        self.api.request=Mock(side_effect=[conflict,snapshot])
        name=self.manager.backup()
        saved=json.loads((Path(self.tmp.name)/'backups'/name).read_text())
        self.assertEqual(snapshot,saved)
        self.assertEqual('/api/backup/sqlite',self.api.request.call_args[0][1])

    def test_subscription_creation_uses_public_link_not_wildcard_listener(self):
        self.api.request=Mock(side_effect=[{'advertise_addr':'','listen':':1026','sni':'example.com','server_pub_key':'c'*64},
            {'link':'atlant://192.0.2.1:1026?wire_version=4'}])
        a=self.manager.prepare('subcreate alice My VPN')
        self.assertEqual('192.0.2.1:1026',a['body']['nodes'][0]['server'])
        self.assertEqual(1,len(a['body']['nodes']))

    def test_restore_path_traversal_rejected(self):
        for path in ['../config.json','/root/config.json','backup-evil.json']:
            with self.assertRaises(AdminError):self.manager.prepare('restore '+path)

    def test_redaction(self):
        value=clean({'pbk':'secret','nested':[{'link':'atlant://secret'}], 'log':'atlant://abc '+('c'*64)})
        self.assertNotIn('secret',json.dumps(value));self.assertNotIn('c'*64,json.dumps(value))

    def test_service_start_when_api_down(self):
        self.manager.helper_call=Mock(return_value={'ActiveState':'active'})
        self.api.request=Mock(side_effect=AdminError('down'))
        result=self.manager.execute(self.manager.prepare('service start'))
        self.manager.helper_call.assert_called_once_with('start')
        self.assertIsNone(result['safety_backup'])

    def test_service_shell_command_rejected(self):
        with self.assertRaises(AdminError):self.manager.prepare('service "restart;id"')

    def test_private_write_atomic(self):
        path=Path(self.tmp.name)/'state.json'
        private_write(path,{'offset':1});private_write(path,{'offset':2})
        self.assertEqual({'offset':2},json.loads(path.read_text()))
        self.assertEqual([path],list(Path(self.tmp.name).iterdir()))

if __name__=='__main__':unittest.main()
