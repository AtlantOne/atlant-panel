import tempfile
import unittest

from atlant_control_demo import DemoAPI, demo_credentials
from control.security import verify_password
from pathlib import Path
from atlantctl import AdminError, Manager


class DemoFlowTests(unittest.TestCase):
    def test_subscription_migration_preserves_demo_usage_and_requires_current_plan(self):
        plan=self.manager.execute(self.manager.prepare('submigration'))
        self.assertTrue(plan['items'][0]['eligible'])
        before=dict(self.api.subscriptions[0]['global_quota'])
        command='submigrate '+plan['revision']+' '+plan['items'][0]['id']
        self.manager.execute(self.manager.prepare(command))
        record=self.api.subscriptions[0]
        self.assertTrue(record['managed'])
        self.assertEqual(before,record['global_quota'])
        self.assertEqual([],record['nodes'])
        self.assertEqual('default',record['inbound_refs'][0]['inbound_id'])
        with self.assertRaises(AdminError):self.manager.execute(self.manager.prepare(command))

    def test_subscriber_actions_resolve_internal_account_and_do_not_expose_keys(self):
        import json
        created=self.manager.execute(self.manager.prepare('subscribercreate '+json.dumps({'title':'Client','inbound_refs':[{'server_id':'d'*32,'inbound_id':'default'}],'ip_limit':2,'note':'Personal'})))
        record=self.api.subscriptions[-1]
        for command,path in [('subkick','/api/user/kick'),('subrekey','/api/user/regenerate-key')]:
            action=self.manager.prepare(command+' '+record['id'])
            self.assertEqual(path,action['path'])
            self.assertEqual(record['user'],action['query']['name'])
            result=self.manager.execute(action)
            self.assertNotIn('pbk',json.dumps(result))
        self.assertTrue(result['result']['refresh_subscription'])
        with self.assertRaises(AdminError):self.manager.prepare('subkick '+self.api.subscriptions[0]['id'])

    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.api=DemoAPI()
        self.manager=Manager({'state_dir':self.temp.name},api=self.api)

    def test_edit_preserves_unmentioned_values(self):
        user=self.api.users['demo'].copy()
        self.manager.execute(self.manager.prepare('set demo {"note":"updated","total_limit":107374182,"ip_limit":3}'))
        self.assertEqual(107374182,self.api.users['demo']['total_limit'])
        self.assertEqual(user['expires_at'],self.api.users['demo']['expires_at'])
        self.assertEqual('updated',self.api.users['demo']['note'])

    def test_subscriber_creation_needs_no_preexisting_user(self):
        import json
        before=len(self.api.users)
        payload={'title':'New subscriber','total_limit':107374182,'inbound_refs':[{'server_id':'d'*32,'inbound_id':'default'}]}
        action=self.manager.prepare('subscribercreate '+json.dumps(payload))
        self.assertTrue(action['secret'])
        self.assertNotIn('user',action['body'])
        result=self.manager.execute(action)['result']
        self.assertEqual(before+1,len(self.api.users))
        self.assertTrue(result['subscription']['managed'])
        self.assertEqual(107374182,result['subscription']['global_quota']['total_limit'])

    def test_inbound_catalog_uses_shared_readonly_command(self):
        action = self.manager.prepare('inbounds')
        self.assertFalse(action['write'])
        result = self.manager.execute(action)
        catalog = result.get('result', result)
        self.assertEqual(1, catalog['revision'])
        self.assertEqual(['tcp', 'xhttp', 'quic'], catalog['inbounds'][0]['settings']['transports'])
        self.assertNotIn('private_key', str(catalog))
        catalog['inbounds'].clear()
        self.assertEqual(1, len(self.api.request('GET', '/api/inbounds')['inbounds']))

    def test_inbound_edit_then_explicit_apply_preserves_key(self):
        catalog=self.manager.execute(self.manager.prepare('inbounds'))
        settings=dict(catalog['inbounds'][0]['settings'],sni='changed.example.com')
        import json
        self.manager.execute(self.manager.prepare('inboundset 1 '+json.dumps(settings)))
        saved=self.manager.execute(self.manager.prepare('inbounds'))
        self.assertEqual(2,saved['revision'])
        self.assertEqual(1,saved['applied_revision'])
        self.assertEqual(catalog['inbounds'][0]['server_pub_key'],saved['inbounds'][0]['server_pub_key'])
        self.manager.execute(self.manager.prepare('inboundapply 2'))
        self.assertEqual(2,self.manager.execute(self.manager.prepare('inbounds'))['applied_revision'])

    def test_attach_changes_both_membership_and_exported_profile(self):
        command='subattach '+('a'*32)+' demo 1'
        for _ in range(2):self.manager.execute(self.manager.prepare(command))
        self.assertEqual('a'*32,self.api.users['demo']['subscription_id'])
        self.assertEqual(2,len(self.api.subscriptions[0]['nodes']))
        self.assertEqual('demo',self.api.subscriptions[0]['nodes'][1]['user'])
        self.assertEqual(2,len(self.api.request('GET','/api/quota/bindings')))

    def test_attachment_rejects_invalid_endpoint(self):
        with self.assertRaises(AdminError):
            self.manager.execute(self.manager.prepare('subattach '+('a'*32)+' demo 99'))
        self.assertNotIn('subscription_id',self.api.users['demo'])

    def test_persistent_preview_credentials_are_reused_without_plaintext_storage(self):
        record,password=demo_credentials(self.temp.name)
        self.assertTrue(verify_password(record,password))
        self.assertNotIn(password,(Path(self.temp.name)/'credentials.json').read_text())
        reused,shown=demo_credentials(self.temp.name)
        self.assertEqual(record,reused)
        self.assertIsNone(shown)


if __name__=='__main__':unittest.main()
