"""Pairing lifecycle, persistent replay defense and actual TLS panel traffic."""
import concurrent.futures
import json
import os
from pathlib import Path
import secrets
import ssl
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

from atlantctl import Manager
from control.peers import PeerError, PeerHTTP, Peers, digest
from control.server import PanelServer
from control.security import password_record
from control.i18n import LANGUAGES, message
from control.console import Console
from test_control_tls import certificate_pairs


class PairingTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.now=[2000000000]
        self.a=Peers(self.root/'a',lambda:'https://a.example',clock=lambda:self.now[0])
        self.b=Peers(self.root/'b',lambda:'https://b.example',clock=lambda:self.now[0])

    def route(self,url,path,data):
        target=self.a if url=='https://a.example' else self.b
        if path=='/peer/claim':return target.claim(data)
        if path=='/peer/result':return target.result(data)
        return target.receive(data,lambda operation:{'operation':operation},getattr(self,'write',None))

    def connect(self):
        self.a.http.request=self.route;self.b.http.request=self.route
        claim=self.b.join(self.a.invite()['link'])['claim']
        self.a.approve(claim);self.b.finish(claim)
        return self.a.info()['panel_id'],self.b.info()['panel_id']

    def test_manual_approval_then_scoped_catalog_and_no_key_disclosure(self):
        self.b.http.request=self.route;self.a.http.request=self.route
        invitation=self.a.invite();parsed=self.a.parse_invite(invitation['link'])
        claim=self.b.join(invitation['link'])['claim']
        self.assertTrue(self.b.finish(claim)['pending'])
        self.assertEqual([],self.b.info()['peers'])
        self.a.approve(claim);self.b.finish(claim)
        primary=self.a.info()['panel_id'];follower=self.b.info()['panel_id']
        self.assertEqual({'operation':'inbounds','peer_inbounds_write':False},self.a.call(follower,'inbounds'))
        with self.assertRaises(PeerError):self.b.call(primary,'inbounds')
        with self.assertRaises(PeerError):self.a.call(follower,'config')
        with self.a.db() as db:
            self.assertEqual(digest(parsed['secret']),db.execute('SELECT hash FROM invites').fetchone()[0])
            keys=db.execute('SELECT in_key,out_key FROM peers').fetchone()
        public=json.dumps([self.a.info(),self.b.info()])
        for value in [parsed['secret'],*keys]:self.assertNotIn(value,public)

    def test_single_use_claim_is_atomic_and_retry_is_idempotent(self):
        invitation=self.a.parse_invite(self.a.invite()['link'])
        data={'invite':invitation['invite'],'secret':invitation['secret'],'panel':invitation['panel'],'candidate':secrets.token_hex(16),'origin':'https://b.example','claim':secrets.token_hex(16),'auth':secrets.token_hex(32)}
        other=dict(data,claim=secrets.token_hex(16))
        def claim(value):
            try:return self.a.claim(value)
            except PeerError:return None
        with concurrent.futures.ThreadPoolExecutor(2) as pool:results=list(pool.map(claim,[data,other]))
        self.assertEqual(1,sum(result is not None for result in results))
        winner=data if results[0] else other
        self.assertEqual(next(result for result in results if result),self.a.claim(winner))

    def test_replay_is_rejected_after_store_restart(self):
        primary,follower=self.connect();captured=[]
        def capture(url,path,data):
            captured.append(dict(data));return self.route(url,path,data)
        self.a.http.request=capture
        self.a.call(follower,'status')
        restarted=Peers(self.root/'b',lambda:'https://b.example',clock=lambda:self.now[0])
        with self.assertRaisesRegex(PeerError,'peer_used'):restarted.receive(captured[0],Mock())
        for change in [{'timestamp':self.now[0]-61},{'signature':'0'*64},{'recipient':'0'*32}]:
            with self.assertRaises(PeerError):restarted.receive(dict(captured[0],**change),Mock())

    def test_expired_rejected_and_cancelled_pairings_do_not_connect(self):
        self.b.http.request=self.route
        claim=self.b.join(self.a.invite()['link'])['claim']
        self.a.reject(claim)
        with self.assertRaises(PeerError):self.b.finish(claim)
        claim=self.b.join(self.a.invite()['link'])['claim'];self.b.cancel(claim)
        with self.assertRaises(PeerError):self.b.finish(claim)
        invitation=self.a.invite()['link'];self.now[0]+=301
        with self.assertRaises(PeerError):self.b.join(invitation)

    def test_revoke_both_sides_and_offline_warning(self):
        primary,follower=self.connect()
        self.assertTrue(self.a.revoke(follower)['remote_notified'])
        for store,remote in [(self.a,follower),(self.b,primary)]:
            with self.assertRaises(PeerError):store.peer(remote)
        primary,follower=self.connect()
        self.a.http.request=Mock(side_effect=PeerError('peer_unavailable'))
        self.assertFalse(self.a.revoke(follower)['remote_notified'])
        restarted=Peers(self.root/'a',lambda:'https://a.example',clock=lambda:self.now[0])
        with self.assertRaises(PeerError):restarted.peer(follower)

    def test_old_claim_cannot_retrieve_repaired_connection_keys(self):
        self.b.http.request=self.route;self.a.http.request=self.route
        claim=self.b.join(self.a.invite()['link'])['claim']
        with self.b.db() as db:auth=db.execute('SELECT auth FROM outgoing WHERE id=?',(claim,)).fetchone()[0]
        self.a.approve(claim);self.b.finish(claim)
        old={'claim':claim,'auth':auth,'panel':self.a.info()['panel_id']}
        self.assertIn('in_key',self.a.result(old))
        self.a.revoke(self.b.info()['panel_id'])
        self.connect()
        with self.assertRaises(PeerError):self.a.result(old)

    def test_plaintext_private_addresses_and_invite_limits(self):
        self.a.live_origin='http://127.0.0.1'
        with self.assertRaisesRegex(PeerError,'peer_https_required'):self.a.invite()
        with self.assertRaisesRegex(PeerError,'peer_address_rejected'):PeerHTTP().request('https://127.0.0.1','/peer/claim',{})
        for _ in range(6):self.a.allow_attempt('1.2.3.4')
        with self.assertRaisesRegex(PeerError,'peer_limit'):self.a.allow_attempt('1.2.3.4')

    def test_cli_explains_offline_revocation_in_all_languages(self):
        for language in LANGUAGES:
            output=[];Console(Mock(),language,write=output.append).describe({'revoked':True,'remote_notified':False})
            self.assertIn(message('peer_revoked_offline',language),output)

    def test_remote_writes_require_explicit_follower_grant(self):
        primary,follower=self.connect();self.write=Mock(return_value={'ok':True,'result':{'revision':2}})
        denied=self.a.admin(follower,'inboundapply 1')
        self.assertTrue(denied['uncertain']);self.write.assert_not_called()
        self.b.grant(primary,True)
        self.assertTrue(self.a.call(follower,'inbounds')['peer_inbounds_write'])
        result=self.a.retry(follower,denied['request_id'])
        self.assertTrue(result['ok']);self.write.assert_called_once_with(primary,'inboundapply 1')
        self.assertEqual(result,self.a.retry(follower,denied['request_id']));self.assertEqual(1,self.write.call_count)
        self.b.grant(primary,False)
        self.assertTrue(self.a.admin(follower,'inboundapply 2')['uncertain']);self.assertEqual(1,self.write.call_count)
        with self.assertRaises(PeerError):self.a.grant(follower,True)
        for command in ['config','service stop','subscribercreate {}','inboundset@alias 1 {}']:
            with self.assertRaises(PeerError):self.a.admin(follower,command)

    def test_lost_response_does_not_duplicate_remote_write(self):
        primary,follower=self.connect();self.b.grant(primary,True)
        self.write=Mock(return_value={'ok':True,'result':{'revision':2}})
        def lose_response(url,path,data):
            self.route(url,path,data)
            raise PeerError('peer_unavailable')
        self.a.http.request=lose_response
        result=self.a.admin(follower,'inboundapply 1');self.assertTrue(result['uncertain'])
        self.a.http.request=self.route
        restarted=Peers(self.root/'a',lambda:'https://a.example',clock=lambda:self.now[0]);restarted.http.request=self.route
        self.assertTrue(restarted.retry(follower,result['request_id'])['ok']);self.assertEqual(1,self.write.call_count)

    def test_crash_during_write_remains_uncertain_after_restart(self):
        primary,follower=self.connect();self.b.grant(primary,True)
        self.write=Mock(side_effect=RuntimeError('crash after core commit'))
        with self.assertRaises(RuntimeError):self.a.admin(follower,'inboundapply 1')
        request=self.a.jobs(follower)['jobs'][0]['id']
        self.b=Peers(self.root/'b',lambda:'https://b.example',clock=lambda:self.now[0])
        self.write=Mock(return_value={'ok':True})
        self.assertTrue(self.a.retry(follower,request)['uncertain']);self.write.assert_not_called()

    def test_request_id_payload_is_immutable_and_expires(self):
        primary,follower=self.connect();self.b.grant(primary,True);captured=[]
        self.write=Mock(return_value={'ok':True})
        def capture(url,path,data):
            captured.append(dict(data));return self.route(url,path,data)
        self.a.http.request=capture;self.a.admin(follower,'inboundapply 1')
        data=captured[-1];data.update(command='inboundapply 2',nonce=secrets.token_hex(16));data.pop('signature')
        peer,_=self.a.peer(follower);data['signature']=self.a.signature(peer['out_key'],data)
        with self.assertRaises(PeerError):self.b.receive(data,Mock(),self.write)
        self.assertEqual(1,self.write.call_count)
        self.now[0]+=86401;data.update(timestamp=self.now[0],nonce=secrets.token_hex(16));data.pop('signature');data['signature']=self.a.signature(peer['out_key'],data)
        with self.assertRaises(PeerError):self.b.receive(data,Mock(),self.write)

    def test_repair_does_not_inherit_old_write_grant(self):
        primary,follower=self.connect();self.b.grant(primary,True)
        self.a.revoke(follower);primary,follower=self.connect()
        self.write=Mock(return_value={'ok':True})
        self.assertFalse(self.a.call(follower,'inbounds')['peer_inbounds_write'])
        self.assertTrue(self.a.admin(follower,'inboundapply 1')['uncertain']);self.write.assert_not_called()

    def test_concurrent_delivery_executes_one_write(self):
        primary,follower=self.connect();self.b.grant(primary,True)
        entered=threading.Event();release=threading.Event()
        def write(*args):
            entered.set()
            if not release.wait(5):raise RuntimeError('test synchronization failed')
            return {'ok':True}
        self.write=Mock(side_effect=write)
        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            first=pool.submit(self.a.admin,follower,'inboundapply 1')
            self.assertTrue(entered.wait(5))
            try:
                request=self.a.jobs(follower)['jobs'][0]['id']
                second=pool.submit(self.a.retry,follower,request)
                self.assertTrue(second.result(timeout=5)['uncertain'])
            finally:release.set()
            self.assertTrue(first.result(timeout=5)['ok'])
        self.assertEqual(1,self.write.call_count)

    def test_catalog_sync_uses_applied_snapshot_after_confirmation(self):
        api=Mock();api.request.return_value={'users':{}}
        manager=Manager({'state_dir':str(self.root/'manager')},api=api)
        remote='c'*32
        snapshot={'server_id':'d'*32,'revision':8,'inbounds':[]}
        manager.peers.call=Mock(return_value=snapshot)
        action=manager.prepare('peersync '+remote)
        self.assertTrue(action['write']);manager.peers.call.assert_not_called();api.request.assert_not_called()
        manager.execute(action)
        manager.peers.call.assert_called_once_with(remote,'appliedinbounds')
        api.request.assert_any_call('POST','/api/control/catalogs',dict(snapshot,peer_id=remote))


class PairingTLSTests(unittest.TestCase):
    def test_two_real_https_panels_pair_catalog_and_revoke(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);pairs=certificate_pairs()
            trust=root/'trust.pem';trust.write_text(pairs['first']['certificate']+pairs['second']['certificate'])
            servers=[];threads=[];managers=[]
            try:
                for index,fixture in enumerate(['first','second']):
                    certificate=root/(fixture+'.pem');key=root/(fixture+'.key')
                    certificate.write_text(pairs[fixture]['certificate']);key.write_text(pairs[fixture]['key']);key.chmod(0o600)
                    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(certificate,key)
                    api=Mock();api.request.return_value={'items':[],'test_panel':index,'users':{}}
                    manager=Manager({'state_dir':str(root/fixture),'peer_ca_file':str(trust),'peer_allow_private_networks':True},api=api)
                    server=PanelServer(('127.0.0.1',0),'https://127.0.0.1:0',manager,password_record('only-local-test-password'),context)
                    server.origin='https://127.0.0.1:'+str(server.server_port);server.authority='127.0.0.1:'+str(server.server_port)
                    servers.append(server);managers.append(manager)
                    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start();threads.append(thread)
                a,b=[manager.peers for manager in managers]
                claim=b.join(a.invite()['link'])['claim']
                self.assertTrue(b.finish(claim)['pending'])
                a.approve(claim);self.assertTrue(b.finish(claim)['connected'])
                follower=b.info()['panel_id']
                self.assertEqual(1,a.call(follower,'inbounds')['test_panel'])
                primary=a.info()['panel_id'];b.grant(primary,True)
                response=managers[0].execute(managers[0].prepare('peerexecute '+follower+" 'inboundapply 1'"))
                self.assertTrue(response['result']['ok'])
                managers[1].api.request.assert_any_call('POST','/api/inbounds/apply',{'revision':1},{})
                self.assertFalse(list((root/'second'/'backups').glob('backup-*.json')))
                self.assertIn('peer '+primary+' inboundapply',(root/'second'/'audit.jsonl').read_text())
                with self.assertRaises(PeerError):b.call(a.info()['panel_id'],'inbounds')
                with self.assertRaises(PeerError):PeerHTTP(allow_private=True).request(servers[0].origin,'/peer/result',{})
                self.assertTrue(a.revoke(follower)['remote_notified'])
                self.assertEqual('revoked',b.info()['peers'][0]['state'])
            finally:
                for server in servers:server.shutdown();server.server_close()
                for thread in threads:thread.join(timeout=3)


@unittest.skipUnless(os.environ.get('ATLANT_PEER_TEST_CORE'),'requires isolated Go core test harness')
class PairingCoreTests(unittest.TestCase):
    def test_remote_native_inbound_lifecycle_and_stale_revision(self):
        config=json.loads(os.environ['ATLANT_PEER_TEST_CORE'])
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);pairs=certificate_pairs();servers=[];threads=[];managers=[]
            trust=root/'trust.pem';trust.write_text(pairs['first']['certificate']+pairs['second']['certificate'])
            try:
                for name in ('first','second'):
                    cert=root/(name+'.pem');key=root/(name+'.key')
                    cert.write_text(pairs[name]['certificate']);key.write_text(pairs[name]['key']);key.chmod(0o600)
                    tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);tls.load_cert_chain(cert,key)
                    manager=Manager(dict(config,state_dir=str(root/name),peer_ca_file=str(trust),peer_allow_private_networks=True))
                    server=PanelServer(('127.0.0.1',0),'https://127.0.0.1:0',manager,password_record('local-core-acceptance-password'),tls)
                    server.origin='https://127.0.0.1:'+str(server.server_port);server.authority='127.0.0.1:'+str(server.server_port)
                    servers.append(server);managers.append(manager)
                    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start();threads.append(thread)
                a,b=[manager.peers for manager in managers]
                claim=b.join(a.invite()['link'])['claim'];a.approve(claim);b.finish(claim)
                primary=a.info()['panel_id'];remote=b.info()['panel_id'];b.grant(primary,True)
                def execute(command):
                    action=managers[0].prepare('peerexecute '+remote+' '+__import__('shlex').quote(command))
                    return managers[0].execute(action)['result']
                catalog=a.call(remote,'inbounds');self.assertEqual(1,catalog['revision'])
                settings={'id':'peer-test','name':'Remote acceptance','enabled':True,'listen':config['listen'],'advertise_addr':config['listen'],'sni':'localhost.','transports':['tcp'],'wire_version':7,'xhttp_path':'/api/v1/sync'}
                self.assertTrue(execute('inboundcreate 1 '+json.dumps(settings))['ok'])
                catalog=a.call(remote,'inbounds');self.assertEqual(2,catalog['revision']);self.assertNotEqual(2,catalog['applied_revision'])
                self.assertTrue(execute('inboundapply 2')['ok'])
                applied=a.call(remote,'appliedinbounds')
                self.assertEqual(2,applied['revision']);self.assertEqual('peer-test',applied['inbounds'][0]['settings']['id'])
                catalog=a.call(remote,'inbounds');self.assertEqual(2,catalog['applied_revision']);self.assertIn('peer-test',catalog['active'])
                settings['name']='Edited remotely'
                self.assertTrue(execute('inboundset 2 '+json.dumps(settings))['ok'])
                self.assertFalse(execute('inboundset 2 '+json.dumps(settings))['ok'])
                self.assertEqual(3,a.call(remote,'inbounds')['revision'])
                self.assertTrue(execute('inbounddelete 3 peer-test')['ok'])
                self.assertTrue(execute('inboundapply 4')['ok'])
                # Applying changes the saved revision only when a mutation does;
                # create and delete leave the catalog at revision four.
                catalog=a.call(remote,'inbounds');self.assertEqual([],catalog['inbounds']);self.assertEqual(4,catalog['applied_revision'])
                self.assertFalse(list((root/'second'/'backups').glob('backup-*.json')))
            finally:
                for server in servers:server.shutdown();server.server_close()
                for thread in threads:thread.join(timeout=3)


if __name__=='__main__':unittest.main()
