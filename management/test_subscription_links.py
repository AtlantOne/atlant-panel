import base64
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import Mock
from atlantctl import Manager, AdminError
from control.subscription_links import access, validated_link, verify
from control.security import Operations

SID='a'*32
TOKEN=base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip('=')
URL='https://vpn.example.test/sub/'+TOKEN
HASH=hashlib.sha256(bytes(range(32))).hexdigest()

class SubscriptionLinkTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.api=Mock()
        self.api.request.return_value=[{'id':SID}]
        self.manager=Manager({'state_dir':self.temp.name},api=self.api)

    def test_vault_survives_reopening_without_listing_secrets(self):
        self.assertEqual('',access(self.temp.name,SID))
        self.assertEqual(URL,access(self.temp.name,SID,URL))
        self.assertEqual(URL,access(self.temp.name,SID))
        if os.name=='posix':self.assertEqual(0o600,(Path(self.temp.name)/'subscription-links.db').stat().st_mode&0o777)
        operations=Operations(self.manager)
        with self.assertRaises(PermissionError):operations.prepare('test','subshare '+SID)
        self.assertEqual(URL,operations.prepare('test','subshare '+SID,True)['result']['url'])

    def test_import_matches_real_token_and_subscription(self):
        self.api.request.return_value={'subscriptions':[{'id':SID,'token_hash':HASH}]}
        verify(self.api,SID,URL)
        with self.assertRaises(ValueError):verify(self.api,'b'*32,URL)
        with self.assertRaises(ValueError):verify(self.api,SID,URL[:-1]+'A')

    def test_import_through_confirmed_manager_flow_never_rotates_or_logs_url(self):
        def request(method,path,body=None,query=None):
            self.assertEqual('GET',method)
            return [{'id':SID}] if path=='/api/subscriptions' else {'subscriptions':[{'id':SID,'token_hash':HASH}]}
        self.api.request.side_effect=request
        operations=Operations(self.manager)
        prepared=operations.prepare('session',f'subshareimport {SID} {URL}',True)
        result=operations.commit('session',prepared['confirmation'])
        self.assertEqual(URL,result['result']['result']['url'])
        self.assertEqual(URL,operations.prepare('session','subshare '+SID,True)['result']['url'])
        self.assertNotIn(TOKEN,(Path(self.temp.name)/'audit.jsonl').read_text())

    def test_import_checks_sqlite_snapshot_without_creating_disk_database(self):
        db=sqlite3.connect(':memory:')
        try:
            db.execute('CREATE TABLE subscriptions(id TEXT,token_hash TEXT)')
            db.execute('INSERT INTO subscriptions VALUES(?,?)',(SID,HASH));db.commit()
            snapshot={'format':'sqlite3-base64-v1','database':base64.b64encode(db.serialize()).decode()}
        finally:db.close()
        conflict=AdminError('conflict');conflict.status_code=409
        self.api.request.side_effect=[conflict,snapshot]
        verify(self.api,SID,URL)

    def test_no_secret_is_written_to_audit_and_rotation_response_is_saved(self):
        self.api.request.return_value={'subscription':{'id':SID},'url':URL}
        action={'local':'result','result':{'subscription':{'id':SID},'url':URL},'label':'subrotate '+SID,'secret':True,'write':False}
        self.manager.execute(action)
        self.assertEqual(URL,access(self.temp.name,SID))
        self.assertFalse((Path(self.temp.name)/'audit.jsonl').exists())

    def test_invalid_or_external_fetch_schemes_rejected(self):
        for url in ['http://vpn.example.test/sub/'+TOKEN,'javascript:alert(1)','https://user:pass@host/sub/'+TOKEN,URL+'?x=1',URL+'#x',URL+'\n','https://vpn.example.test/sub/short']:
            with self.subTest(url=url),self.assertRaises(ValueError):validated_link(url)
        self.assertEqual(URL,validated_link(URL))
