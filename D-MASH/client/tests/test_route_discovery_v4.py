import base64
import copy
import json
from pathlib import Path
import subprocess
import unittest
from nacl.exceptions import BadSignatureError, CryptoError
from nacl.public import PrivateKey
from nacl.signing import SigningKey
from backend.route_discovery_v4 import (issue_certificate,verify_certificate,create_query,
    answer_query,verify_reply,seal,open_box)

class RouteDiscoveryV4Tests(unittest.TestCase):
    def setUp(self):
        self.now=1800000000
        self.owner=SigningKey(bytes([11])*32)
        self.sign=SigningKey(bytes([12])*32)
        self.box=PrivateKey(bytes([13])*32)
        self.recipient=PrivateKey(bytes([14])*32)
        self.cert=issue_certificate(self.owner,self.sign.verify_key,self.box.public_key,self.recipient.public_key,
            generation=1,issued_at=self.now,expires_at=self.now+3600)

    def peer(self,value):
        result=subprocess.run(['node',str(Path(__file__).with_name('route_discovery_v4_peer.cjs'))],
            input=json.dumps({'now':self.now,**value}),text=True,capture_output=True,timeout=15)
        self.assertEqual(result.returncode,0,'JS discovery interoperability failed')
        return json.loads(result.stdout)

    def test_real_js_python_queries_both_directions(self):
        query,state=create_query(self.cert,now=self.now)
        reply=self.peer(dict(mode='answer',query=query,certificate=self.cert,
            sign=self.sign.encode().hex(),box=bytes(self.box).hex()))['reply']
        self.assertTrue(verify_reply(reply,state,now=self.now))
        outgoing=self.peer(dict(mode='query',certificate=self.cert))
        reply=answer_query(outgoing['blob'],self.cert,self.sign,self.box,now=self.now)
        self.assertTrue(self.peer(dict(mode='verify',reply=reply,state=outgoing['state']))['accepted'])

    def test_delegate_can_answer_without_recipient_or_owner_secrets(self):
        query,state=create_query(self.cert,now=self.now)
        reply=answer_query(query,self.cert,self.sign,self.box,now=self.now)
        self.assertTrue(verify_reply(reply,state,now=self.now))
        payload=seal(bytes(self.recipient.public_key),{'opaque':'test payload'})
        self.assertEqual(open_box(self.recipient,payload),{'opaque':'test payload'})
        with self.assertRaises(CryptoError):open_box(self.box,payload)
        changed=dict(self.cert,recipient_box=bytes(self.box.public_key).hex())
        with self.assertRaises(BadSignatureError):verify_certificate(changed,self.now)

    def test_replay_cross_query_expiry_and_forgery(self):
        query,state=create_query(self.cert,now=self.now)
        reply=answer_query(query,self.cert,self.sign,self.box,now=self.now)
        _,other=create_query(self.cert,now=self.now)
        with self.assertRaises(CryptoError):verify_reply(reply,other,now=self.now)
        for stale in (self.now+180,self.now+3600):
            with self.assertRaises(ValueError):verify_reply(reply,state,now=stale)
        forged=open_box(state['reply_private'],reply);forged['signature']='00'*64
        boxed=seal(bytes(state['reply_private'].public_key),forged)
        with self.assertRaises(BadSignatureError):verify_reply(boxed,state,now=self.now)
        forged=open_box(state['reply_private'],reply);forged['certificate']['generation']=True
        boxed=seal(bytes(state['reply_private'].public_key),forged)
        with self.assertRaises(ValueError):verify_reply(boxed,state,now=self.now)
        swapped=copy.deepcopy(state);swapped['query']['reply_key']='ab'*32
        with self.assertRaises(BadSignatureError):verify_reply(reply,swapped,now=self.now)

    def test_untrusted_descriptors_keys_and_outer_boxes_fail_closed(self):
        for patch in ({'version':True},{'generation':0},{'expires_at':self.now+31*86400},
                      {'issued_at':self.now+61},{'unexpected':True},{'route_id':'AA'*32}):
            with self.assertRaises((ValueError,BadSignatureError)):
                verify_certificate(dict(self.cert,**patch),self.now)
        query,_=create_query(self.cert,now=self.now)
        with self.assertRaises(ValueError):answer_query(query,self.cert,self.owner,self.box,now=self.now)
        with self.assertRaises(ValueError):answer_query(query,self.cert,self.sign,self.recipient,now=self.now)
        for invalid in ('?',query+'\n',base64.b64encode(bytes(71)).decode(),'A'*22000):
            with self.assertRaises(ValueError):open_box(self.box,invalid)
        with self.assertRaises(ValueError):seal(bytes(self.box.public_key),{'data':'x'*16384})
