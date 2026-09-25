import unittest
import json
import subprocess
from pathlib import Path
from nacl.signing import SigningKey
from backend.crypto import NodeCryptoManager
from backend.secure_session import Handshake
from backend.node_admission_v4 import PasswordGate, password_credential, password_proof, derive_password_key

class AdmissionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        def mine():
            while True:
                key=SigningKey.generate()
                if NodeCryptoManager.verify_node_pow(key.verify_key.encode().hex()):return key
        cls.a,cls.b=mine(),mine()
        cls.credential=password_credential('test-only password admission')

    def pair(self):
        i,r=Handshake(self.a,'NODE',version=4),Handshake(self.b,'NODE',version=4)
        auth,client=i.finish(r.respond(i.initiate(),'NODE',now=100),self.b.verify_key.encode().hex(),now=100)
        return client,r.accept(auth,now=100)

    def test_correct_wrong_replay_and_resource_gate(self):
        client,server=self.pair();gate=PasswordGate(self.credential,clock=lambda:100)
        with self.assertRaises(PermissionError):gate.require(server)
        challenge=gate.challenge(server)
        proof=password_proof(self.credential['key'],challenge,client,now=100)
        self.assertTrue(gate.verify(server,proof));gate.require(server)
        self.assertFalse(gate.verify(server,proof))
        gate.revoke_all()
        with self.assertRaises(PermissionError):gate.require(server)
        client,server=self.pair();challenge=gate.challenge(server)
        wrong=password_proof(b'x'*32,challenge,client,now=100)
        self.assertFalse(gate.verify(server,wrong))
        with self.assertRaises(PermissionError):gate.challenge(server)
        with self.assertRaises(PermissionError):gate.require(server)

    def test_session_binding_expiry_and_identity_work(self):
        client,server=self.pair();other_client,other_server=self.pair()
        now=[100];gate=PasswordGate(self.credential,clock=lambda:now[0])
        challenge=gate.challenge(server);gate.challenge(other_server)
        proof=password_proof(self.credential['key'],challenge,client,now=100)
        self.assertFalse(gate.verify(other_server,proof))
        now[0]=190
        self.assertFalse(gate.verify(server,proof))
        with self.assertRaises(PermissionError):password_proof(self.credential['key'],challenge,client,now=190)
        client.peer_id='00'*32
        with self.assertRaises(PermissionError):gate.challenge(client)

    def test_argon2_profile_vector(self):
        key=derive_password_key('test-only password admission',bytes(range(16)))
        self.assertEqual(len(key),32)
        self.assertEqual(key,derive_password_key('test-only password admission',bytes(range(16))))
        self.assertNotEqual(key,derive_password_key('wrong',bytes(range(16))))

    def test_real_js_hmac_proof_and_wrong_context(self):
        harness=Path(__file__).resolve().parents[3]/'D-MASH PWA/not_messenger/tests/node_admission_peer.cjs'
        for altered in (False,True):
            client,server=self.pair();gate=PasswordGate(self.credential,clock=lambda:100)
            challenge=gate.challenge(server)
            value={'key':list(self.credential['key']),'challenge':challenge,'now':100,
                'session':{'version':4,'closed':False,'localRole':'NODE','peerRole':'NODE',
                    'localId':client.local_id,'peerId':client.peer_id,
                    'transcriptHash':list(bytes(32) if altered else client.transcript_hash)}}
            result=json.loads(subprocess.run(['node',str(harness)],input=json.dumps(value),text=True,capture_output=True,check=True).stdout)
            self.assertEqual(gate.verify(server,result['proof']),not altered)
            if not altered:
                self.assertEqual(result['proof'],password_proof(self.credential['key'],challenge,client,now=100))
            value['challenge']['profile']='ARGON2ID_UNBOUNDED'
            result=json.loads(subprocess.run(['node',str(harness)],input=json.dumps(value),text=True,capture_output=True,check=True).stdout)
            self.assertTrue(result['rejected'])

    def test_bad_password_cooldown_survives_socket_replacement(self):
        now=[100];gate=PasswordGate(self.credential,clock=lambda:now[0])
        client,server=self.pair();challenge=gate.challenge(server)
        self.assertFalse(gate.verify(server,password_proof(b'x'*32,challenge,client,now=100)))
        gate.forget(server)
        client,server=self.pair()
        with self.assertRaisesRegex(PermissionError,'cooldown'):gate.challenge(server)
        now[0]=101
        challenge=gate.challenge(server)
        self.assertTrue(gate.verify(server,password_proof(self.credential['key'],challenge,client,now=101)))
        self.assertFalse(gate.failures)
