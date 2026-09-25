import copy
import json
from pathlib import Path
import subprocess
import unittest
from nacl.signing import SigningKey
from backend.secure_session import Handshake
from backend.node_registration_v4 import resource, verify_registration
from backend.resource_pow import mine_activation_pow

HARNESS = Path(__file__).resolve().parents[3] / 'D-MASH PWA/not_messenger/tests/node_registration_peer.cjs'

class RegistrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        a,b = SigningKey.generate(),SigningKey.generate()
        initiator,responder = Handshake(a,'NODE',version=4),Handshake(b,'NODE',version=4)
        auth,cls.sender = initiator.finish(responder.respond(initiator.initiate(),'NODE',now=100),b.verify_key.encode().hex(),now=100)
        cls.receiver = responder.accept(auth,now=100)
        cls.dnss = 'ab'*16
        work = resource(cls.sender.local_id,cls.receiver.local_id,cls.dnss,cls.receiver.transcript_hash)
        # Genuine production-minimum work; no mocked verification or reduced target.
        cls.request = {'type':'NODE_REGISTER','dnss':cls.dnss,'pow':mine_activation_pow(
            cls.receiver.local_id,'DNSS',cls.sender.local_id,work,280,20)}

    def test_authenticated_session_identity_metadata(self):
        self.assertEqual(self.sender.local_id,self.receiver.peer_id)
        self.assertEqual(self.receiver.local_id,self.sender.peer_id)
        self.assertNotEqual(self.sender.local_id,self.sender.peer_id)

    def test_js_python_positive_and_negative_parity(self):
        cases = [(self.receiver,copy.deepcopy(self.request),20,100,self.dnss,True)]
        for attribute,value in [('version',3),('closed',True),('local_role','DEVICE'),
            ('peer_id','aa'*32),('local_id','cc'*32),('transcript_hash',bytes(32))]:
            session=copy.copy(self.receiver);setattr(session,attribute,value)
            cases.append((session,copy.deepcopy(self.request),20,100,self.dnss,False))
        cases.extend([(self.sender,copy.deepcopy(self.request),20,100,self.dnss,False),
            (self.receiver,copy.deepcopy(self.request),20,280,self.dnss,False),
            (self.receiver,copy.deepcopy(self.request),20,99,self.dnss,False),
            (self.receiver,copy.deepcopy(self.request),20,100,'cd'*16,False),
            (self.receiver,copy.deepcopy(self.request),19,100,self.dnss,False)])
        for key,value in [('v',True),('nonce',True),('difficulty',True),('expires_at',True),('resource','old-session'),('digest','FF'*32)]:
            request=copy.deepcopy(self.request);request['pow'][key]=value
            cases.append((self.receiver,request,20,100,self.dnss,False))
        request=copy.deepcopy(self.request);request['pow']['unexpected']=True
        cases.append((self.receiver,request,20,100,self.dnss,False))
        values=[]
        for session,request,difficulty,now,expected,valid in cases:
            self.assertEqual(verify_registration(session,request,difficulty,now=now,expected_dnss=expected),valid)
            values.append({'session':{'version':session.version,'closed':session.closed,
                'localRole':session.local_role,'peerRole':session.peer_role,
                'localId':session.local_id,'peerId':session.peer_id,'transcriptHash':session.transcript_hash.hex()},
                'request':request,'difficulty':difficulty,'now':now,'expectedDnss':expected})
        output=subprocess.run(['node',str(HARNESS)],input=json.dumps(values),capture_output=True,text=True,check=True)
        self.assertEqual(json.loads(output.stdout),[case[-1] for case in cases])

    def test_transcript_rejects_ambiguous_encodings(self):
        for issuer,recipient,dnss,transcript in [(self.sender.local_id,self.receiver.local_id,'AB'*16,bytes(32)),
            (self.sender.local_id,self.sender.local_id,self.dnss,bytes(32)),
            (self.sender.local_id,self.receiver.local_id,self.dnss,bytes(31))]:
            with self.assertRaises(ValueError):resource(issuer,recipient,dnss,transcript)
