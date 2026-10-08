import base64
import json
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'backend'))
from nacl.signing import SigningKey
import node_store_profile_v4 as api

class CodecTests(unittest.TestCase):
    def test_vectors_and_negative_mutations(self):
        fixture=Path(__file__).resolve().parents[3]/'D-MASH PWA/not_messenger/tests/fixtures/node_store_profile_v4_signed.json'
        for row in json.loads(fixture.read_text()):
            envelope=row['envelope']; expected=row['expected']
            self.assertEqual(api.body_bytes(envelope['kind'],envelope['body']).hex(),row['bytes'])
            self.assertEqual(api.verify(envelope,now=100,expected=expected),envelope['body'])
            secret=SigningKey(bytes.fromhex(row['seed']))
            self.assertEqual(api.sign(envelope['kind'],envelope['body'],secret),envelope)
            with self.assertRaises(Exception): api.verify(envelope,now=200,expected=expected)
            bad=json.loads(json.dumps(envelope));bad['body']['extra']=1
            with self.assertRaises(Exception): api.verify(bad,now=100,expected=expected)
            bad=json.loads(json.dumps(envelope));bad['signature']=base64.b64encode(bytes(64)).decode()
            with self.assertRaises(Exception): api.verify(bad,now=100,expected=expected)
            for signature in [bytes(32)+base64.b64decode(envelope['signature'])[32:], base64.b64decode(envelope['signature'])[:32]+(2**252+27742317777372353535851937790883648493).to_bytes(32,'little')]:
                bad={**envelope,'signature':base64.b64encode(signature).decode()}
                with self.assertRaises(Exception): api.verify(bad,now=100,expected=expected)
            for field in ('version','expires_at'):
                bad=json.loads(json.dumps(envelope));bad['body'][field]=True
                with self.assertRaises(Exception): api.verify(bad,now=100,expected=expected)
            if 'transcript_hash' in expected:
                with self.assertRaises(Exception): api.verify(envelope,now=100,expected={**expected,'transcript_hash':'ee'*32})
            with self.assertRaises(Exception): api.parse(' '+api.canonical(envelope).decode(),now=100,expected=expected)
            with self.assertRaises(Exception): api.verify(envelope,now=100,expected={'issuer':'ff'*32})
    def test_profiles(self):
        self.assertEqual(api.negotiate({'profiles':[api.PROFILE],'required_profiles':[api.PROFILE]}),api.PROFILE)
        for value in ({},{'profiles':[api.PROFILE],'required_profiles':['UNKNOWN']},{'profiles':[api.PROFILE,api.PROFILE],'required_profiles':[api.PROFILE]}):
            with self.assertRaises(ValueError):api.negotiate(value)

if __name__=='__main__':unittest.main()
