"""Opt-in v4 crypto profile: NODE only, no downgrade or implicit resources."""
import json
from pathlib import Path
import subprocess
import unittest
from nacl.signing import SigningKey
from backend.secure_session import Handshake

HARNESS = Path(__file__).resolve().parents[3] / 'D-MASH PWA/not_messenger/tests/secure_session_peer.cjs'


def browser(value):
    result = subprocess.run(['node', str(HARNESS)], input=json.dumps(value), capture_output=True, text=True, check=True)
    return json.loads(result.stdout)


class UnifiedSessionTests(unittest.TestCase):
    def test_real_js_python_v4_records_in_both_directions(self):
        hello = browser({'role': 'NODE', 'version': 4})
        self.assertEqual(hello['version'], 4)
        key = SigningKey.generate()
        responder = Handshake(key, 'NODE', version=4)
        challenge = responder.respond(hello, 'NODE', now=100)
        args = {'hello': hello, 'challenge': challenge, 'role': 'NODE', 'version': 4,
                'nodeId': key.verify_key.encode().hex()}
        result = browser(args)
        server = responder.accept(result['auth'], now=100)
        self.assertEqual(server.version, 4)
        self.assertEqual(server.local_role, 'NODE')
        self.assertEqual(server.peer_role, 'NODE')
        self.assertEqual(result['frame']['version'], 4)
        self.assertEqual(server.open(result['frame'])['type'], 'PING')
        self.assertEqual(browser({**args, 'frame': server.seal({'type': 'READY'})})['opened'], {'type': 'READY'})

    def test_python_node_exchange(self):
        a, b = SigningKey.generate(), SigningKey.generate()
        i, r = Handshake(a, 'NODE', version=4), Handshake(b, 'NODE', version=4)
        challenge = r.respond(i.initiate(), 'NODE', now=100)
        auth, client = i.finish(challenge, b.verify_key.encode().hex(), now=100)
        server = r.accept(auth, now=100)
        frame = client.seal({'type': 'PING'})
        self.assertEqual(server.open(frame), {'type': 'PING'})
        with self.assertRaises(ValueError): server.open(frame)
        self.assertTrue(server.closed)

    def test_v4_crypto_does_not_inherit_v3_node_grants(self):
        import asyncio
        from types import SimpleNamespace
        from backend.node_session import authorize_node
        secure = SimpleNamespace(session=SimpleNamespace(version=4, local_role='NODE', peer_role='NODE'))
        with self.assertRaisesRegex(PermissionError, 'different protocol version'):
            asyncio.run(authorize_node(secure, 'local', 'peer'))

    def test_v4_rejects_device_and_unknown_profiles(self):
        for role, version in [('DEVICE', 4), ('NODE', 5), ('NODE', True)]:
            with self.subTest(role=role, version=version), self.assertRaises(ValueError):
                Handshake(SigningKey.generate(), role, version=version)

    def test_mixed_version_hello_fails_before_any_challenge(self):
        for old, new in [(3, 4), (4, 3)]:
            i = Handshake(SigningKey.generate(), 'NODE', version=old)
            r = Handshake(SigningKey.generate(), 'NODE', version=new)
            with self.assertRaises(ValueError): r.respond(i.initiate(), 'NODE', now=100)
            self.assertIsNone(r.challenge)
            r.close(); i.close()

    def test_version_tampering_does_not_convert_v3_transcript_or_record(self):
        a, b = SigningKey.generate(), SigningKey.generate()
        i = Handshake(a, 'NODE', version=4)
        hello = i.initiate()
        # An attacker may rewrite the visible version; signatures and KDF
        # still bind the original initiator transcript and v4 domain.
        hello['version'] = 3
        r = Handshake(b, 'NODE')
        challenge = r.respond(hello, 'NODE', now=100)
        challenge['version'] = 4
        with self.assertRaises(Exception): i.finish(challenge, b.verify_key.encode().hex(), now=100)
        r.close()
