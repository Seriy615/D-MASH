"""Cross-library parity for the browser's unchanged production Node identity work."""
import json
from pathlib import Path
import subprocess
import unittest
import blake3
from nacl.signing import VerifyKey
from backend.crypto import NodeCryptoManager


class NodeIdentityJsTests(unittest.TestCase):
    def test_blake3_vectors_and_real_node_work(self):
        # Public proof from a throwaway production-cost identity. No private
        # seed is stored; live browser mining has a separate bounded runner.
        root = Path(__file__).resolve().parents[3]
        fixture = json.loads((root / 'D-MASH PWA/not_messenger/tests/fixtures/node_identity_public.json').read_text())
        node_id = fixture['node_id']
        VerifyKey(bytes.fromhex(node_id)).verify(fixture['message'].encode(), bytes.fromhex(fixture['signature']))
        inputs = ['0' * 64, 'a' * 64, node_id]
        harness = Path(__file__).resolve().parents[3] / 'D-MASH PWA/not_messenger/tests/node_identity_peer.cjs'
        result = subprocess.run(['node', str(harness)], input=json.dumps(inputs), capture_output=True, text=True, check=True)
        for value, output in zip(inputs, json.loads(result.stdout), strict=True):
            self.assertEqual(output['hash'], blake3.blake3(value.encode()).hexdigest())
            self.assertEqual(output['valid'], NodeCryptoManager.verify_node_pow(value))
        self.assertTrue(json.loads(result.stdout)[-1]['valid'])
