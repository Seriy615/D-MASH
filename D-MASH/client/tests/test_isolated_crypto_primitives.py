import time
import unittest

from nacl.encoding import HexEncoder
from nacl.signing import SigningKey

from backend.dnss import DNSSContext
from backend.entry_grant import EntryGrantV1
from backend.resource_pow import mine_resource_pow, verify_resource_pow


class IsolatedCryptoPrimitiveTests(unittest.TestCase):
    def test_dnss_is_128_bit_and_node_blind_hashes_differ(self):
        node_a = DNSSContext("a" * 64, blind_key=b"k" * 32)
        node_b = DNSSContext("b" * 64, blind_key=b"k" * 32)
        self.assertEqual(len(node_a.token()), 16)
        self.assertNotEqual(node_a.token(), node_a.token())
        self.assertNotEqual(node_a.blind_hash("same-resource"), node_b.blind_hash("same-resource"))

    def test_entry_grant_rejects_wrong_signer_and_wrong_node(self):
        node = SigningKey.generate()
        other = SigningKey.generate()
        route = SigningKey.generate().verify_key.encode(encoder=HexEncoder).decode("ascii")
        node_id = node.verify_key.encode(encoder=HexEncoder).decode("ascii")
        other_id = other.verify_key.encode(encoder=HexEncoder).decode("ascii")
        grant = EntryGrantV1.issue(node, route, int(time.time()) + 60)
        self.assertTrue(grant.verify(expected_node_id=node_id))
        self.assertFalse(grant.verify(expected_node_id=other_id))
        forged = EntryGrantV1.issue(other, route, int(time.time()) + 60)
        # A grant signed by another key cannot claim this node identity.
        forged = EntryGrantV1(node_id, forged.route_id, forged.route_public_key, forged.expires_at, forged.signature)
        self.assertFalse(forged.verify(expected_node_id=node_id))

    def test_resource_pow_is_node_bound(self):
        nonce = mine_resource_pow("node-A", "resource", difficulty=10)
        self.assertTrue(verify_resource_pow("node-A", "resource", nonce, 10))
        self.assertFalse(verify_resource_pow("node-B", "resource", nonce, 10))


if __name__ == "__main__":
    unittest.main()
