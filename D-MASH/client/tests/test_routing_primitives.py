import base64
import json
import os
import sys
import unittest

from nacl.signing import SigningKey

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from backend.routing_primitives import (
    create_entry_grant,
    create_resource_pow,
    generate_dnss,
    node_context,
    validate_node_context,
    verify_entry_grant,
    verify_resource_pow,
)


class RoutingPrimitiveTests(unittest.TestCase):
    def setUp(self):
        self.a = SigningKey.generate()
        self.b = SigningKey.generate()
        self.node_a = self.a.verify_key.encode().hex()
        self.node_b = self.b.verify_key.encode().hex()

    def test_dnss_is_fresh_and_context_separated(self):
        first = generate_dnss(self.node_a)
        second = generate_dnss(self.node_a)
        other_context = generate_dnss(self.node_b)
        self.assertEqual(len(bytes.fromhex(first)), 16)
        self.assertEqual(len(bytes.fromhex(second)), 16)
        self.assertEqual(len(bytes.fromhex(other_context)), 16)
        self.assertNotEqual(first, second)
        self.assertNotEqual(first, other_context)

    def test_node_context_requires_node_and_blind_callback(self):
        calls = []
        def blind(node_id, value):
            calls.append((node_id, value))
            return b"blind:" + bytes.fromhex(node_id) + value

        context = node_context(self.node_a, b"resource", blind)
        self.assertTrue(validate_node_context(self.node_a, context, blind, b"resource"))
        self.assertFalse(validate_node_context(self.node_b, context, blind, b"resource"))
        self.assertFalse(validate_node_context(self.node_a, context, blind, b"other"))
        self.assertTrue(calls)

    def test_entry_grant_is_signed_node_bound_and_canonical(self):
        encoded = create_entry_grant(self.node_a, self.a, "route-token", 4_000_000_000, issued_at=10)
        self.assertEqual(verify_entry_grant(encoded, self.a.verify_key, self.node_a, now=20)["resource"], "route-token")
        self.assertIsNone(verify_entry_grant(encoded, self.b.verify_key, self.node_a, now=20))
        self.assertIsNone(verify_entry_grant(encoded, self.a.verify_key, self.node_b, now=20))
        self.assertIsNone(verify_entry_grant(encoded, self.a.verify_key, self.node_a, now=4_000_000_000))
        wire = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        self.assertNotIn("account", wire)
        self.assertNotIn("username", wire)
        self.assertNotIn("user_id", wire)

    def test_resource_pow_is_node_bound(self):
        proof = create_resource_pow(self.node_a, "blob-17", difficulty=8)
        self.assertTrue(verify_resource_pow(proof, self.node_a))
        self.assertFalse(verify_resource_pow(proof, self.node_b))
        self.assertNotIn("account", proof)
        self.assertNotIn("username", proof)
        self.assertNotIn("user_id", proof)


if __name__ == "__main__":
    unittest.main()
