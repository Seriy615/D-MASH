import base64
import time
import unittest

from nacl.signing import SigningKey

from backend.entry_grant import EntryGrantV1, route_id_for_public_key


class RouteOwnedEntryGrantTests(unittest.TestCase):
    def setUp(self):
        self.route_key = SigningKey.generate()
        self.node_key = SigningKey.generate()
        self.other_node = SigningKey.generate()
        self.route_id = route_id_for_public_key(self.route_key.verify_key)
        self.node_id = self.node_key.verify_key.encode().hex()
        self.other_node_id = self.other_node.verify_key.encode().hex()

    def grant(self):
        now = int(time.time())
        return EntryGrantV1.issue(
            self.route_key,
            self.route_id,
            now + 300,
            entry_node_id=self.node_id,
            generation=7,
            created_at=now,
        )

    def test_route_id_is_route_signing_public_key_not_a_hash(self):
        grant = self.grant()
        raw = base64.urlsafe_b64decode(grant.route_id + "=" * (-len(grant.route_id) % 4))
        self.assertEqual(raw, self.route_key.verify_key.encode())
        self.assertEqual(grant.route_id, self.route_id)
        self.assertEqual(grant.route_public_key, self.route_id)

    def test_route_private_key_not_node_key_authorizes_grant(self):
        grant = self.grant()
        self.assertTrue(grant.verify(expected_node_id=self.node_id))
        self.assertFalse(grant.verify(expected_node_id=self.other_node_id))

        forged_by_entry_node = EntryGrantV1.issue(
            self.node_key,
            route_id_for_public_key(self.node_key.verify_key),
            grant.expires_at,
            entry_node_id=self.node_id,
            generation=grant.generation,
            created_at=grant.created_at,
        )
        self.assertNotEqual(forged_by_entry_node.route_id, grant.route_id)
        self.assertTrue(forged_by_entry_node.verify(expected_node_id=self.node_id))

    def test_entry_node_cannot_mint_somebody_elses_route_id(self):
        now = int(time.time())
        with self.assertRaises(ValueError):
            EntryGrantV1.issue(
                self.node_key,
                self.route_id,
                now + 300,
                entry_node_id=self.node_id,
                created_at=now,
            )

    def test_signed_node_generation_creation_and_expiry_are_tamper_evident(self):
        grant = self.grant()
        mutations = [
            {"node_id": self.other_node_id},
            {"generation": grant.generation + 1},
            {"created_at": grant.created_at + 1},
            {"expires_at": grant.expires_at + 1},
        ]
        for change in mutations:
            fields = {
                "node_id": grant.node_id,
                "route_id": grant.route_id,
                "route_public_key": grant.route_public_key,
                "expires_at": grant.expires_at,
                "signature": grant.signature,
                "generation": grant.generation,
                "created_at": grant.created_at,
            }
            fields.update(change)
            tampered = EntryGrantV1(**fields)
            self.assertFalse(tampered.verify(expected_node_id=tampered.node_id))

    def test_old_node_signed_wire_shape_is_rejected(self):
        route_hex = self.route_key.verify_key.encode().hex()
        old_shape = {
            "v": "EntryGrantV1",
            "node_id": self.node_id,
            "route_id": "00" * 32,
            "route_public_key": route_hex,
            "expires_at": int(time.time()) + 60,
            "signature": "AA",
        }
        with self.assertRaises(ValueError):
            EntryGrantV1.from_dict(old_shape)


if __name__ == "__main__":
    unittest.main()
