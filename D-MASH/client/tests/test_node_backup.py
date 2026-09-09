import os
import tempfile
import unittest
from pathlib import Path

from backend.crypto import NodeCryptoManager
from backend.core import ensure_base_ncrh
from backend.node_backup import LocalBlindObjectStore, backup_node, decrypt_bundle, encrypt_bundle, restore_node_files


class NodeSecretTests(unittest.TestCase):
    def test_base_ncrh_is_atomically_persisted_and_not_rotated_on_read(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / 'base.ncrh')
            first = ensure_base_ncrh(path)
            second = ensure_base_ncrh(path)
            self.assertEqual(first, second)
            self.assertEqual(len(first), 32)
            self.assertEqual(Path(path).stat().st_mode & 0o777, 0o600)

    def test_base_ncrh_and_roots_are_stable_until_secret_replaced(self):
        base = b'a' * 32
        first = NodeCryptoManager('11' * 32, base)
        restarted = NodeCryptoManager('11' * 32, base)
        self.assertEqual(first.derive_ncrh_root(), restarted.derive_ncrh_root())
        self.assertEqual(first.extend_ncrh(first.derive_ncrh_root()), restarted.extend_ncrh(first.derive_ncrh_root()))
        replaced = NodeCryptoManager('11' * 32, b'b' * 32)
        self.assertNotEqual(first.derive_ncrh_root(), replaced.derive_ncrh_root())

    def test_root_and_hop_use_separate_domains(self):
        node = NodeCryptoManager('22' * 32, b'c' * 32)
        self.assertNotEqual(node.derive_ncrh_root(), node.extend_ncrh(node.derive_ncrh_root()))


class BackupTests(unittest.IsolatedAsyncioTestCase):
    async def test_encrypted_blind_roundtrip_and_opaque_ids(self):
        with tempfile.TemporaryDirectory() as directory:
            store = LocalBlindObjectStore(directory)
            first = await backup_node(store, '11' * 32, b'a' * 32, generation=1)
            second = await backup_node(store, '11' * 32, b'a' * 32, generation=2)
            self.assertNotEqual(first[0], second[0])
            blob = await store.get(first[0])
            self.assertNotIn(b'11' * 32, blob); self.assertNotIn(b'a' * 32, blob); self.assertNotIn(b'recovery_generation', blob)
            payload = decrypt_bundle(blob, __import__('base64').urlsafe_b64decode(first[1] + '=='))
            self.assertEqual(payload['recovery_generation'], 1)
            self.assertEqual(payload['persistent_secret_state']['base_ncrh_hex'], (b'a' * 32).hex())
            self.assertEqual(set(payload['persistent_secret_state']), {'signing_key_hex', 'base_ncrh_hex'})
            self.assertNotIn('hop_labels', payload)
            self.assertNotIn('route_candidates', payload)
            with self.assertRaises(Exception): decrypt_bundle(blob[:-1] + bytes([blob[-1] ^ 1]), __import__('base64').urlsafe_b64decode(first[1] + '=='))
            with self.assertRaises(Exception): decrypt_bundle(blob, b'z' * 32)
            for entry in Path(directory).iterdir():
                self.assertEqual(entry.stat().st_mode & 0o777, 0o600)

    async def test_restore_only_persistent_state_and_failure_is_non_mutating(self):
        with tempfile.TemporaryDirectory() as directory:
            identity = Path(directory) / 'node.key'; base = Path(directory) / 'node.key.basencrh'
            identity.write_text('22' * 32); base.write_text('bb' * 32)
            bundle = encrypt_bundle('11' * 32, b'a' * 32, generation=7)
            ram_salt = restore_node_files(decrypt_bundle(bundle['ciphertext'], __import__('base64').urlsafe_b64decode(bundle['recovery_key'] + '==')), str(identity), str(base))
            self.assertEqual(len(ram_salt), 32)
            self.assertNotEqual(ram_salt, b'a' * 32)
            self.assertEqual(identity.read_text(), '11' * 32); self.assertEqual(base.read_text(), (b'a' * 32).hex())
            before = (identity.read_bytes(), base.read_bytes())
            with self.assertRaises(Exception): decrypt_bundle(bundle['ciphertext'][:-1], b'z' * 32)
            self.assertEqual((identity.read_bytes(), base.read_bytes()), before)
