import base64
import sqlite3
import unittest

from nacl import utils

from personal_bot_vault import PersonalBotVault


class PersonalBotVaultTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.vault = PersonalBotVault(base64.urlsafe_b64encode(utils.random(32)).decode("ascii"))
        self.vault.ensure_schema(self.db)

    def test_token_is_encrypted_and_not_returned_by_status(self):
        token = "example-private-bot-token"
        stored = self.vault.save(self.db, "opaque-owner", token)
        self.db.commit()
        raw = self.db.execute("SELECT token_ciphertext FROM personal_bots").fetchone()[0]
        self.assertNotIn(token, raw)
        self.assertEqual(stored.token_suffix, token[-4:])
        self.assertEqual(self.vault.status(self.db, "opaque-owner").token_suffix, token[-4:])
        self.assertEqual(self.vault.decrypt_for_delivery(self.db, "opaque-owner"), token)

    def test_disable_replace_and_remove_lifecycle(self):
        self.vault.save(self.db, "opaque-owner", "token-one")
        self.assertTrue(self.vault.disable(self.db, "opaque-owner"))
        self.assertIsNone(self.vault.decrypt_for_delivery(self.db, "opaque-owner"))
        self.vault.save(self.db, "opaque-owner", "token-two")
        self.assertEqual(self.vault.decrypt_for_delivery(self.db, "opaque-owner"), "token-two")
        self.assertTrue(self.vault.remove(self.db, "opaque-owner"))
        self.assertIsNone(self.vault.status(self.db, "opaque-owner"))


if __name__ == "__main__":
    unittest.main()
