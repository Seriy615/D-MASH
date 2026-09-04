import base64
import sqlite3
import unittest

from nacl import utils

import notification_service
from personal_bot_enrollment import EnrollmentStore
from personal_bot_vault import PersonalBotVault


class PersonalBotDeliveryTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.key = base64.urlsafe_b64encode(utils.random(32)).decode("ascii")
        self.old_key = notification_service.VAULT_KEY
        notification_service.VAULT_KEY = self.key
        self.vault = PersonalBotVault(self.key)
        self.vault.ensure_schema(self.db)
        self.store = EnrollmentStore()
        self.store.ensure_schema(self.db)
        secrets = self.store.create(self.db, "opaque-owner")
        self.store.bind_from_webhook(self.db, secrets.webhook_secret, "safe-chat-id", "/start " + secrets.start_code, self.key)
        self.vault.save(self.db, "opaque-owner", "private-personal-bot-token")

    def tearDown(self):
        notification_service.VAULT_KEY = self.old_key
        self.db.close()

    def test_delivery_uses_bound_personal_bot_only_inside_origin(self):
        calls = []
        old_call = notification_service.telegram_call
        notification_service.telegram_call = lambda token, method, fields: calls.append((token, method, fields)) or {"message_id": 1}
        try:
            self.assertTrue(notification_service.send_personal_test(self.db, "opaque-owner"))
        finally:
            notification_service.telegram_call = old_call
        self.assertEqual(calls, [("private-personal-bot-token", "sendMessage", {"chat_id": "safe-chat-id", "text": notification_service.MESSAGE})])

    def test_disabled_or_unbound_bot_has_no_delivery_target(self):
        self.assertIsNotNone(notification_service.personal_delivery_target(self.db, "opaque-owner"))
        self.vault.disable(self.db, "opaque-owner")
        self.assertIsNone(notification_service.personal_delivery_target(self.db, "opaque-owner"))


if __name__ == "__main__":
    unittest.main()
