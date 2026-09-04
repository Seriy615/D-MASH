import sqlite3
import asyncio
import tempfile
import unittest
from pathlib import Path

from personal_bot_enrollment import EnrollmentStore
import notification_service


class FakeTelegramRequest:
    def __init__(self, update):
        self.update = update

    async def json(self):
        return self.update


class EnrollmentTests(unittest.TestCase):
    def test_webhook_secret_and_one_time_start_code_bind_once(self):
        db = sqlite3.connect(":memory:")
        store = EnrollmentStore()
        store.ensure_schema(db)
        secrets = store.create(db, "owner")
        self.assertIsNone(store.bind_from_webhook(db, "wrong", "123", "/start " + secrets.start_code))
        self.assertIsNone(store.bind_from_webhook(db, secrets.webhook_secret, "123", "/start wrong"))
        self.assertIsNotNone(store.bind_from_webhook(db, secrets.webhook_secret, "123", "/start " + secrets.start_code))
        self.assertIsNone(store.bind_from_webhook(db, secrets.webhook_secret, "123", "/start " + secrets.start_code))

    def test_valid_start_deep_link_confirms_connected_beacon(self):
        with tempfile.TemporaryDirectory() as directory:
            old_path, old_call = notification_service.DB_PATH, notification_service.telegram_call
            notification_service.DB_PATH = Path(directory) / "notifications.db"
            calls = []
            notification_service.telegram_call = lambda token, method, fields: calls.append((token, method, fields)) or {"message_id": 1}
            try:
                with notification_service.connect_db() as db:
                    secrets = EnrollmentStore().create(db, "opaque-owner")
                    db.commit()
                update = {"message": {"chat": {"id": 123}, "text": "/start " + secrets.start_code}}
                result = asyncio.run(notification_service.personal_webhook(FakeTelegramRequest(update), secrets.webhook_secret))
                self.assertEqual(result, {"status": "bound"})
                self.assertEqual(calls, [(notification_service.TOKEN, "sendMessage", {
                    "chat_id": "123", "text": notification_service.BEACON_CONNECTED_MESSAGE,
                })])
            finally:
                notification_service.DB_PATH, notification_service.telegram_call = old_path, old_call


if __name__ == "__main__":
    unittest.main()
