import sqlite3
import unittest

from personal_bot_enrollment import EnrollmentStore


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


if __name__ == "__main__":
    unittest.main()
