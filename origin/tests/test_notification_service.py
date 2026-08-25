import asyncio
import hashlib
import hmac
import json
import tempfile
import unittest
from pathlib import Path

from fastapi import HTTPException

import notification_service


class FakeRequest:
    def __init__(self, body: bytes):
        self._body = body

    async def body(self) -> bytes:
        return self._body


class OriginNotificationTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.old_path = notification_service.DB_PATH
        self.old_hmac = notification_service.HMAC_KEY
        self.old_send = notification_service.telegram_send
        notification_service.DB_PATH = Path(self.tempdir.name) / "notifications.db"
        notification_service.HMAC_KEY = b"k" * 32
        self.sends = []
        notification_service.telegram_send = lambda chat_id: self.sends.append(chat_id) or True
        with notification_service.connect_db() as db:
            db.execute(
                "INSERT INTO bindings (handle_hash, chat_id, enabled) VALUES (?, ?, 1)",
                (notification_service.handle_hash("opaque-pending-handle"), "shared-chat"),
            )
            db.commit()

    def tearDown(self):
        notification_service.DB_PATH = self.old_path
        notification_service.HMAC_KEY = self.old_hmac
        notification_service.telegram_send = self.old_send
        self.tempdir.cleanup()

    def call_notify(self, payload: dict, signature: str):
        return asyncio.run(notification_service.notify(FakeRequest(json.dumps(payload).encode()), signature))

    def test_opaque_notification_uses_shared_binding_once(self):
        payload = {
            "version": 1,
            "notification_handle": "opaque-pending-handle",
            "idempotency_key": "stable-idempotency-key",
            "created_at": 1,
            "expires_at": 4_102_444_800,
        }
        body = json.dumps(payload).encode()
        signature = hmac.new(notification_service.HMAC_KEY, body, hashlib.sha256).hexdigest()
        self.assertEqual(self.call_notify(payload, signature), {"status": "notified"})
        self.assertEqual(self.call_notify(payload, signature), {"status": "already_processed"})
        self.assertEqual(self.sends, ["shared-chat"])

    def test_invalid_node_signature_is_rejected_before_lookup(self):
        payload = {
            "notification_handle": "opaque-pending-handle",
            "idempotency_key": "another-key",
            "expires_at": 4_102_444_800,
        }
        with self.assertRaises(HTTPException) as raised:
            self.call_notify(payload, "not-a-valid-signature")
        self.assertEqual(raised.exception.status_code, 403)
        self.assertEqual(self.sends, [])


if __name__ == "__main__":
    unittest.main()
