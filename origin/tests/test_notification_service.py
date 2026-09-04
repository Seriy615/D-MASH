import asyncio
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from fastapi import HTTPException
from nacl.encoding import HexEncoder
from nacl.public import PrivateKey, SealedBox
from nacl.signing import SigningKey
from nacl import utils
import base64

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
        self.old_origin_key = notification_service.ORIGIN_PRIVATE_KEY_HEX
        self.old_node_keys = notification_service.AUTHORIZED_NODE_KEYS
        self.old_vault_key = notification_service.VAULT_KEY
        self.old_send = notification_service.telegram_send
        notification_service.DB_PATH = Path(self.tempdir.name) / "notifications.db"
        self.origin_key = PrivateKey.generate()
        self.node_key = SigningKey.generate()
        self.node_id = self.node_key.verify_key.encode(encoder=HexEncoder).decode()
        notification_service.ORIGIN_PRIVATE_KEY_HEX = self.origin_key.encode(encoder=HexEncoder).decode()
        notification_service.AUTHORIZED_NODE_KEYS = frozenset({self.node_id})
        notification_service.VAULT_KEY = base64.urlsafe_b64encode(utils.random(32)).decode("ascii")
        self.sends = []
        notification_service.telegram_send = lambda chat_id, event_type: self.sends.append((chat_id, event_type)) or True
        with notification_service.connect_db() as db:
            db.execute(
                "INSERT INTO bindings (handle_hash, chat_id, enabled) VALUES (?, ?, 1)",
                (notification_service.handle_hash("opaque-pending-handle"), "shared-chat"),
            )
            db.commit()

    def tearDown(self):
        notification_service.DB_PATH = self.old_path
        notification_service.ORIGIN_PRIVATE_KEY_HEX = self.old_origin_key
        notification_service.AUTHORIZED_NODE_KEYS = self.old_node_keys
        notification_service.VAULT_KEY = self.old_vault_key
        notification_service.telegram_send = self.old_send
        self.tempdir.cleanup()

    def call_notify(self, payload: dict, *, signer=None):
        signer = signer or self.node_key
        ciphertext = __import__("base64").b64encode(
            SealedBox(self.origin_key.public_key).encrypt(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
        ).decode()
        node_id = signer.verify_key.encode(encoder=HexEncoder).decode()
        transcript = f"DMP-ORIGIN-NOTIFY|1|{node_id}|{ciphertext}".encode()
        envelope = {"version": 1, "node_id": node_id, "ciphertext": ciphertext,
                    "signature": __import__("base64").b64encode(signer.sign(transcript).signature).decode()}
        return asyncio.run(notification_service.notify(FakeRequest(json.dumps(envelope).encode())))

    def test_opaque_notification_uses_shared_binding_once(self):
        payload = {
            "version": 2,
            "notification_handle": "opaque-pending-handle",
            "event_type": "MALYAVA",
            "idempotency_key": "stable-idempotency-key",
            "created_at": 1,
            "expires_at": 4_102_444_800,
        }
        self.assertEqual(self.call_notify(payload), {"status": "notified"})
        self.assertEqual(self.call_notify(payload), {"status": "already_processed"})
        self.assertEqual(self.sends, [("shared-chat", "MALYAVA")])

    def test_incoming_bazar_is_classified_without_disclosing_content(self):
        payload = {
            "version": 2, "notification_handle": "opaque-pending-handle",
            "event_type": "INCOMING_BAZAR", "idempotency_key": "incoming-bazar-key",
            "created_at": 1, "expires_at": 4_102_444_800,
        }
        self.assertEqual(self.call_notify(payload), {"status": "notified"})
        self.assertEqual(self.sends, [("shared-chat", "INCOMING_BAZAR")])

    def test_unknown_or_legacy_event_is_rejected_after_signature_verification(self):
        payload = {
            "version": 2, "notification_handle": "opaque-pending-handle",
            "event_type": "NOT_A_REAL_EVENT", "idempotency_key": "bad-event-key",
            "created_at": 1, "expires_at": 4_102_444_800,
        }
        with self.assertRaises(HTTPException) as raised:
            self.call_notify(payload)
        self.assertEqual(raised.exception.status_code, 400)

    def test_invalid_node_signature_is_rejected_before_lookup(self):
        payload = {"version": 2, "notification_handle": "opaque-pending-handle", "event_type": "MALYAVA", "idempotency_key": "another-key", "expires_at": 4_102_444_800}
        with self.assertRaises(HTTPException) as raised:
            self.call_notify(payload, signer=SigningKey.generate())
        self.assertEqual(raised.exception.status_code, 403)
        self.assertEqual(self.sends, [])

    def test_telegram_alert_is_a_single_complete_pwa_link(self):
        old_token, old_call, old_send = notification_service.TOKEN, notification_service.telegram_call, notification_service.telegram_send
        calls = []
        notification_service.TOKEN = "token"
        notification_service.telegram_send = self.old_send
        notification_service.telegram_call = lambda token, method, fields: calls.append((token, method, fields)) or {"message_id": 1}
        try:
            self.assertTrue(notification_service.telegram_send("chat", "MALYAVA"))
        finally:
            notification_service.TOKEN, notification_service.telegram_call, notification_service.telegram_send = old_token, old_call, old_send
        self.assertEqual(calls[0][2], {"chat_id": "chat", "text": '<a href="https://messenger.d-mash.ru/not_messenger/index.html">✉️ МАЛЯВА</a>', "parse_mode": "HTML", "disable_web_page_preview": "true"})


if __name__ == "__main__":
    unittest.main()
