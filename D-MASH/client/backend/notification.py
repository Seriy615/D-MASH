"""Opaque pending-message notification trigger for the node boundary."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Awaitable, Callable, Optional
from nacl.encoding import HexEncoder
from nacl.public import PublicKey, SealedBox


log = logging.getLogger("dmash.notification")
SendCallback = Callable[[dict], Awaitable[bool]]

# Node-originated events carry no message text, sender ID, or routing locator.
# The label is the entire semantic disclosure made to the notification provider.
NOTIFICATION_EVENTS = frozenset({"MALYAVA", "INCOMING_BAZAR"})


@dataclass
class PendingNotification:
    pending_id: str
    notification_handle: str
    idempotency_key: str
    created_at: int
    expires_at: int
    event_type: str = "MALYAVA"
    task: Optional[asyncio.Task] = None
    cancelled: bool = False
    notified: bool = False


class NotificationTrigger:
    def __init__(self, sender: SendCallback, delay_seconds: float = 10, ttl_seconds: int = 3600, max_attempts: int = 3):
        self.sender = sender
        self.delay_seconds = delay_seconds
        self.ttl_seconds = ttl_seconds
        self.max_attempts = max_attempts
        self.pending: dict[str, PendingNotification] = {}

    def schedule(
        self,
        notification_handle: str,
        pending_id: Optional[str] = None,
        *,
        event_type: str = "MALYAVA",
        created_at: Optional[int] = None,
        expires_at: Optional[int] = None,
    ) -> str:
        if not notification_handle or len(notification_handle) > 256:
            raise ValueError("invalid notification handle")
        if event_type not in NOTIFICATION_EVENTS:
            raise ValueError("invalid notification event")
        pending_id = pending_id or secrets.token_hex(16)
        if pending_id in self.pending:
            return pending_id
        now = int(time.time())
        created_at = int(created_at if created_at is not None else now)
        expires_at = int(expires_at if expires_at is not None else created_at + self.ttl_seconds)
        state = PendingNotification(
            pending_id=pending_id,
            notification_handle=notification_handle,
            idempotency_key=hashlib.sha256(f"dmash-notify-v1:{pending_id}".encode()).hexdigest(),
            created_at=created_at,
            expires_at=expires_at,
            event_type=event_type,
        )
        self.pending[pending_id] = state
        state.task = asyncio.create_task(self._run(state))
        return pending_id

    def cancel(self, pending_id: str) -> bool:
        state = self.pending.get(pending_id)
        if not state or state.notified:
            return False
        state.cancelled = True
        if state.task:
            state.task.cancel()
        self.pending.pop(pending_id, None)
        return True

    async def _run(self, state: PendingNotification):
        try:
            # On restart an existing durable mailbox record may already be older
            # than the delay. Keep its stable idempotency key and notify at once.
            due_at = state.created_at + self.delay_seconds
            await asyncio.sleep(max(0, due_at - time.time()))
            for attempt in range(1, self.max_attempts + 1):
                if state.cancelled or int(time.time()) >= state.expires_at:
                    return
                payload = {
                    "version": 2,
                    "notification_handle": state.notification_handle,
                    "event_type": state.event_type,
                    "idempotency_key": state.idempotency_key,
                    "created_at": state.created_at,
                    "expires_at": state.expires_at,
                }
                if await self.sender(payload):
                    state.notified = True
                    log.info("notification accepted pending=%s", self._audit_alias(state.pending_id))
                    return
                if attempt < self.max_attempts:
                    await asyncio.sleep(min(30, 2 ** (attempt - 1)))
        except asyncio.CancelledError:
            return
        finally:
            if state.cancelled or state.notified or int(time.time()) >= state.expires_at:
                self.pending.pop(state.pending_id, None)

    @staticmethod
    def _audit_alias(value: str) -> str:
        return hashlib.sha256(value.encode()).hexdigest()[:12]


class OriginNotificationClient:
    """Encrypted Origin delivery; plaintext notification data never crosses HTTP."""
    def __init__(self, url: str, origin_public_key_hex: str, node_crypto, timeout_seconds: float = 5):
        if not url.startswith("https://"):
            raise ValueError("notification Origin must use HTTPS")
        if not node_crypto or not node_crypto.signing_key or not node_crypto.node_id:
            raise ValueError("node identity is required for Origin notifications")
        try:
            self.origin_public_key = PublicKey(origin_public_key_hex, encoder=HexEncoder)
        except Exception as exc:
            raise ValueError("DMASH_NOTIFICATION_ORIGIN_PUBLIC_KEY must be a Curve25519 public key in hex") from exc
        self.url, self.node_crypto, self.timeout_seconds = url, node_crypto, timeout_seconds

    async def send(self, payload: dict) -> bool:
        plaintext = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ciphertext = base64.b64encode(SealedBox(self.origin_public_key).encrypt(plaintext)).decode("ascii")
        transcript = f"DMP-ORIGIN-NOTIFY|1|{self.node_crypto.node_id}|{ciphertext}"
        envelope = {
            "version": 1, "node_id": self.node_crypto.node_id,
            "ciphertext": ciphertext, "signature": self.node_crypto.sign_challenge(transcript),
        }
        body = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode()

        def request() -> bool:
            req = urllib.request.Request(self.url, data=body, method="POST", headers={
                "Content-Type": "application/json",
            })
            try:
                with urllib.request.urlopen(req, timeout=self.timeout_seconds) as response:
                    return 200 <= response.status < 300
            except (urllib.error.URLError, TimeoutError):
                return False

        return await asyncio.to_thread(request)

    @classmethod
    def from_env(cls, node_crypto) -> Optional["OriginNotificationClient"]:
        url = os.getenv("DMASH_NOTIFICATION_ORIGIN_URL")
        public_key = os.getenv("DMASH_NOTIFICATION_ORIGIN_PUBLIC_KEY")
        if not url or not public_key:
            return None
        return cls(url, public_key, node_crypto)
