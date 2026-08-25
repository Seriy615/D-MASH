"""Opaque pending-message notification trigger for the node boundary."""

from __future__ import annotations

import asyncio
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


log = logging.getLogger("dmash.notification")
SendCallback = Callable[[dict], Awaitable[bool]]


@dataclass
class PendingNotification:
    pending_id: str
    notification_handle: str
    idempotency_key: str
    created_at: int
    expires_at: int
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
        created_at: Optional[int] = None,
        expires_at: Optional[int] = None,
    ) -> str:
        if not notification_handle or len(notification_handle) > 256:
            raise ValueError("invalid notification handle")
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
                    "version": 1,
                    "notification_handle": state.notification_handle,
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
    def __init__(self, url: str, hmac_key: bytes, timeout_seconds: float = 5):
        if not url.startswith("https://"):
            raise ValueError("notification Origin must use HTTPS")
        if len(hmac_key) < 32:
            raise ValueError("notification HMAC key must be at least 32 bytes")
        self.url, self.hmac_key, self.timeout_seconds = url, hmac_key, timeout_seconds

    async def send(self, payload: dict) -> bool:
        body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        signature = hmac.new(self.hmac_key, body, hashlib.sha256).hexdigest()

        def request() -> bool:
            req = urllib.request.Request(self.url, data=body, method="POST", headers={
                "Content-Type": "application/json", "X-DMASH-Signature": signature,
            })
            try:
                with urllib.request.urlopen(req, timeout=self.timeout_seconds) as response:
                    return 200 <= response.status < 300
            except (urllib.error.URLError, TimeoutError):
                return False

        return await asyncio.to_thread(request)

    @classmethod
    def from_env(cls) -> Optional["OriginNotificationClient"]:
        url = os.getenv("DMASH_NOTIFICATION_ORIGIN_URL")
        key = os.getenv("DMASH_NOTIFICATION_HMAC_KEY")
        if not url or not key:
            return None
        return cls(url, key.encode())
