"""Ephemeral S-TURN control-plane primitives.

This module deliberately stops at the authenticated, privacy-preserving
session boundary.  coturn/systemd installation belongs to the Node installer;
the runtime never stores permanent TURN passwords or Account identifiers.
"""

from __future__ import annotations

import base64
import binascii
import asyncio
import hashlib
import hmac
import secrets
import socket
import time
import os
from urllib.parse import urlparse
from dataclasses import dataclass, field


def _token(value: object, name: str) -> bytes:
    if not isinstance(value, str) or len(value) < 16 or len(value) > 256:
        raise ValueError(f"invalid {name}")
    return value.encode("ascii")


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


@dataclass
class _Session:
    call_hash: bytes
    expires: float
    caller_ticket: str
    callee_ticket: str
    joined: dict[str, str] = field(default_factory=dict)
    used_tickets: set[str] = field(default_factory=set)
    messages: list[tuple[str, dict]] = field(default_factory=list)
    wake: dict[str, asyncio.Event] = field(default_factory=dict)


class STurnService:
    """Short-lived TURN credentials and opaque signaling relay state."""

    def __init__(self, *, signaling_wss: str | None = None,
                 turn_urls: tuple[str, ...] = (), shared_secret: bytes | None = None,
                 clock=time.time, health_probe=None, capacity=1024,
                 max_messages=128, max_queue_bytes=1024 * 1024):
        if any(type(v) is not int or v < 1 for v in (capacity, max_messages, max_queue_bytes)):
            raise ValueError("invalid signaling capacity")
        self.capacity, self.max_messages, self.max_queue_bytes = capacity, max_messages, max_queue_bytes
        self.active_signaling_connections = 0
        self.max_signaling_connections = capacity * 2 + 32
        self._closed = False
        if signaling_wss is not None and not signaling_wss.startswith("wss://"):
            raise ValueError("signaling_wss must use wss")
        if not isinstance(turn_urls, tuple) or any(not isinstance(url, str) or not url.startswith("turn:")
                                                   for url in turn_urls):
            raise ValueError("invalid TURN URLs")
        if shared_secret is not None and (not isinstance(shared_secret, bytes) or len(shared_secret) != 32):
            raise ValueError("shared_secret must be 32 bytes")
        self.signaling_wss = signaling_wss
        self.turn_urls = turn_urls
        self._secret = shared_secret or secrets.token_bytes(32)
        self.clock = clock
        self.health_probe = health_probe or (lambda: False)
        self._sessions: dict[str, _Session] = {}

    @classmethod
    def from_env(cls) -> "STurnService | None":
        """Build the service only from an explicit, deployment-owned config.

        A configured URL is not treated as health. The probe makes a bounded
        TCP reachability check to the TURN listener; deployments can replace
        it with an authenticated allocation probe at the integration edge.
        """
        signaling = os.getenv("DMASH_SIGNALING_WSS", "").strip()
        turn_urls = tuple(item.strip() for item in os.getenv("DMASH_TURN_URLS", "").split(",") if item.strip())
        encoded_secret = os.getenv("DMASH_TURN_SHARED_SECRET_B64", "").strip()
        if not signaling or not turn_urls or not encoded_secret:
            return None
        try:
            secret = base64.b64decode(encoded_secret, validate=True)
        except (ValueError, binascii.Error):
            raise ValueError("DMASH_TURN_SHARED_SECRET_B64 must be standard Base64") from None
        if len(secret) != 32:
            raise ValueError("DMASH_TURN_SHARED_SECRET_B64 must decode to 32 bytes")

        def probe() -> bool:
            for value in turn_urls:
                parsed = urlparse(value.replace("turn:", "turn://", 1))
                if parsed.scheme != "turn" or not parsed.hostname:
                    return False
                try:
                    with socket.create_connection((parsed.hostname, parsed.port or 3478), timeout=0.4):
                        return True
                except OSError:
                    continue
            return False

        return cls(signaling_wss=signaling, turn_urls=turn_urls,
                   shared_secret=secret, health_probe=probe)

    def healthy(self) -> bool:
        if self._closed or not self.signaling_wss or not self.turn_urls:
            return False
        try:
            return bool(self.health_probe())
        except Exception:
            return False

    def descriptor(self) -> dict:
        """Return only public service metadata when the health check succeeds."""
        if not self.healthy():
            return {"can_s_turn": False}
        return {"can_s_turn": True, "signaling_wss": self.signaling_wss,
                "turn_urls": list(self.turn_urls)}

    def _prune(self) -> None:
        now = self.clock()
        for key, session in list(self._sessions.items()):
            if session.expires <= now:
                del self._sessions[key]

    def issue_turn_credentials(self, call_id: str, *, ttl: int = 300) -> dict:
        """Issue TURN REST-style credentials bound to one ephemeral call."""
        _token(call_id, "call_id")
        if type(ttl) is not int or not 1 <= ttl <= 900:
            raise ValueError("invalid TURN credential lifetime")
        if not self.healthy():
            raise RuntimeError("S-TURN service is not healthy")
        expires = int(self.clock()) + ttl
        username = f"{expires}:{_b64(secrets.token_bytes(18))}"
        # coturn TURN REST uses padded standard Base64 of HMAC-SHA1.
        password = base64.b64encode(hmac.new(self._secret, username.encode(), hashlib.sha1).digest()).decode("ascii")
        return {"username": username, "credential": password, "expires_at": expires,
                "turn_urls": list(self.turn_urls)}

    def create_session(self, call_id: str, call_secret: bytes, *, ttl: int = 900) -> dict:
        """Create scoped tickets from a call's one-time secret/verifier."""
        _token(call_id, "call_id")
        if not isinstance(call_secret, bytes) or len(call_secret) != 32:
            raise ValueError("call_secret must be 32 bytes")
        if type(ttl) is not int or not 1 <= ttl <= 3600:
            raise ValueError("invalid signaling lifetime")
        if not self.healthy():
            raise RuntimeError("S-TURN service is not healthy")
        self._prune()
        if len(self._sessions) >= self.capacity:
            raise BufferError("signaling session capacity reached")
        caller_ticket, callee_ticket = _b64(secrets.token_bytes(32)), _b64(secrets.token_bytes(32))
        key = _b64(secrets.token_bytes(32))
        self._sessions[key] = _Session(
            call_hash=hmac.new(self._secret, call_id.encode() + call_secret, hashlib.sha256).digest(),
            expires=self.clock() + ttl, caller_ticket=caller_ticket, callee_ticket=callee_ticket)
        return {"session_id": key, "caller_ticket": caller_ticket, "callee_ticket": callee_ticket,
                "expires_at": int(self.clock() + ttl), "signaling_wss": self.signaling_wss}

    def join(self, session_id: str, ticket: str, role: str) -> str:
        session = self._sessions.get(session_id)
        if session is None or session.expires <= self.clock():
            self._sessions.pop(session_id, None)
            raise PermissionError("expired signaling session")
        if not isinstance(ticket, str) or not ticket.isascii():
            raise PermissionError("invalid signaling ticket")
        if ticket in session.used_tickets:
            raise PermissionError("signaling ticket already used")
        if role == "caller" and hmac.compare_digest(ticket, session.caller_ticket):
            principal = "caller"
        elif role == "callee" and hmac.compare_digest(ticket, session.callee_ticket):
            principal = "callee"
        else:
            raise PermissionError("invalid signaling ticket")
        session.used_tickets.add(ticket)
        handle = _b64(secrets.token_bytes(32))
        session.joined[handle] = principal
        session.wake[handle] = asyncio.Event()
        return handle

    def relay(self, session_id: str, principal: str, message: dict) -> None:
        session = self._sessions.get(session_id)
        if session is None or session.expires <= self.clock() or principal not in session.joined:
            raise PermissionError("signaling session is not joined")
        if not isinstance(message, dict):
            raise ValueError("invalid signaling message")
        if set(message) - {"type", "payload"} or message.get("type") not in {"offer", "answer", "ice", "hangup"}:
            raise ValueError("invalid signaling message")
        if not isinstance(message.get("payload"), str) or len(message["payload"]) > 256 * 1024:
            raise ValueError("invalid signaling payload")
        size = len(message["payload"].encode("utf-8"))
        if (size > 256 * 1024 or len(session.messages) >= self.max_messages
                or sum(len(m["payload"].encode("utf-8")) for _, m in session.messages) + size > self.max_queue_bytes):
            raise BufferError("signaling queue capacity reached")
        session.messages.append((principal, dict(message)))
        for handle, event in session.wake.items():
            if handle != principal: event.set()

    def receive(self, session_id: str, principal: str) -> list[dict]:
        session = self._sessions.get(session_id)
        if session is None or session.expires <= self.clock():
            self._sessions.pop(session_id, None)
            raise PermissionError("signaling session is not joined")
        if principal not in session.joined:
            raise PermissionError("signaling session is not joined")
        messages = [message for sender, message in session.messages if sender != principal]
        session.messages = [(sender, message) for sender, message in session.messages if sender == principal]
        return messages

    def close_session(self, session_id: str) -> None:
        session = self._sessions.pop(session_id, None)
        if session:
            for event in session.wake.values(): event.set()

    async def wait_messages(self, session_id: str, principal: str) -> list[dict]:
        while True:
            messages = self.receive(session_id, principal)
            if messages: return messages
            session = self._sessions[session_id]
            event = session.wake[principal]
            event.clear()
            try:
                await asyncio.wait_for(event.wait(), max(0, session.expires - self.clock()))
            except TimeoutError:
                self.close_session(session_id)
                raise PermissionError('expired signaling session') from None

    def close(self) -> None:
        self._closed = True
        for sid in list(self._sessions): self.close_session(sid)
        self._secret = b""
