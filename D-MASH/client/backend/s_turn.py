"""Ephemeral S-TURN control-plane primitives.

This module deliberately stops at the authenticated, privacy-preserving
session boundary.  coturn/systemd installation belongs to the Node installer;
the runtime never stores permanent TURN passwords or Account identifiers.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time
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
    joined: set[str] = field(default_factory=set)
    used_tickets: set[str] = field(default_factory=set)
    messages: list[tuple[str, dict]] = field(default_factory=list)


class STurnService:
    """Short-lived TURN credentials and opaque signaling relay state."""

    def __init__(self, *, signaling_wss: str | None = None,
                 turn_urls: tuple[str, ...] = (), shared_secret: bytes | None = None,
                 clock=time.time, health_probe=None):
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
        self.health_probe = health_probe or (lambda: True)
        self._sessions: dict[str, _Session] = {}

    def healthy(self) -> bool:
        if not self.signaling_wss or not self.turn_urls:
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
        password = _b64(hmac.new(self._secret, username.encode(), hashlib.sha256).digest())
        return {"username": username, "credential": password, "expires_at": expires,
                "turn_urls": list(self.turn_urls)}

    def create_session(self, call_id: str, call_secret: bytes, *, ttl: int = 900) -> dict:
        """Create caller/callee tickets; the secret never leaves this API."""
        _token(call_id, "call_id")
        if not isinstance(call_secret, bytes) or len(call_secret) != 32:
            raise ValueError("call_secret must be 32 bytes")
        if type(ttl) is not int or not 1 <= ttl <= 3600:
            raise ValueError("invalid signaling lifetime")
        if not self.healthy():
            raise RuntimeError("S-TURN service is not healthy")
        self._prune()
        caller_ticket, callee_ticket = _b64(secrets.token_bytes(32)), _b64(secrets.token_bytes(32))
        key = _b64(secrets.token_bytes(32))
        self._sessions[key] = _Session(
            call_hash=hmac.new(self._secret, call_id.encode(), hashlib.sha256).digest(),
            expires=self.clock() + ttl, caller_ticket=caller_ticket, callee_ticket=callee_ticket)
        return {"session_id": key, "caller_ticket": caller_ticket, "callee_ticket": callee_ticket,
                "expires_at": int(self.clock() + ttl), "signaling_wss": self.signaling_wss}

    def join(self, session_id: str, ticket: str, role: str) -> str:
        session = self._sessions.get(session_id)
        if session is None or session.expires <= self.clock():
            self._sessions.pop(session_id, None)
            raise PermissionError("expired signaling session")
        if ticket in session.used_tickets:
            raise PermissionError("signaling ticket already used")
        if role == "caller" and hmac.compare_digest(ticket, session.caller_ticket):
            principal = "caller"
        elif role == "callee" and hmac.compare_digest(ticket, session.callee_ticket):
            principal = "callee"
        else:
            raise PermissionError("invalid signaling ticket")
        session.used_tickets.add(ticket)
        session.joined.add(principal)
        return principal

    def relay(self, session_id: str, principal: str, message: dict) -> None:
        session = self._sessions.get(session_id)
        if session is None or session.expires <= self.clock() or principal not in session.joined:
            raise PermissionError("signaling session is not joined")
        if principal not in {"caller", "callee"} or not isinstance(message, dict):
            raise ValueError("invalid signaling message")
        if set(message) - {"type", "payload"} or message.get("type") not in {"offer", "answer", "ice", "hangup"}:
            raise ValueError("invalid signaling message")
        if not isinstance(message.get("payload"), str) or len(message["payload"]) > 256 * 1024:
            raise ValueError("invalid signaling payload")
        session.messages.append((principal, dict(message)))

    def receive(self, session_id: str, principal: str) -> list[dict]:
        session = self._sessions.get(session_id)
        if session is None or session.expires <= self.clock() or principal not in session.joined:
            self._sessions.pop(session_id, None)
            raise PermissionError("signaling session is not joined")
        messages = [message for sender, message in session.messages if sender != principal]
        session.messages = [(sender, message) for sender, message in session.messages if sender == principal]
        return messages

    def close_session(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)

    def close(self) -> None:
        self._sessions.clear()
        self._secret = b""
