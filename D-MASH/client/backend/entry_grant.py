"""Route-owned, NodeID-bound EntryGrantV1 signing and verification.

Security invariant: ``RouteID`` is the Ed25519 route signing public key itself
(base64url, no padding).  The Entry Node is only a bound destination in the
signed transcript; the Node key is never an authority for a Route.  Therefore
an Entry Node cannot manufacture an EntryGrant for somebody else's RouteID.

``route_public_key`` is retained as signed compatibility metadata because older
Python call sites exposed it separately.  It is never used as the ownership
verification key.  New callers should set it to the same key as ``route_id``.
"""

from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass
from typing import Any, Mapping, Optional

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey


_VERSION = "EntryGrantV1"
_DOMAIN_SIGN = b"D-MASH|ENTRY_GRANT|V1\x00"
_REQUIRED = frozenset((
    "v", "node_id", "route_id", "route_public_key",
    "generation", "created_at", "expires_at",
))


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64decode(value: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise ValueError("base64url value must be a non-empty string")
    try:
        raw = base64.b64decode(
            value.replace("-", "+").replace("_", "/") + "=" * (-len(value) % 4),
            validate=True,
        )
    except (ValueError, base64.binascii.Error) as exc:
        raise ValueError("invalid base64url value") from exc
    if _b64encode(raw) != value:
        raise ValueError("base64url value is not canonical")
    return raw


def _node_bytes(node_id: str) -> bytes:
    if not isinstance(node_id, str) or len(node_id) != 64 or node_id.lower() != node_id:
        raise ValueError("node_id must be a lowercase Ed25519 public-key hex string")
    try:
        raw = bytes.fromhex(node_id)
    except ValueError as exc:
        raise ValueError("node_id must be hexadecimal") from exc
    if len(raw) != 32:
        raise ValueError("node_id must encode 32 bytes")
    return raw


def _route_key_bytes(value: str) -> bytes:
    """Decode a 32-byte Ed25519 public key from canonical hex or base64url."""
    if not isinstance(value, str) or not value:
        raise ValueError("route public key must be a non-empty string")
    if len(value) == 64 and value.lower() == value:
        try:
            raw = bytes.fromhex(value)
        except ValueError:
            raw = b""
        if len(raw) == 32:
            return raw
    raw = _b64decode(value)
    if len(raw) != 32:
        raise ValueError("route public key must encode 32 bytes")
    return raw


def route_id_for_public_key(route_public_key: str | bytes | bytearray | memoryview | VerifyKey) -> str:
    """Return the canonical RouteID: the Ed25519 public key itself, base64url."""
    if isinstance(route_public_key, VerifyKey):
        raw = bytes(route_public_key)
    elif isinstance(route_public_key, (bytes, bytearray, memoryview)):
        raw = bytes(route_public_key)
    else:
        raw = _route_key_bytes(route_public_key)
    if len(raw) != 32:
        raise ValueError("route public key must encode 32 bytes")
    return _b64encode(raw)


def _u32(value: int) -> bytes:
    return value.to_bytes(4, "big", signed=False)


def _u64(value: int) -> bytes:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < (1 << 64):
        raise ValueError("integer field is outside uint64 range")
    return value.to_bytes(8, "big", signed=False)


def _field(value: bytes) -> bytes:
    return _u32(len(value)) + value


def _canonical_payload(payload: Mapping[str, Any]) -> bytes:
    if set(payload) != _REQUIRED:
        raise ValueError("EntryGrantV1 payload fields are invalid")
    if payload.get("v") != _VERSION:
        raise ValueError("unsupported grant version")

    route_id = payload.get("route_id")
    route_public_key = payload.get("route_public_key")
    node_id = payload.get("node_id")
    generation = payload.get("generation")
    created_at = payload.get("created_at")
    expires_at = payload.get("expires_at")

    route_bytes = _route_key_bytes(route_id)
    compatibility_key = _route_key_bytes(route_public_key)
    node_bytes = _node_bytes(node_id)
    if route_id != _b64encode(route_bytes):
        raise ValueError("route_id must be canonical base64url RouteSignPublic")
    if not isinstance(generation, int) or isinstance(generation, bool) or generation < 1:
        raise ValueError("generation must be a positive integer")
    if not isinstance(created_at, int) or isinstance(created_at, bool) or created_at < 0:
        raise ValueError("created_at must be a non-negative integer Unix timestamp")
    if not isinstance(expires_at, int) or isinstance(expires_at, bool) or expires_at <= created_at:
        raise ValueError("expires_at must be later than created_at")

    return b"".join((
        _DOMAIN_SIGN,
        _field(route_bytes),
        _field(node_bytes),
        _field(compatibility_key),
        _u64(generation),
        _u64(created_at),
        _u64(expires_at),
    ))


@dataclass(frozen=True)
class EntryGrantV1:
    # Field order intentionally preserves the old positional constructor used
    # by a few tests/callers.  New security metadata is appended with defaults.
    node_id: str
    route_id: str
    route_public_key: str
    expires_at: int
    signature: str
    version: str = _VERSION
    generation: int = 1
    created_at: int = 0

    @property
    def entry_node_id(self) -> str:
        return self.node_id

    @property
    def payload(self) -> dict[str, Any]:
        return {
            "v": self.version,
            "node_id": self.node_id,
            "route_id": self.route_id,
            "route_public_key": self.route_public_key,
            "generation": self.generation,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
        }

    def canonical_bytes(self) -> bytes:
        return _canonical_payload(self.payload)

    def to_dict(self) -> dict[str, Any]:
        return {**self.payload, "signature": self.signature}

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=True)

    @classmethod
    def issue(
        cls,
        route_signing_key: SigningKey,
        route_public_key: str,
        expires_at: int,
        *,
        entry_node_id: Optional[str] = None,
        generation: int = 1,
        created_at: int = 0,
    ) -> "EntryGrantV1":
        """Issue a Route-owned grant.

        New callers MUST pass ``entry_node_id`` and should pass the route's own
        public key as ``route_public_key``.  For compatibility with older unit
        call sites, omission of ``entry_node_id`` self-binds the grant to the
        signing key.  That compatibility mode is still safe: it can authorize
        only ``RouteID == signing_key.verify_key`` and therefore cannot mint a
        grant for an unrelated RouteID.
        """
        if not isinstance(route_signing_key, SigningKey):
            raise TypeError("route_signing_key must be nacl.signing.SigningKey")
        signing_public = bytes(route_signing_key.verify_key)
        route_id = _b64encode(signing_public)
        _route_key_bytes(route_public_key)  # validate compatibility metadata

        if entry_node_id is None:
            node_id = signing_public.hex()
        else:
            node_id = _node_bytes(entry_node_id).hex()
            if _route_key_bytes(route_public_key) != signing_public:
                raise ValueError("new EntryGrant callers must bind route_public_key to RouteSignPublic")

        unsigned = {
            "v": _VERSION,
            "node_id": node_id,
            "route_id": route_id,
            "route_public_key": route_public_key,
            "generation": generation,
            "created_at": created_at,
            "expires_at": expires_at,
        }
        signature = _b64encode(route_signing_key.sign(_canonical_payload(unsigned)).signature)
        return cls(
            node_id=node_id,
            route_id=route_id,
            route_public_key=route_public_key,
            expires_at=expires_at,
            signature=signature,
            generation=generation,
            created_at=created_at,
        )

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "EntryGrantV1":
        if set(value) != _REQUIRED | {"signature"}:
            raise ValueError("EntryGrantV1 fields are invalid")
        return cls(
            node_id=value["node_id"],
            route_id=value["route_id"],
            route_public_key=value["route_public_key"],
            expires_at=value["expires_at"],
            signature=value["signature"],
            version=value["v"],
            generation=value["generation"],
            created_at=value["created_at"],
        )

    @classmethod
    def from_json(cls, value: str) -> "EntryGrantV1":
        return cls.from_dict(json.loads(value))

    def verify(self, expected_node_id: Optional[str] = None, now: Optional[int] = None) -> bool:
        """Verify Route ownership, Entry Node binding, transcript, and expiry."""
        try:
            canonical_node = _node_bytes(self.node_id).hex()
            if expected_node_id is not None and canonical_node != _node_bytes(expected_node_id).hex():
                return False
            current_time = int(time.time()) if now is None else int(now)
            if self.expires_at <= current_time:
                return False
            route_key = VerifyKey(_route_key_bytes(self.route_id))
            route_key.verify(self.canonical_bytes(), _b64decode(self.signature))
            return True
        except (ValueError, TypeError, BadSignatureError, json.JSONDecodeError, OverflowError):
            return False
