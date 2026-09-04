"""Canonical, NodeID-bound EntryGrantV1 signing and verification.

An EntryGrant authorizes exactly one route public key.  Its RouteID is the
BLAKE3 digest of that key under this format's domain, preventing a signed grant
from being transplanted to a different route key.  NodeID is an Ed25519 verify
key encoded as 64 lowercase hexadecimal characters.
"""

from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass
from typing import Any, Mapping, Optional

import blake3
from nacl.encoding import HexEncoder
from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey


_VERSION = "EntryGrantV1"
_DOMAIN_ROUTE = b"D-MASH|ENTRY-GRANT|V1|ROUTE-ID\x00"
_DOMAIN_SIGN = b"D-MASH|ENTRY-GRANT|V1|SIGN\x00"
_REQUIRED = frozenset(("v", "node_id", "route_id", "route_public_key", "expires_at"))


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64decode(value: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError("signature must be a string")
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _verify_key(node_id: str) -> VerifyKey:
    if not isinstance(node_id, str) or len(node_id) != 64 or node_id.lower() != node_id:
        raise ValueError("node_id must be a lowercase Ed25519 public-key hex string")
    return VerifyKey(node_id, encoder=HexEncoder)


def route_id_for_public_key(route_public_key: str) -> str:
    """Compute the canonical RouteID and reject malformed Ed25519 public keys."""
    key = _verify_key(route_public_key)
    return blake3.blake3(_DOMAIN_ROUTE + bytes(key)).hexdigest()


def _canonical_payload(payload: Mapping[str, Any]) -> bytes:
    if set(payload) != _REQUIRED:
        raise ValueError("EntryGrantV1 payload fields are invalid")
    if payload.get("v") != _VERSION:
        raise ValueError("unsupported grant version")
    node_id = payload.get("node_id")
    route_public_key = payload.get("route_public_key")
    expires_at = payload.get("expires_at")
    if not isinstance(expires_at, int) or isinstance(expires_at, bool):
        raise ValueError("expires_at must be an integer Unix timestamp")
    _verify_key(node_id)
    if payload.get("route_id") != route_id_for_public_key(route_public_key):
        raise ValueError("route_id does not belong to route_public_key")
    # Fixed separators and sorted keys define the exact signed byte sequence.
    return json.dumps(dict(payload), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


@dataclass(frozen=True)
class EntryGrantV1:
    node_id: str
    route_id: str
    route_public_key: str
    expires_at: int
    signature: str
    version: str = _VERSION

    @property
    def payload(self) -> dict[str, Any]:
        return {"v": self.version, "node_id": self.node_id, "route_id": self.route_id,
                "route_public_key": self.route_public_key, "expires_at": self.expires_at}

    def canonical_bytes(self) -> bytes:
        return _canonical_payload(self.payload)

    def to_dict(self) -> dict[str, Any]:
        return {**self.payload, "signature": self.signature}

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=True)

    @classmethod
    def issue(cls, node_signing_key: SigningKey, route_public_key: str, expires_at: int) -> "EntryGrantV1":
        if not isinstance(node_signing_key, SigningKey):
            raise TypeError("node_signing_key must be nacl.signing.SigningKey")
        node_id = node_signing_key.verify_key.encode(encoder=HexEncoder).decode("ascii")
        route_id = route_id_for_public_key(route_public_key)
        unsigned = {"v": _VERSION, "node_id": node_id, "route_id": route_id,
                    "route_public_key": route_public_key, "expires_at": expires_at}
        signature = _b64encode(node_signing_key.sign(_DOMAIN_SIGN + _canonical_payload(unsigned)).signature)
        return cls(node_id=node_id, route_id=route_id, route_public_key=route_public_key,
                   expires_at=expires_at, signature=signature)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "EntryGrantV1":
        if set(value) != _REQUIRED | {"signature"}:
            raise ValueError("EntryGrantV1 fields are invalid")
        return cls(node_id=value["node_id"], route_id=value["route_id"],
                   route_public_key=value["route_public_key"], expires_at=value["expires_at"],
                   signature=value["signature"], version=value["v"])

    @classmethod
    def from_json(cls, value: str) -> "EntryGrantV1":
        return cls.from_dict(json.loads(value))

    def verify(self, expected_node_id: Optional[str] = None, now: Optional[int] = None) -> bool:
        """Verify format, node binding, ownership binding, signature, and expiry."""
        try:
            if expected_node_id is not None and self.node_id != expected_node_id:
                return False
            if self.expires_at <= (int(time.time()) if now is None else now):
                return False
            _verify_key(self.node_id).verify(_DOMAIN_SIGN + self.canonical_bytes(), _b64decode(self.signature))
            return True
        except (ValueError, TypeError, BadSignatureError, json.JSONDecodeError):
            return False
