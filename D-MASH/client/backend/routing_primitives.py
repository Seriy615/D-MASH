"""Protocol primitives for anonymous, node-bound routing.

All serialized objects in this module are deliberately small and contain no
account or user identifiers.  Node IDs are Ed25519 public keys represented as
64 hexadecimal characters.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from typing import Any, Mapping, Optional, Union

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

BytesLike = Union[bytes, bytearray, memoryview]


def _node_bytes(node_id: Union[str, BytesLike]) -> bytes:
    if isinstance(node_id, str):
        if len(node_id) != 64:
            raise ValueError("NodeID must be 64 hexadecimal characters")
        try:
            value = bytes.fromhex(node_id)
        except ValueError as exc:
            raise ValueError("NodeID must be hexadecimal") from exc
    else:
        value = bytes(node_id)
    if len(value) != 32:
        raise ValueError("NodeID must be 32 bytes")
    return value


def validate_node_id(node_id: Union[str, BytesLike]) -> bool:
    try:
        _node_bytes(node_id)
        return True
    except (TypeError, ValueError):
        return False


def generate_dnss() -> str:
    """Return a fresh random 128-bit DNSS value as lowercase hexadecimal."""
    return secrets.token_hex(16)


def new_dnss_value() -> bytes:
    """Return a fresh random 128-bit DNSS value as bytes."""
    return secrets.token_bytes(16)


def blind_alias(secret: BytesLike, value: Union[str, BytesLike]) -> str:
    """Create a stable opaque alias using HMAC-SHA256.

    The secret is caller-owned and must not be derived from a public NodeID.
    """
    key = bytes(secret)
    if not key:
        raise ValueError("blind secret must not be empty")
    message = value.encode("utf-8") if isinstance(value, str) else bytes(value)
    return hmac.new(key, b"D-MASH|BLIND-ALIAS|V1\0" + message,
                    hashlib.sha256).hexdigest()


# Explicit protocol spelling and a convenient compatibility spelling.
hmac_blind_alias = blind_alias
create_blind_alias = blind_alias


def node_context(node_id: Union[str, BytesLike], context: Union[str, BytesLike],
                 blind_digest_callback=None) -> dict:
    """Build a NodeID-bound opaque context (legacy helper)."""
    nid = _node_bytes(node_id).hex()
    raw = context.encode() if isinstance(context, str) else bytes(context)
    if not raw:
        raise ValueError("context must not be empty")
    digest = (blind_digest_callback(nid, raw) if blind_digest_callback else
              hashlib.sha256(b"D-MASH|NODE-CONTEXT|V1\0" + _node_bytes(nid) + raw).digest())
    if isinstance(digest, str):
        digest = digest.encode()
    return {"v": 1, "node_id": nid, "context_digest": bytes(digest).hex()}


def validate_node_context(node_id, context: Mapping[str, Any],
                          blind_digest_callback=None, raw_context=None) -> bool:
    try:
        if context.get("v") != 1 or context.get("node_id") != _node_bytes(node_id).hex():
            return False
        if raw_context is None:
            return False
        expected = node_context(node_id, raw_context, blind_digest_callback)
        return hmac.compare_digest(str(context.get("context_digest", "")),
                                   expected["context_digest"])
    except (TypeError, ValueError):
        return False


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _signing_key(key) -> SigningKey:
    if isinstance(key, SigningKey):
        return key
    return SigningKey(bytes.fromhex(key) if isinstance(key, str) else bytes(key))


def _verify_key(key) -> VerifyKey:
    if isinstance(key, VerifyKey):
        return key
    return VerifyKey(bytes.fromhex(key) if isinstance(key, str) else bytes(key))


def encode_entry_grant(grant: Mapping[str, Any]) -> str:
    allowed = {"v", "node_id", "route_id", "expires_at", "issued_at", "signature"}
    if set(grant) != allowed:
        raise ValueError("EntryGrantV1 has an invalid schema")
    return base64.urlsafe_b64encode(_canonical(grant)).rstrip(b"=").decode("ascii")


def create_entry_grant(node_id, route_signing_key, resource: str,
                       expires_at: int, *, issued_at: Optional[int] = None,
                       route_id: Optional[str] = None) -> str:
    """Sign canonical EntryGrantV1, binding both NodeID and route ID."""
    nid = _node_bytes(node_id).hex()
    if not isinstance(resource, str) or not resource:
        raise ValueError("route_id/resource is required")
    rid = resource if route_id is None else route_id
    if not isinstance(rid, str) or not rid or not isinstance(expires_at, int):
        raise ValueError("route_id and integer expiry are required")
    payload = {"v": 1, "node_id": nid, "route_id": rid,
               "expires_at": expires_at,
               "issued_at": int(time.time()) if issued_at is None else issued_at}
    sig = _signing_key(route_signing_key).sign(_canonical(payload)).signature.hex()
    return encode_entry_grant({**payload, "signature": sig})


def verify_entry_grant(encoded, route_verify_key, node_id, *, now=None,
                       route_id: Optional[str] = None) -> Optional[dict]:
    try:
        text = encoded.decode() if isinstance(encoded, bytes) else encoded
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
        grant = json.loads(raw.decode("utf-8"))
        if set(grant) != {"v", "node_id", "route_id", "expires_at", "issued_at", "signature"}:
            return None
        nid = _node_bytes(node_id).hex()
        if grant["v"] != 1 or grant["node_id"] != nid:
            return None
        if route_id is not None and grant["route_id"] != route_id:
            return None
        if not isinstance(grant["route_id"], str) or not isinstance(grant["expires_at"], int):
            return None
        if (now if now is not None else int(time.time())) >= grant["expires_at"]:
            return None
        payload = {k: grant[k] for k in ("v", "node_id", "route_id", "expires_at", "issued_at")}
        sig = bytes.fromhex(grant["signature"])
        _verify_key(route_verify_key).verify(_canonical(payload), sig)
        return {**payload, "resource": payload["route_id"]}
    except (TypeError, ValueError, KeyError, json.JSONDecodeError, BadSignatureError,
            UnicodeError, base64.binascii.Error):
        return None


def _pow_digest(node_id: bytes, route_id: str, nonce: int) -> bytes:
    if nonce < 0 or nonce >= 1 << 64:
        raise ValueError("nonce out of range")
    return hashlib.sha256(b"D-MASH|ROUTE-POW|V1\0" + node_id +
                          route_id.encode("utf-8") + nonce.to_bytes(8, "big")).digest()


def _meets(digest: bytes, difficulty: int) -> bool:
    return difficulty == 0 or (int.from_bytes(digest, "big") >> (256 - difficulty)) == 0


def create_resource_pow(node_id, resource: str, difficulty: int = 8) -> dict:
    nid = _node_bytes(node_id)
    if not isinstance(resource, str) or not resource or not isinstance(difficulty, int) or not 0 <= difficulty <= 256:
        raise ValueError("invalid resource or difficulty")
    nonce = 0
    while True:
        digest = _pow_digest(nid, resource, nonce)
        if _meets(digest, difficulty):
            return {"v": 1, "node_id": nid.hex(), "resource": resource,
                    "difficulty": difficulty, "nonce": nonce, "digest": digest.hex()}
        nonce += 1


def verify_resource_pow(proof: Mapping[str, Any], node_id, *, difficulty=None) -> bool:
    try:
        nid = _node_bytes(node_id)
        d = proof["difficulty"] if difficulty is None else difficulty
        if proof.get("v") != 1 or proof.get("node_id") != nid.hex() or not isinstance(d, int) or not 0 <= d <= 256:
            return False
        if not isinstance(proof["resource"], str) or not isinstance(proof["nonce"], int):
            return False
        digest = _pow_digest(nid, proof["resource"], proof["nonce"])
        return hmac.compare_digest(str(proof.get("digest", "")), digest.hex()) and _meets(digest, d)
    except (KeyError, TypeError, ValueError, OverflowError):
        return False

create_pow = create_resource_pow
verify_pow = verify_resource_pow
sign_entry_grant = create_entry_grant
verify_grant = verify_entry_grant
