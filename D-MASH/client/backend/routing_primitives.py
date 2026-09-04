"""Protocol primitives for anonymous, node-bound routing.

All serialized objects in this module are deliberately small and contain no
account or user identifiers. Node IDs are Ed25519 public keys represented as
64 hexadecimal characters.

EntryGrant helpers delegate to the canonical Route-owned EntryGrantV1 used by
the DMP-C gateway. This prevents a second, divergent ownership protocol from
reappearing in the legacy helper surface.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from typing import Any, Mapping, Optional, Union

from nacl.signing import SigningKey, VerifyKey

if __package__:
    from .entry_grant import EntryGrantV1, route_id_for_public_key
else:
    from entry_grant import EntryGrantV1, route_id_for_public_key

BytesLike = Union[bytes, bytearray, memoryview]
DEFAULT_RESOURCE_POW_DIFFICULTY = 22


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


def generate_dnss(node_id: Union[str, BytesLike]) -> str:
    """Return fresh 128-bit DNSS entropy scoped to a validated NodeID."""
    _node_bytes(node_id)
    return secrets.token_hex(16)


def new_dnss_value() -> bytes:
    """Return a fresh random 128-bit DNSS value as bytes."""
    return secrets.token_bytes(16)


def blind_alias(secret: BytesLike, value: Union[str, BytesLike]) -> str:
    """Create a stable opaque alias using HMAC-SHA256."""
    key = bytes(secret)
    if not key:
        raise ValueError("blind secret must not be empty")
    message = value.encode("utf-8") if isinstance(value, str) else bytes(value)
    return hmac.new(key, b"D-MASH|BLIND-ALIAS|V1\0" + message,
                    hashlib.sha256).hexdigest()


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
    if isinstance(key, str):
        raw = bytes.fromhex(key) if len(key) == 64 else base64.urlsafe_b64decode(key + "=" * (-len(key) % 4))
    else:
        raw = bytes(key)
    return VerifyKey(raw)


def encode_entry_grant(grant: Mapping[str, Any]) -> str:
    """Encode the compatibility wrapper around canonical EntryGrantV1."""
    if set(grant) != {"grant", "resource"} or not isinstance(grant.get("resource"), str):
        raise ValueError("EntryGrant wrapper has an invalid schema")
    EntryGrantV1.from_dict(grant["grant"])
    return base64.urlsafe_b64encode(_canonical(grant)).rstrip(b"=").decode("ascii")


def create_entry_grant(node_id, route_signing_key, resource: str,
                       expires_at: int, *, issued_at: Optional[int] = None,
                       route_id: Optional[str] = None) -> str:
    """Create a Route-owned EntryGrant bound to ``node_id``.

    ``resource`` is retained only as compatibility metadata for callers of this
    older helper. It is not the RouteID and grants no routing authority.
    """
    nid = _node_bytes(node_id).hex()
    if not isinstance(resource, str) or not resource:
        raise ValueError("resource is required")
    signing_key = _signing_key(route_signing_key)
    canonical_route_id = route_id_for_public_key(signing_key.verify_key)
    if route_id is not None and route_id != canonical_route_id:
        raise ValueError("RouteID must equal RouteSignPublic")
    created_at = int(time.time()) if issued_at is None else issued_at
    grant = EntryGrantV1.issue(
        signing_key,
        canonical_route_id,
        expires_at,
        entry_node_id=nid,
        generation=1,
        created_at=created_at,
    )
    return encode_entry_grant({"grant": grant.to_dict(), "resource": resource})


def verify_entry_grant(encoded, route_verify_key, node_id, *, now=None,
                       route_id: Optional[str] = None) -> Optional[dict]:
    try:
        text_value = encoded.decode() if isinstance(encoded, bytes) else encoded
        raw = base64.urlsafe_b64decode(text_value + "=" * (-len(text_value) % 4))
        wrapper = json.loads(raw.decode("utf-8"))
        if set(wrapper) != {"grant", "resource"} or not isinstance(wrapper["resource"], str):
            return None
        grant = EntryGrantV1.from_dict(wrapper["grant"])
        expected_route_id = route_id_for_public_key(_verify_key(route_verify_key))
        if grant.route_id != expected_route_id:
            return None
        if route_id is not None and route_id != grant.route_id:
            return None
        nid = _node_bytes(node_id).hex()
        if not grant.verify(expected_node_id=nid, now=now):
            return None
        return {
            "v": 1,
            "node_id": grant.node_id,
            "route_id": grant.route_id,
            "generation": grant.generation,
            "issued_at": grant.created_at,
            "expires_at": grant.expires_at,
            "resource": wrapper["resource"],
        }
    except (TypeError, ValueError, KeyError, json.JSONDecodeError,
            UnicodeError, base64.binascii.Error):
        return None


def _pow_digest(node_id: bytes, route_id: str, nonce: int) -> bytes:
    if nonce < 0 or nonce >= 1 << 64:
        raise ValueError("nonce out of range")
    return hashlib.sha256(b"D-MASH|ROUTE-POW|V1\0" + node_id +
                          route_id.encode("utf-8") + nonce.to_bytes(8, "big")).digest()


def _meets(digest: bytes, difficulty: int) -> bool:
    return difficulty == 0 or (int.from_bytes(digest, "big") >> (256 - difficulty)) == 0


def create_resource_pow(node_id, resource: str,
                        difficulty: int = DEFAULT_RESOURCE_POW_DIFFICULTY) -> dict:
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
