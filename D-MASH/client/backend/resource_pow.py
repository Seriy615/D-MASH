"""Small node-bound proof-of-work helpers for opaque resources."""

from __future__ import annotations

import os
import hmac
import time
from typing import Union

import blake3

BytesLike = Union[str, bytes]
_DOMAIN = b"D-MASH|RESOURCE-POW|V1\x00"
_ACTIVATION_DOMAIN = b"D-MASH|ACTIVATION-POW|V1\x00"
MIN_ACTIVATION_DIFFICULTY = 20
MAX_ACTIVATION_DIFFICULTY = 24
DEFAULT_ACTIVATION_DIFFICULTY = 22
MAX_ACTIVATION_VALIDITY_SECONDS = 3600


def activation_pow_difficulty() -> int:
    """Return the configured safe activation difficulty.

    Invalid or out-of-range configuration is deliberately ignored rather than
    weakening the registration gate.
    """
    try:
        configured = int(os.environ.get("DMASH_ACTIVATION_POW_DIFFICULTY", "22"))
    except (TypeError, ValueError):
        return DEFAULT_ACTIVATION_DIFFICULTY
    return min(MAX_ACTIVATION_DIFFICULTY, max(MIN_ACTIVATION_DIFFICULTY, configured))


def _bytes(value: BytesLike, name: str) -> bytes:
    if isinstance(value, str):
        return value.encode("utf-8")
    if isinstance(value, bytes):
        return value
    raise TypeError(f"{name} must be str or bytes")


def _node_id(node_id: BytesLike) -> bytes:
    node = _bytes(node_id, "node_id")
    if not node:
        raise ValueError("node_id must not be empty")
    return node


def resource_pow_digest(node_id: BytesLike, resource: BytesLike, nonce: int) -> bytes:
    """Return the PoW digest, binding challenge work to the supplied NodeID."""
    if not isinstance(nonce, int) or isinstance(nonce, bool) or nonce < 0 or nonce >= 2**64:
        raise ValueError("nonce must be an unsigned 64-bit integer")
    node, item = _node_id(node_id), _bytes(resource, "resource")
    payload = _DOMAIN + len(node).to_bytes(2, "big") + node + len(item).to_bytes(4, "big") + item + nonce.to_bytes(8, "big")
    return blake3.blake3(payload).digest()


def _leading_zero_bits(digest: bytes) -> int:
    bits = 0
    for byte in digest:
        if byte == 0:
            bits += 8
        else:
            return bits + 8 - byte.bit_length()
    return bits


def verify_resource_pow(node_id: BytesLike, resource: BytesLike, nonce: int, difficulty: int) -> bool:
    """Validate an unsigned nonce against a node-bound leading-zero-bit target."""
    if not isinstance(difficulty, int) or isinstance(difficulty, bool) or not 0 <= difficulty <= 256:
        return False
    try:
        return _leading_zero_bits(resource_pow_digest(node_id, resource, nonce)) >= difficulty
    except (TypeError, ValueError):
        return False


def mine_resource_pow(node_id: BytesLike, resource: BytesLike, difficulty: int, start_nonce: int = 0) -> int:
    """Find a nonce locally. Intended for bounded, low-difficulty challenges."""
    if not isinstance(difficulty, int) or isinstance(difficulty, bool) or not 0 <= difficulty <= 256:
        raise ValueError("difficulty must be between 0 and 256")
    if not isinstance(start_nonce, int) or isinstance(start_nonce, bool) or not 0 <= start_nonce < 2**64:
        raise ValueError("start_nonce must be an unsigned 64-bit integer")
    for nonce in range(start_nonce, 2**64):
        if verify_resource_pow(node_id, resource, nonce, difficulty):
            return nonce
    raise RuntimeError("nonce space exhausted")


def activation_pow_digest(node_id: BytesLike, activation_type: str,
                          device_transport_key: BytesLike, resource: BytesLike,
                          nonce: int, expires_at: int) -> bytes:
    """Digest for a one-time activation proof.

    The device key and expiry are deliberately in the work transcript: a proof
    cannot be moved between devices, activation kinds, resources, or windows.
    """
    if not isinstance(activation_type, str) or activation_type not in {"DNSS", "ENTRY_GRANT"}:
        raise ValueError("invalid activation type")
    if (not isinstance(expires_at, int) or isinstance(expires_at, bool) or
            not 0 <= expires_at < 2**64):
        raise ValueError("expires_at must be an unsigned 64-bit integer")
    node = _node_id(node_id)
    key = _bytes(device_transport_key, "device_transport_key")
    item = _bytes(resource, "resource")
    if not key or not item:
        raise ValueError("device_transport_key and resource must not be empty")
    resource_pow_digest(node, b"", nonce)  # validate nonce without duplicating rules
    payload = (_ACTIVATION_DOMAIN + len(node).to_bytes(2, "big") + node +
               activation_type.encode("ascii") + b"\x00" +
               len(key).to_bytes(2, "big") + key +
               len(item).to_bytes(4, "big") + item + expires_at.to_bytes(8, "big") +
               nonce.to_bytes(8, "big"))
    return blake3.blake3(payload).digest()


def verify_activation_pow(node_id: BytesLike, activation_type: str,
                          device_transport_key: BytesLike, resource: BytesLike,
                          nonce: int, expires_at: int, difficulty: int,
                          digest: BytesLike, *, now: int | None = None) -> bool:
    """Validate an activation proof, including its exact digest and expiry."""
    if not isinstance(difficulty, int) or isinstance(difficulty, bool) or not 0 <= difficulty <= 256:
        return False
    current_time = int(time.time()) if now is None else now
    if not isinstance(current_time, int) or isinstance(current_time, bool):
        return False
    if (not isinstance(expires_at, int) or expires_at <= current_time or
            expires_at > current_time + MAX_ACTIVATION_VALIDITY_SECONDS):
        return False
    try:
        expected = activation_pow_digest(node_id, activation_type, device_transport_key,
                                          resource, nonce, expires_at)
        supplied = bytes.fromhex(digest) if isinstance(digest, str) else bytes(digest)
        # Digest equality authenticates the complete node/device/resource-bound
        # transcript. Use a constant-time comparison at this boundary.
        return hmac.compare_digest(supplied, expected) and _leading_zero_bits(expected) >= difficulty
    except (TypeError, ValueError, OverflowError):
        return False


def mine_activation_pow(node_id: BytesLike, activation_type: str,
                        device_transport_key: BytesLike, resource: BytesLike,
                        expires_at: int, difficulty: int | None = None,
                        start_nonce: int = 0) -> dict[str, object]:
    """Mine and return the wire proof for a new activation."""
    if difficulty is None:
        difficulty = activation_pow_difficulty()
    if not isinstance(difficulty, int) or isinstance(difficulty, bool) or not 0 <= difficulty <= 256:
        raise ValueError("difficulty must be between 0 and 256")
    if not isinstance(start_nonce, int) or isinstance(start_nonce, bool) or not 0 <= start_nonce < 2**64:
        raise ValueError("start_nonce must be an unsigned 64-bit integer")
    for nonce in range(start_nonce, 2**64):
        digest = activation_pow_digest(node_id, activation_type, device_transport_key,
                                       resource, nonce, expires_at)
        if _leading_zero_bits(digest) >= difficulty:
            # Proofs are protocol objects, not internal hash inputs: never put
            # bytes in the returned mapping because callers send it via JSON.
            # Hex is the canonical textual form for binary resources; textual
            # resources (such as RouteID) are already wire-safe.
            wire_resource = resource.hex() if isinstance(resource, bytes) else resource
            return {"v": 1, "type": activation_type, "resource": wire_resource,
                    "nonce": nonce, "expires_at": expires_at,
                    "difficulty": difficulty, "digest": digest.hex()}
    raise RuntimeError("nonce space exhausted")
