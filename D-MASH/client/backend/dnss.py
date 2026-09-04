"""DNSS node-scoped entropy and blind-hash primitives.

This module deliberately has no dependency on the running node or its storage.  A
caller supplies the node identity and (for stable hashes) its node-local blind
key.  DNSS values are always 128 bits obtained from PyNaCl's OS CSPRNG.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from typing import Union

import blake3
import nacl.utils


_DOMAIN_ENTROPY = b"D-MASH|DNSS|V1|ENTROPY\x00"
_DOMAIN_BLIND = b"D-MASH|DNSS|V1|NODE-BLIND\x00"
BytesLike = Union[str, bytes]


def _as_bytes(value: BytesLike, name: str) -> bytes:
    if isinstance(value, str):
        return value.encode("utf-8")
    if isinstance(value, bytes):
        return value
    raise TypeError(f"{name} must be str or bytes")


def _node_id_bytes(node_id: BytesLike) -> bytes:
    value = _as_bytes(node_id, "node_id")
    if not value:
        raise ValueError("node_id must not be empty")
    return value


def new_dnss_value() -> bytes:
    """Return exactly 128 cryptographically random bits."""
    return nacl.utils.random(16)


def node_blind_hash(node_id: BytesLike, blind_key: bytes, value: BytesLike) -> str:
    """Return a domain-separated, node-bound keyed BLAKE3 digest (hex).

    ``blind_key`` is deliberately caller-owned so this helper neither persists
    secrets nor silently derives one from public NodeID material.
    """
    if not isinstance(blind_key, bytes) or len(blind_key) != 32:
        raise ValueError("blind_key must be exactly 32 bytes")
    node = _node_id_bytes(node_id)
    data = _as_bytes(value, "value")
    payload = _DOMAIN_BLIND + len(node).to_bytes(2, "big") + node + data
    return blake3.blake3(payload, key=blind_key).hexdigest()


@dataclass(frozen=True)
class DNSSContext:
    """An isolated entropy context for one node identity.

    The context does not make entropy deterministic: every ``token`` call uses
    the OS CSPRNG.  It does retain a 32-byte blind key solely for callers that
    need stable, node-scoped opaque indexes during the lifetime of the context.
    Supply ``blind_key`` when stable hashes across recreated contexts are needed.
    """

    node_id: BytesLike
    blind_key: bytes = field(default_factory=lambda: nacl.utils.random(32), repr=False)

    def __post_init__(self) -> None:
        _node_id_bytes(self.node_id)
        if not isinstance(self.blind_key, bytes) or len(self.blind_key) != 32:
            raise ValueError("blind_key must be exactly 32 bytes")

    def token(self) -> bytes:
        """Return a fresh 16-byte (128-bit) CSPRNG value."""
        return new_dnss_value()

    def token_b64(self) -> str:
        return base64.urlsafe_b64encode(self.token()).decode("ascii").rstrip("=")

    def blind_hash(self, value: BytesLike) -> str:
        return node_blind_hash(self.node_id, self.blind_key, value)
