"""Durable, node-local registry for DNSS-to-verified-EntryGrant registrations.

The registry deliberately stores only a keyed, node-scoped blind hash of a DNSS.
It is a standalone persistence primitive: gateway/request wiring belongs to callers.
"""

from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Optional, Union

from .dnss import node_blind_hash
from .entry_grant import EntryGrantV1


DNSS = Union[bytes, bytearray, memoryview]


@dataclass(frozen=True)
class RegistrationRecord:
    """The non-secret, verified data held for one DNSS registration."""

    node_id: str
    route_id: str
    route_public_key: str
    expires_at: int
    signature: str
    registered_at: int

    @property
    def grant(self) -> EntryGrantV1:
        return EntryGrantV1(
            node_id=self.node_id,
            route_id=self.route_id,
            route_public_key=self.route_public_key,
            expires_at=self.expires_at,
            signature=self.signature,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "route_id": self.route_id,
            "route_public_key": self.route_public_key,
            "expires_at": self.expires_at,
            "signature": self.signature,
            "registered_at": self.registered_at,
        }


class RegistrationRegistry:
    """A SQLite-backed registry scoped cryptographically to one local node.

    ``node_crypto`` must be a loaded ``NodeCryptoManager`` (or compatible
    object) exposing ``node_id`` and its stable 32-byte ``secret_salt``.  The
    latter is used only in memory as the BLAKE3 key.  Consequently a database
    contains neither the raw DNSS nor the blind key, and cannot be reused by a
    different node identity.
    """

    def __init__(self, database_path: Union[str, Path], node_crypto: Any):
        self.database_path = str(database_path)
        self._node_id, self._blind_key = self._node_material(node_crypto)
        self._connection = sqlite3.connect(self.database_path)
        self._connection.row_factory = sqlite3.Row
        self._initialize()

    @staticmethod
    def _node_material(node_crypto: Any) -> tuple[str, bytes]:
        node_id = getattr(node_crypto, "node_id", None)
        blind_key = getattr(node_crypto, "secret_salt", None)
        if not isinstance(node_id, str) or not node_id:
            raise ValueError("node_crypto must expose a loaded node_id")
        if not isinstance(blind_key, bytes) or len(blind_key) != 32:
            raise ValueError("node_crypto must expose a stable 32-byte secret_salt")
        return node_id, blind_key

    def _initialize(self) -> None:
        with self._connection:
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS registration_registry_node (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    node_id TEXT NOT NULL
                )
                """
            )
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS registration_registry (
                    dnss_hash TEXT PRIMARY KEY,
                    node_id TEXT NOT NULL,
                    route_id TEXT NOT NULL,
                    route_public_key TEXT NOT NULL,
                    expires_at INTEGER NOT NULL,
                    signature TEXT NOT NULL,
                    registered_at INTEGER NOT NULL
                )
                """
            )
            row = self._connection.execute(
                "SELECT node_id FROM registration_registry_node WHERE singleton = 1"
            ).fetchone()
            if row is None:
                self._connection.execute(
                    "INSERT INTO registration_registry_node (singleton, node_id) VALUES (1, ?)",
                    (self._node_id,),
                )
            elif row["node_id"] != self._node_id:
                raise ValueError("registration registry belongs to a different node")

    @staticmethod
    def _dnss_bytes(dnss: DNSS) -> bytes:
        if not isinstance(dnss, (bytes, bytearray, memoryview)):
            raise TypeError("dnss must be a 16-byte value")
        value = bytes(dnss)
        if len(value) != 16:
            raise ValueError("dnss must be exactly 16 bytes")
        return value

    def blind_hash(self, dnss: DNSS) -> str:
        """Return the stable, node-scoped opaque index for a raw DNSS."""
        return node_blind_hash(self._node_id, self._blind_key, self._dnss_bytes(dnss))

    @staticmethod
    def _coerce_grant(grant: Union[EntryGrantV1, Mapping[str, Any]]) -> EntryGrantV1:
        if isinstance(grant, EntryGrantV1):
            return grant
        if isinstance(grant, Mapping):
            return EntryGrantV1.from_dict(grant)
        raise TypeError("grant must be EntryGrantV1 or its dictionary form")

    def register(
        self, dnss: DNSS, grant: Union[EntryGrantV1, Mapping[str, Any]], *, now: Optional[int] = None
    ) -> RegistrationRecord:
        """Verify and atomically register a grant for ``dnss``.

        The grant must be signed by this exact registry node and still valid at
        ``now``.  Re-registering the same DNSS replaces its non-secret metadata.
        """
        current_time = int(time.time()) if now is None else int(now)
        entry_grant = self._coerce_grant(grant)
        if not entry_grant.verify(expected_node_id=self._node_id, now=current_time):
            raise ValueError("EntryGrant is invalid, expired, or belongs to another node")
        record = RegistrationRecord(
            node_id=entry_grant.node_id,
            route_id=entry_grant.route_id,
            route_public_key=entry_grant.route_public_key,
            expires_at=entry_grant.expires_at,
            signature=entry_grant.signature,
            registered_at=current_time,
        )
        with self._connection:
            self._connection.execute(
                """
                INSERT INTO registration_registry
                    (dnss_hash, node_id, route_id, route_public_key, expires_at, signature, registered_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(dnss_hash) DO UPDATE SET
                    node_id = excluded.node_id,
                    route_id = excluded.route_id,
                    route_public_key = excluded.route_public_key,
                    expires_at = excluded.expires_at,
                    signature = excluded.signature,
                    registered_at = excluded.registered_at
                """,
                (
                    self.blind_hash(dnss),
                    record.node_id,
                    record.route_id,
                    record.route_public_key,
                    record.expires_at,
                    record.signature,
                    record.registered_at,
                ),
            )
        return record

    def lookup(self, dnss: DNSS, *, now: Optional[int] = None) -> Optional[RegistrationRecord]:
        """Return current verified metadata, deleting expired or invalid rows."""
        current_time = int(time.time()) if now is None else int(now)
        dnss_hash = self.blind_hash(dnss)
        row = self._connection.execute(
            "SELECT node_id, route_id, route_public_key, expires_at, signature, registered_at "
            "FROM registration_registry WHERE dnss_hash = ?",
            (dnss_hash,),
        ).fetchone()
        if row is None:
            return None
        record = RegistrationRecord(**dict(row))
        if not record.grant.verify(expected_node_id=self._node_id, now=current_time):
            with self._connection:
                self._connection.execute("DELETE FROM registration_registry WHERE dnss_hash = ?", (dnss_hash,))
            return None
        return record

    def purge_expired(self, *, now: Optional[int] = None) -> int:
        """Delete rows whose grant expiry has passed and return their count."""
        current_time = int(time.time()) if now is None else int(now)
        with self._connection:
            cursor = self._connection.execute(
                "DELETE FROM registration_registry WHERE expires_at <= ?", (current_time,)
            )
        return cursor.rowcount

    def close(self) -> None:
        self._connection.close()

    def __enter__(self) -> "RegistrationRegistry":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
