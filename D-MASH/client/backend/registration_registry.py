"""Durable, node-local registry for DNSS-to-verified EntryGrant registrations.

The registry stores only a keyed, node-scoped blind hash of DNSS.  EntryGrant
ownership is verified by the Route signing key (RouteID); the local NodeID is
only a signed binding target and never a Route authority.

One DEVICE<->NODE DNSS can authorize multiple Routes.  The durable key is
therefore ``(blind_dnss, route_id)``, never a per-Route DNSS.  This preserves the
protocol invariant that DNSS identifies a device/node registration context and
RouteID identifies an independently owned routing resource.
"""

from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Optional, Union

if __package__:
    from .dnss import node_blind_hash
    from .entry_grant import EntryGrantV1
else:
    from dnss import node_blind_hash
    from entry_grant import EntryGrantV1


DNSS = Union[bytes, bytearray, memoryview]


@dataclass(frozen=True)
class RegistrationRecord:
    node_id: str
    route_id: str
    route_public_key: str
    expires_at: int
    signature: str
    registered_at: int
    generation: int = 1
    created_at: int = 0

    @property
    def grant(self) -> EntryGrantV1:
        return EntryGrantV1(
            node_id=self.node_id,
            route_id=self.route_id,
            route_public_key=self.route_public_key,
            expires_at=self.expires_at,
            signature=self.signature,
            generation=self.generation,
            created_at=self.created_at,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "route_id": self.route_id,
            "route_public_key": self.route_public_key,
            "generation": self.generation,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "signature": self.signature,
            "registered_at": self.registered_at,
        }


class RegistrationRegistry:
    """SQLite registry cryptographically scoped to one local Node."""

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
        return node_id.lower(), blind_key

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

            # If an old one-row-per-DNSS table exists, add the metadata columns
            # first and then migrate to a composite primary key. SQLite cannot
            # ALTER a primary key in place, so use an atomic copy/rename.
            exists = self._connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='registration_registry'"
            ).fetchone()
            if exists:
                columns = {
                    row[1]: row for row in self._connection.execute(
                        "PRAGMA table_info(registration_registry)"
                    ).fetchall()
                }
                if "generation" not in columns:
                    self._connection.execute(
                        "ALTER TABLE registration_registry ADD COLUMN generation INTEGER NOT NULL DEFAULT 1"
                    )
                if "created_at" not in columns:
                    self._connection.execute(
                        "ALTER TABLE registration_registry ADD COLUMN created_at INTEGER NOT NULL DEFAULT 0"
                    )
                pk_columns = [
                    row[1] for row in sorted(
                        self._connection.execute("PRAGMA table_info(registration_registry)").fetchall(),
                        key=lambda item: item[5] or 99,
                    ) if row[5]
                ]
                if pk_columns == ["dnss_hash"]:
                    self._connection.execute("DROP TABLE IF EXISTS registration_registry_v2")
                    self._connection.execute(
                        """
                        CREATE TABLE registration_registry_v2 (
                            dnss_hash TEXT NOT NULL,
                            node_id TEXT NOT NULL,
                            route_id TEXT NOT NULL,
                            route_public_key TEXT NOT NULL,
                            generation INTEGER NOT NULL DEFAULT 1,
                            created_at INTEGER NOT NULL DEFAULT 0,
                            expires_at INTEGER NOT NULL,
                            signature TEXT NOT NULL,
                            registered_at INTEGER NOT NULL,
                            PRIMARY KEY (dnss_hash, route_id)
                        )
                        """
                    )
                    self._connection.execute(
                        """
                        INSERT OR REPLACE INTO registration_registry_v2
                            (dnss_hash,node_id,route_id,route_public_key,generation,created_at,expires_at,signature,registered_at)
                        SELECT dnss_hash,node_id,route_id,route_public_key,generation,created_at,expires_at,signature,registered_at
                        FROM registration_registry
                        """
                    )
                    self._connection.execute("DROP TABLE registration_registry")
                    self._connection.execute("ALTER TABLE registration_registry_v2 RENAME TO registration_registry")
            else:
                self._connection.execute(
                    """
                    CREATE TABLE registration_registry (
                        dnss_hash TEXT NOT NULL,
                        node_id TEXT NOT NULL,
                        route_id TEXT NOT NULL,
                        route_public_key TEXT NOT NULL,
                        generation INTEGER NOT NULL DEFAULT 1,
                        created_at INTEGER NOT NULL DEFAULT 0,
                        expires_at INTEGER NOT NULL,
                        signature TEXT NOT NULL,
                        registered_at INTEGER NOT NULL,
                        PRIMARY KEY (dnss_hash, route_id)
                    )
                    """
                )

            self._connection.execute(
                "CREATE INDEX IF NOT EXISTS registration_registry_dnss_idx ON registration_registry(dnss_hash)"
            )
            self._connection.execute(
                "CREATE INDEX IF NOT EXISTS registration_registry_expiry_idx ON registration_registry(expires_at)"
            )

            row = self._connection.execute(
                "SELECT node_id FROM registration_registry_node WHERE singleton = 1"
            ).fetchone()
            if row is None:
                self._connection.execute(
                    "INSERT INTO registration_registry_node (singleton, node_id) VALUES (1, ?)",
                    (self._node_id,),
                )
            elif row["node_id"].lower() != self._node_id:
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
        current_time = int(time.time()) if now is None else int(now)
        entry_grant = self._coerce_grant(grant)
        if not entry_grant.verify(expected_node_id=self._node_id, now=current_time):
            raise ValueError("EntryGrant is invalid, expired, or belongs to another node")
        record = RegistrationRecord(
            node_id=entry_grant.node_id,
            route_id=entry_grant.route_id,
            route_public_key=entry_grant.route_public_key,
            generation=entry_grant.generation,
            created_at=entry_grant.created_at,
            expires_at=entry_grant.expires_at,
            signature=entry_grant.signature,
            registered_at=current_time,
        )
        with self._connection:
            self._connection.execute(
                """
                INSERT INTO registration_registry
                    (dnss_hash,node_id,route_id,route_public_key,generation,created_at,expires_at,signature,registered_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(dnss_hash, route_id) DO UPDATE SET
                    node_id=excluded.node_id,
                    route_public_key=excluded.route_public_key,
                    generation=excluded.generation,
                    created_at=excluded.created_at,
                    expires_at=excluded.expires_at,
                    signature=excluded.signature,
                    registered_at=excluded.registered_at
                """,
                (self.blind_hash(dnss), record.node_id, record.route_id,
                 record.route_public_key, record.generation, record.created_at,
                 record.expires_at, record.signature, record.registered_at),
            )
        return record

    def lookup(
        self, dnss: DNSS, *, route_id: Optional[str] = None, now: Optional[int] = None
    ) -> Optional[RegistrationRecord]:
        """Return one valid record, optionally for an exact RouteID.

        Invalid/expired legacy rows are deleted as they are encountered.  A raw
        DNSS is never persisted or returned.
        """
        current_time = int(time.time()) if now is None else int(now)
        dnss_hash = self.blind_hash(dnss)
        sql = (
            "SELECT node_id,route_id,route_public_key,generation,created_at,expires_at,signature,registered_at "
            "FROM registration_registry WHERE dnss_hash = ?"
        )
        params: list[Any] = [dnss_hash]
        if route_id is not None:
            sql += " AND route_id = ?"
            params.append(route_id)
        sql += " ORDER BY registered_at DESC"
        rows = self._connection.execute(sql, params).fetchall()
        for row in rows:
            record = RegistrationRecord(**dict(row))
            if record.grant.verify(expected_node_id=self._node_id, now=current_time):
                return record
            with self._connection:
                self._connection.execute(
                    "DELETE FROM registration_registry WHERE dnss_hash = ? AND route_id = ?",
                    (dnss_hash, record.route_id),
                )
        return None

    def list_for_dnss(self, dnss: DNSS, *, now: Optional[int] = None) -> list[RegistrationRecord]:
        """Return all currently valid Route grants for this blinded DNSS."""
        current_time = int(time.time()) if now is None else int(now)
        dnss_hash = self.blind_hash(dnss)
        rows = self._connection.execute(
            "SELECT node_id,route_id,route_public_key,generation,created_at,expires_at,signature,registered_at "
            "FROM registration_registry WHERE dnss_hash = ? ORDER BY registered_at DESC",
            (dnss_hash,),
        ).fetchall()
        valid: list[RegistrationRecord] = []
        for row in rows:
            record = RegistrationRecord(**dict(row))
            if record.grant.verify(expected_node_id=self._node_id, now=current_time):
                valid.append(record)
            else:
                with self._connection:
                    self._connection.execute(
                        "DELETE FROM registration_registry WHERE dnss_hash = ? AND route_id = ?",
                        (dnss_hash, record.route_id),
                    )
        return valid

    def purge_expired(self, *, now: Optional[int] = None) -> int:
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
