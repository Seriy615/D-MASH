"""Capability-gated durable fallback persistence for opaque Device envelopes.

This is an isolated Node storage primitive.  It deliberately stores no Account
identity, Account key, plaintext, or legacy DMP-C state.  The caller supplies a
Device retrieval handle plus an opaque envelope identifier and opaque payload;
wire authentication and routing remain separate protocol layers.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import secrets
import time
from typing import Any

try:  # Runtime scripts import backend modules as top-level modules.
    from capabilities import NodeCapabilities
except ModuleNotFoundError:  # Package tests import ``backend.fallback_store``.
    from .capabilities import NodeCapabilities


@dataclass(frozen=True)
class FallbackBatch:
    batch_id: str
    envelopes: list[dict[str, str]]
    more_available: bool


class FallbackStore:
    """Bounded opaque Device-envelope persistence guarded by Node policy.

    Capacity is rejected rather than evicted: a successful store operation is
    retained until exact lease-bound acknowledgement or expiry.
    """

    def __init__(
        self,
        connection: Any,
        *,
        capabilities: NodeCapabilities | None,
        max_batch_items: int = 32,
        max_batch_bytes: int = 64 * 1024,
        max_envelope_bytes: int = 64 * 1024,
        max_device_items: int = 256,
        max_device_bytes: int = 1024 * 1024,
        max_total_bytes: int = 16 * 1024 * 1024,
        max_ttl_seconds: int = 7 * 24 * 60 * 60,
        lease_seconds: int = 30,
        max_handle_bytes: int = 1024,
        max_envelope_id_bytes: int = 256,
    ) -> None:
        # Runtime modules may be imported both as ``capabilities`` and as
        # ``backend.capabilities``; require the policy surface rather than an
        # import-path-specific class identity.
        if capabilities is None or not isinstance(getattr(capabilities, "can_fallback_store", None), bool):
            raise ValueError("NodeCapabilities are required for fallback storage")
        if min(max_batch_items, max_batch_bytes, max_envelope_bytes, max_device_items, max_device_bytes, max_total_bytes, max_ttl_seconds, lease_seconds, max_handle_bytes, max_envelope_id_bytes) < 1:
            raise ValueError("invalid fallback storage limits")
        if max_envelope_bytes > max_batch_bytes:
            raise ValueError("max envelope size must fit a retrieval batch")
        if max_device_bytes > max_total_bytes:
            raise ValueError("per-Device quota must not exceed total quota")
        self.conn = connection
        self.capabilities = capabilities
        self.max_batch_items = max_batch_items
        self.max_batch_bytes = max_batch_bytes
        self.max_envelope_bytes = max_envelope_bytes
        self.max_device_items = max_device_items
        self.max_device_bytes = max_device_bytes
        self.max_total_bytes = max_total_bytes
        self.max_ttl_seconds = max_ttl_seconds
        self.lease_seconds = lease_seconds
        self.max_handle_bytes = max_handle_bytes
        self.max_envelope_id_bytes = max_envelope_id_bytes

    @classmethod
    def from_runtime(cls, connection: Any, state: Any, **limits: Any) -> "FallbackStore":
        """Bind the store to the runtime's configured Node policy, fail closed."""
        return cls(connection, capabilities=getattr(state, "capabilities", None), **limits)

    def _require_enabled(self) -> None:
        if not (self.capabilities.can_route and self.capabilities.can_accept_devices and self.capabilities.can_fallback_store):
            raise PermissionError("fallback storage requires route, Device acceptance, and fallback capabilities")

    async def initialize(self) -> None:
        self._require_enabled()
        await self.conn.execute("""
            CREATE TABLE IF NOT EXISTS fallback_envelopes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_handle_hash TEXT NOT NULL,
                envelope_id TEXT NOT NULL,
                envelope_json TEXT NOT NULL,
                envelope_bytes INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                batch_id TEXT,
                lease_expires_at INTEGER,
                UNIQUE(device_handle_hash, envelope_id)
            )
        """)
        await self.conn.execute("""
            CREATE TABLE IF NOT EXISTS fallback_batch_receipts (
                batch_id TEXT PRIMARY KEY,
                device_handle_hash TEXT NOT NULL,
                ack_digest TEXT NOT NULL,
                expires_at INTEGER NOT NULL
            )
        """)
        await self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_fallback_ready "
            "ON fallback_envelopes(device_handle_hash, expires_at, lease_expires_at)"
        )
        await self.conn.commit()

    def _handle_hash(self, device_handle: str) -> str:
        if not isinstance(device_handle, str) or not device_handle:
            raise ValueError("opaque Device handle is required")
        encoded = device_handle.encode("utf-8")
        if len(encoded) > self.max_handle_bytes:
            raise ValueError("opaque Device handle exceeds the configured size limit")
        return hashlib.sha256(encoded).hexdigest()

    def _envelope_json(self, envelope_id: str, opaque_payload: str) -> str:
        if not isinstance(envelope_id, str) or not envelope_id:
            raise ValueError("opaque envelope_id is required")
        if len(envelope_id.encode("utf-8")) > self.max_envelope_id_bytes:
            raise ValueError("opaque envelope_id exceeds the configured size limit")
        if not isinstance(opaque_payload, str) or not opaque_payload:
            raise ValueError("opaque envelope payload is required")
        if len(opaque_payload.encode("utf-8")) > self.max_envelope_bytes:
            raise ValueError("fallback envelope exceeds the configured size limit")
        # Persist an allow-listed, Account-free schema.  Opaqueness is an API
        # boundary: this primitive stores neither parsed nor derived Account data.
        return json.dumps(
            {"envelope_id": envelope_id, "opaque_payload": opaque_payload},
            separators=(",", ":"),
            sort_keys=True,
        )

    @staticmethod
    def _ack_digest(envelope_ids: list[str]) -> str:
        return hashlib.sha256(json.dumps(sorted(envelope_ids), separators=(",", ":")).encode("utf-8")).hexdigest()

    async def _prune_expired(self, now: int) -> None:
        await self.conn.execute("DELETE FROM fallback_envelopes WHERE expires_at <= ?", (now,))
        await self.conn.execute("DELETE FROM fallback_batch_receipts WHERE expires_at <= ?", (now,))

    async def store(self, device_handle: str, envelope_id: str, opaque_payload: str, *, expires_at: int) -> bool:
        """Store one envelope, returning false only for idempotent duplicate insertion."""
        self._require_enabled()
        now = int(time.time())
        if not isinstance(expires_at, int) or expires_at <= now or expires_at > now + self.max_ttl_seconds:
            raise ValueError("fallback envelope expiry is outside the configured TTL")
        handle_hash = self._handle_hash(device_handle)
        encoded = self._envelope_json(envelope_id, opaque_payload)
        envelope_bytes = len(encoded.encode("utf-8"))
        if envelope_bytes > self.max_envelope_bytes:
            raise ValueError("fallback envelope exceeds the configured size limit")
        await self.conn.execute("BEGIN IMMEDIATE")
        try:
            await self._prune_expired(now)
            async with self.conn.execute(
                "SELECT 1 FROM fallback_envelopes WHERE device_handle_hash = ? AND envelope_id = ?",
                (handle_hash, envelope_id),
            ) as cursor:
                if await cursor.fetchone():
                    await self.conn.commit()
                    return False
            async with self.conn.execute(
                "SELECT COUNT(*), COALESCE(SUM(envelope_bytes), 0) FROM fallback_envelopes WHERE device_handle_hash = ?",
                (handle_hash,),
            ) as cursor:
                device_count, device_bytes = await cursor.fetchone()
            async with self.conn.execute("SELECT COALESCE(SUM(envelope_bytes), 0) FROM fallback_envelopes") as cursor:
                total_bytes = (await cursor.fetchone())[0]
            if (device_count >= self.max_device_items or device_bytes + envelope_bytes > self.max_device_bytes or total_bytes + envelope_bytes > self.max_total_bytes):
                raise OverflowError("fallback storage quota exceeded")
            await self.conn.execute(
                "INSERT INTO fallback_envelopes (device_handle_hash, envelope_id, envelope_json, envelope_bytes, expires_at) VALUES (?, ?, ?, ?, ?)",
                (handle_hash, envelope_id, encoded, envelope_bytes, expires_at),
            )
            await self.conn.commit()
            return True
        except Exception:
            await self.conn.rollback()
            raise

    async def pull_batch(self, device_handle: str) -> FallbackBatch | None:
        self._require_enabled()
        now = int(time.time())
        handle_hash = self._handle_hash(device_handle)
        await self.conn.execute("BEGIN IMMEDIATE")
        try:
            await self._prune_expired(now)
            async with self.conn.execute(
                "SELECT id, envelope_json, envelope_bytes FROM fallback_envelopes "
                "WHERE device_handle_hash = ? AND (lease_expires_at IS NULL OR lease_expires_at <= ?) ORDER BY id ASC",
                (handle_hash, now),
            ) as cursor:
                rows = await cursor.fetchall()
            selected, total_bytes = [], 0
            for row in rows:
                if len(selected) == self.max_batch_items or total_bytes + row["envelope_bytes"] > self.max_batch_bytes:
                    break
                selected.append(row)
                total_bytes += row["envelope_bytes"]
            if not selected:
                await self.conn.commit()
                return None
            batch_id = secrets.token_urlsafe(24)
            placeholders = ",".join("?" for _ in selected)
            await self.conn.execute(
                f"UPDATE fallback_envelopes SET batch_id = ?, lease_expires_at = ? WHERE id IN ({placeholders})",
                [batch_id, now + self.lease_seconds, *[row["id"] for row in selected]],
            )
            async with self.conn.execute(
                "SELECT 1 FROM fallback_envelopes WHERE device_handle_hash = ? "
                "AND (lease_expires_at IS NULL OR lease_expires_at <= ?) LIMIT 1",
                (handle_hash, now),
            ) as cursor:
                more_available = await cursor.fetchone() is not None
            await self.conn.commit()
            return FallbackBatch(batch_id, [json.loads(row["envelope_json"]) for row in selected], more_available)
        except Exception:
            await self.conn.rollback()
            raise

    async def acknowledge(self, device_handle: str, batch_id: str, envelope_ids: list[str]) -> bool:
        """Atomically accept one exact ACK; exact post-commit replay is idempotent."""
        self._require_enabled()
        if (not isinstance(batch_id, str) or not batch_id or not isinstance(envelope_ids, list) or not envelope_ids
                or any(not isinstance(item, str) or not item for item in envelope_ids) or len(set(envelope_ids)) != len(envelope_ids)):
            return False
        handle_hash = self._handle_hash(device_handle)
        digest = self._ack_digest(envelope_ids)
        now = int(time.time())
        await self.conn.execute("BEGIN IMMEDIATE")
        try:
            await self._prune_expired(now)
            async with self.conn.execute(
                "SELECT ack_digest FROM fallback_batch_receipts WHERE batch_id = ? AND device_handle_hash = ?",
                (batch_id, handle_hash),
            ) as cursor:
                receipt = await cursor.fetchone()
            if receipt:
                await self.conn.commit()
                return receipt["ack_digest"] == digest
            async with self.conn.execute(
                "SELECT envelope_id FROM fallback_envelopes WHERE device_handle_hash = ? AND batch_id = ? AND lease_expires_at > ?",
                (handle_hash, batch_id, now),
            ) as cursor:
                matched = [row["envelope_id"] for row in await cursor.fetchall()]
            if set(matched) != set(envelope_ids):
                await self.conn.rollback()
                return False
            async with self.conn.execute(
                "SELECT MAX(expires_at) FROM fallback_envelopes WHERE device_handle_hash = ? AND batch_id = ? AND lease_expires_at > ?",
                (handle_hash, batch_id, now),
            ) as cursor:
                receipt_expires_at = (await cursor.fetchone())[0]
            deleted = await self.conn.execute(
                "DELETE FROM fallback_envelopes WHERE device_handle_hash = ? AND batch_id = ? AND lease_expires_at > ?",
                (handle_hash, batch_id, now),
            )
            if deleted.rowcount != len(envelope_ids):
                raise RuntimeError("fallback ACK lease changed during deletion")
            await self.conn.execute(
                "INSERT INTO fallback_batch_receipts (batch_id, device_handle_hash, ack_digest, expires_at) VALUES (?, ?, ?, ?)",
                (batch_id, handle_hash, digest, receipt_expires_at),
            )
            await self.conn.commit()
            return True
        except Exception:
            await self.conn.rollback()
            raise
