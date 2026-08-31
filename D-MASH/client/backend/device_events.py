"""Opaque Device event queue primitives for the parallel Device transport.

This module deliberately has no Account fields or legacy DMP-C integration.  A
caller supplies only a validated opaque Device delivery handle and opaque event
payload.  Authentication/wire framing remain separate protocol layers.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import secrets
import time
from typing import Any


@dataclass(frozen=True)
class DeviceEventBatch:
    batch_id: str
    events: list[dict[str, Any]]
    more_available: bool


class DeviceEventStore:
    """Durable bounded batches with lease-bound ACK and replay-safe dedup."""

    def __init__(self, connection, *, max_events: int = 32, max_bytes: int = 64 * 1024, lease_seconds: int = 30):
        if max_events < 1 or max_bytes < 1 or lease_seconds < 1:
            raise ValueError("invalid Device event batch limits")
        self.conn = connection
        self.max_events = max_events
        self.max_bytes = max_bytes
        self.lease_seconds = lease_seconds

    async def initialize(self) -> None:
        await self.conn.execute("""
            CREATE TABLE IF NOT EXISTS device_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_handle_hash TEXT NOT NULL,
                event_id TEXT NOT NULL,
                event_json TEXT NOT NULL,
                event_bytes INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                batch_id TEXT,
                lease_expires_at INTEGER,
                UNIQUE(device_handle_hash, event_id)
            )
        """)
        await self.conn.execute("""
            CREATE TABLE IF NOT EXISTS device_batch_receipts (
                batch_id TEXT PRIMARY KEY,
                device_handle_hash TEXT NOT NULL,
                ack_digest TEXT NOT NULL,
                expires_at INTEGER NOT NULL
            )
        """)
        columns = await (await self.conn.execute("PRAGMA table_info(device_batch_receipts)")).fetchall()
        if "ack_digest" not in {column["name"] for column in columns}:
            await self.conn.execute("ALTER TABLE device_batch_receipts ADD COLUMN ack_digest TEXT NOT NULL DEFAULT ''")
        await self.conn.execute("CREATE INDEX IF NOT EXISTS idx_device_events_ready ON device_events(device_handle_hash, expires_at, lease_expires_at)")
        await self.conn.commit()

    @staticmethod
    def _handle_hash(device_handle: str) -> str:
        if not isinstance(device_handle, str) or not device_handle:
            raise ValueError("opaque Device handle is required")
        return hashlib.sha256(device_handle.encode("utf-8")).hexdigest()

    @staticmethod
    def _event_json(event: dict[str, Any]) -> str:
        if not isinstance(event, dict) or not isinstance(event.get("event_id"), str) or not event["event_id"]:
            raise ValueError("opaque event_id is required")
        encoded = json.dumps(event, separators=(",", ":"), sort_keys=True)
        return encoded

    @staticmethod
    def _ack_digest(event_ids: list[str]) -> str:
        return hashlib.sha256(json.dumps(sorted(event_ids), separators=(",", ":")).encode("utf-8")).hexdigest()

    async def enqueue(self, device_handle: str, event: dict[str, Any], *, expires_at: int) -> bool:
        now = int(time.time())
        if not isinstance(expires_at, int) or expires_at <= now:
            raise ValueError("event expiry must be in the future")
        encoded = self._event_json(event)
        if len(encoded.encode("utf-8")) > self.max_bytes:
            raise ValueError("event exceeds the configured Device batch byte limit")
        cursor = await self.conn.execute(
            "INSERT OR IGNORE INTO device_events (device_handle_hash, event_id, event_json, event_bytes, expires_at) VALUES (?, ?, ?, ?, ?)",
            (self._handle_hash(device_handle), event["event_id"], encoded, len(encoded.encode("utf-8")), expires_at),
        )
        changed = cursor.rowcount == 1
        await self.conn.commit()
        return changed

    async def pull_batch(self, device_handle: str) -> DeviceEventBatch | None:
        now = int(time.time())
        handle_hash = self._handle_hash(device_handle)
        await self.conn.execute("BEGIN IMMEDIATE")
        try:
            await self.conn.execute("DELETE FROM device_events WHERE expires_at <= ?", (now,))
            await self.conn.execute("DELETE FROM device_batch_receipts WHERE expires_at <= ?", (now,))
            async with self.conn.execute(
                "SELECT id, event_json, event_bytes FROM device_events WHERE device_handle_hash = ? AND (lease_expires_at IS NULL OR lease_expires_at <= ?) ORDER BY id ASC",
                (handle_hash, now),
            ) as cursor:
                rows = await cursor.fetchall()
            selected, total_bytes = [], 0
            for row in rows:
                if len(selected) == self.max_events or total_bytes + row["event_bytes"] > self.max_bytes:
                    break
                selected.append(row)
                total_bytes += row["event_bytes"]
            if not selected:
                await self.conn.commit()
                return None
            batch_id = secrets.token_urlsafe(24)
            lease_expires_at = now + self.lease_seconds
            placeholders = ",".join("?" for _ in selected)
            await self.conn.execute(
                f"UPDATE device_events SET batch_id = ?, lease_expires_at = ? WHERE id IN ({placeholders})",
                [batch_id, lease_expires_at, *[row["id"] for row in selected]],
            )
            async with self.conn.execute(
                "SELECT 1 FROM device_events WHERE device_handle_hash = ? AND (lease_expires_at IS NULL OR lease_expires_at <= ?) LIMIT 1",
                (handle_hash, now),
            ) as cursor:
                more_available = await cursor.fetchone() is not None
            await self.conn.commit()
            return DeviceEventBatch(batch_id, [json.loads(row["event_json"]) for row in selected], more_available)
        except Exception:
            await self.conn.rollback()
            raise

    async def acknowledge(self, device_handle: str, batch_id: str, event_ids: list[str]) -> bool:
        """Atomically accept one exact ACK; an identical post-commit replay is idempotently successful."""
        if not isinstance(batch_id, str) or not batch_id or not isinstance(event_ids, list) or not event_ids or len(set(event_ids)) != len(event_ids):
            return False
        handle_hash = self._handle_hash(device_handle)
        ack_digest = self._ack_digest(event_ids)
        now = int(time.time())
        await self.conn.execute("BEGIN IMMEDIATE")
        try:
            async with self.conn.execute("SELECT ack_digest FROM device_batch_receipts WHERE batch_id = ? AND device_handle_hash = ?", (batch_id, handle_hash)) as cursor:
                receipt = await cursor.fetchone()
                if receipt:
                    await self.conn.commit()
                    return receipt["ack_digest"] == ack_digest
            async with self.conn.execute(
                "SELECT event_id FROM device_events WHERE device_handle_hash = ? AND batch_id = ? AND lease_expires_at > ?",
                (handle_hash, batch_id, now),
            ) as cursor:
                matched = [row["event_id"] for row in await cursor.fetchall()]
            if set(matched) != set(event_ids):
                await self.conn.rollback()
                return False
            await self.conn.execute(
                "DELETE FROM device_events WHERE device_handle_hash = ? AND batch_id = ?",
                (handle_hash, batch_id),
            )
            await self.conn.execute("INSERT INTO device_batch_receipts (batch_id, device_handle_hash, ack_digest, expires_at) VALUES (?, ?, ?, ?)", (batch_id, handle_hash, ack_digest, now + self.lease_seconds))
            await self.conn.commit()
            return True
        except Exception:
            await self.conn.rollback()
            raise
