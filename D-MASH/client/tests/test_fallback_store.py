import asyncio
import os
import tempfile
import time
import unittest

import aiosqlite

from backend.capabilities import NodeCapabilities
from backend.fallback_store import FallbackStore


class FallbackStoreTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.path = tempfile.mktemp(suffix=".sqlite")
        self.conn = await aiosqlite.connect(self.path)
        self.conn.row_factory = aiosqlite.Row
        self.store = FallbackStore(
            self.conn,
            capabilities=NodeCapabilities(can_route=True, can_accept_devices=True, can_fallback_store=True),
            max_batch_items=2,
            max_batch_bytes=1024,
            max_envelope_bytes=512,
            max_device_items=3,
            max_device_bytes=800,
            max_total_bytes=1000,
            max_ttl_seconds=3600,
            lease_seconds=60,
        )
        await self.store.initialize()

    async def asyncTearDown(self):
        await self.conn.close()
        os.unlink(self.path)

    async def test_disabled_capability_rejects_all_storage_operations(self):
        disabled = FallbackStore(self.conn, capabilities=NodeCapabilities())
        with self.assertRaises(PermissionError):
            await disabled.initialize()
        with self.assertRaises(PermissionError):
            await disabled.store("device", "one", "opaque", expires_at=int(time.time()) + 60)
        with self.assertRaises(PermissionError):
            await disabled.pull_batch("device")
        with self.assertRaises(PermissionError):
            await disabled.acknowledge("device", "batch", ["one"])

    async def test_fallback_requires_all_composed_capabilities(self):
        for policy in (
            NodeCapabilities(can_fallback_store=True, can_route=False),
            NodeCapabilities(can_route=True, can_fallback_store=True),
            NodeCapabilities(can_accept_devices=True, can_fallback_store=True, can_route=False),
        ):
            store = FallbackStore(self.conn, capabilities=policy)
            with self.assertRaises(PermissionError):
                await store.initialize()

    async def test_runtime_boundary_requires_configured_enabled_capability(self):
        class DisabledState:
            capabilities = NodeCapabilities()

        class EnabledState:
            capabilities = NodeCapabilities(can_route=True, can_accept_devices=True, can_fallback_store=True)

        with self.assertRaises(ValueError):
            FallbackStore.from_runtime(self.conn, object())
        disabled = FallbackStore.from_runtime(self.conn, DisabledState())
        with self.assertRaises(PermissionError):
            await disabled.initialize()
        enabled = FallbackStore.from_runtime(self.conn, EnabledState())
        await enabled.initialize()

    async def test_dedup_bounded_pull_and_exact_idempotent_ack(self):
        expiry = int(time.time()) + 300
        self.assertTrue(await self.store.store("device-a", "one", "opaque-a", expires_at=expiry))
        self.assertFalse(await self.store.store("device-a", "one", "different-is-still-a-duplicate", expires_at=expiry))
        self.assertTrue(await self.store.store("device-a", "two", "opaque-b", expires_at=expiry))
        self.assertTrue(await self.store.store("device-a", "three", "opaque-c", expires_at=expiry))
        batch = await self.store.pull_batch("device-a")
        self.assertEqual([item["envelope_id"] for item in batch.envelopes], ["one", "two"])
        self.assertTrue(batch.more_available)
        self.assertFalse(await self.store.acknowledge("device-b", batch.batch_id, ["one", "two"]))
        self.assertFalse(await self.store.acknowledge("device-a", batch.batch_id, ["one"]))
        self.assertFalse(await self.store.acknowledge("device-a", batch.batch_id, ["one", "one"]))
        self.assertTrue(await self.store.acknowledge("device-a", batch.batch_id, ["one", "two"]))
        # Receipts survive lease expiry through the acknowledged envelope TTL.
        async with self.conn.execute(
            "SELECT expires_at FROM fallback_batch_receipts WHERE batch_id = ?", (batch.batch_id,)
        ) as cursor:
            self.assertEqual((await cursor.fetchone())["expires_at"], expiry)
        self.assertTrue(await self.store.acknowledge("device-a", batch.batch_id, ["two", "one"]))
        self.assertFalse(await self.store.acknowledge("device-a", batch.batch_id, ["one"]))
        next_batch = await self.store.pull_batch("device-a")
        self.assertEqual([item["envelope_id"] for item in next_batch.envelopes], ["three"])

    async def test_enforces_ttl_size_and_quotas_without_eviction(self):
        now = int(time.time())
        with self.assertRaises(ValueError):
            await self.store.store("device-a", "expired", "opaque", expires_at=now)
        with self.assertRaises(ValueError):
            await self.store.store("device-a", "too-long", "opaque", expires_at=now + 3601)
        with self.assertRaises(ValueError):
            await self.store.store("device-a", "oversized", "x" * 1024, expires_at=now + 60)
        with self.assertRaises(ValueError):
            await self.store.store("x" * 1025, "id", "opaque", expires_at=now + 60)
        with self.assertRaises(ValueError):
            await self.store.store("device-a", "é" * 129, "opaque", expires_at=now + 60)

        quota_store = FallbackStore(
            self.conn,
            capabilities=NodeCapabilities(can_route=True, can_accept_devices=True, can_fallback_store=True),
            max_batch_items=2,
            max_batch_bytes=100,
            max_envelope_bytes=100,
            max_device_items=1,
            max_device_bytes=100,
            max_total_bytes=100,
            max_ttl_seconds=60,
            lease_seconds=10,
        )
        await quota_store.initialize()
        self.assertTrue(await quota_store.store("device-a", "one", "a", expires_at=now + 30))
        with self.assertRaises(OverflowError):
            await quota_store.store("device-a", "two", "b", expires_at=now + 30)
        self.assertEqual((await quota_store.pull_batch("device-a")).envelopes[0]["envelope_id"], "one")

    async def test_expiry_prunes_and_lease_expiry_replays(self):
        now = int(time.time())
        await self.store.store("device-a", "expired", "opaque", expires_at=now + 1)
        await asyncio.sleep(1.1)
        self.assertIsNone(await self.store.pull_batch("device-a"))

        replay_store = FallbackStore(
            self.conn,
            capabilities=NodeCapabilities(can_route=True, can_accept_devices=True, can_fallback_store=True),
            max_ttl_seconds=60,
            lease_seconds=1,
        )
        await replay_store.initialize()
        await replay_store.store("device-a", "replay", "opaque", expires_at=int(time.time()) + 30)
        first = await replay_store.pull_batch("device-a")
        await asyncio.sleep(1.1)
        replay = await replay_store.pull_batch("device-a")
        self.assertEqual(first.envelopes, replay.envelopes)
        self.assertNotEqual(first.batch_id, replay.batch_id)


if __name__ == "__main__":
    unittest.main()
