import asyncio
import os
import tempfile
import unittest

import aiosqlite

from backend.device_events import DeviceEventStore


class DeviceEventStoreTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.path = tempfile.mktemp(suffix=".sqlite")
        self.conn = await aiosqlite.connect(self.path)
        self.conn.row_factory = aiosqlite.Row
        self.store = DeviceEventStore(self.conn, max_events=2, max_bytes=1024, lease_seconds=60)
        await self.store.initialize()

    async def asyncTearDown(self):
        await self.conn.close()
        os.unlink(self.path)

    async def test_deduplicates_and_returns_bounded_batches(self):
        handle = "device-opaque-handle"
        expiry = 4_000_000_000
        self.assertTrue(await self.store.enqueue(handle, {"event_id": "one", "ciphertext": "a"}, expires_at=expiry))
        self.assertFalse(await self.store.enqueue(handle, {"event_id": "one", "ciphertext": "a"}, expires_at=expiry))
        self.assertTrue(await self.store.enqueue(handle, {"event_id": "two", "ciphertext": "b"}, expires_at=expiry))
        self.assertTrue(await self.store.enqueue(handle, {"event_id": "three", "ciphertext": "c"}, expires_at=expiry))

        first = await self.store.pull_batch(handle)
        self.assertEqual([item["event_id"] for item in first.events], ["one", "two"])
        self.assertTrue(first.more_available)
        self.assertTrue(await self.store.acknowledge(handle, first.batch_id, ["one", "two"]))
        self.assertTrue(await self.store.acknowledge(handle, first.batch_id, ["one", "two"]))
        self.assertFalse(await self.store.acknowledge(handle, first.batch_id, ["one"]))

        second = await self.store.pull_batch(handle)
        self.assertEqual([item["event_id"] for item in second.events], ["three"])
        self.assertFalse(second.more_available)

    async def test_ack_is_bound_to_handle_batch_and_exact_event_set(self):
        expiry = 4_000_000_000
        await self.store.enqueue("device-a", {"event_id": "one", "ciphertext": "a"}, expires_at=expiry)
        batch = await self.store.pull_batch("device-a")
        self.assertFalse(await self.store.acknowledge("device-b", batch.batch_id, ["one"]))
        self.assertFalse(await self.store.acknowledge("device-a", batch.batch_id, ["wrong"]))
        self.assertFalse(await self.store.acknowledge("device-a", batch.batch_id, ["one", "one"]))
        self.assertFalse(await self.store.acknowledge("device-a", batch.batch_id, ["one", "missing"]))
        self.assertTrue(await self.store.acknowledge("device-a", batch.batch_id, ["one"]))

    async def test_rejects_event_that_can_never_fit_a_batch(self):
        store = DeviceEventStore(self.conn, max_events=2, max_bytes=20, lease_seconds=60)
        await store.initialize()
        with self.assertRaises(ValueError):
            await store.enqueue("device-a", {"event_id": "one", "ciphertext": "x" * 128}, expires_at=4_000_000_000)


if __name__ == "__main__":
    unittest.main()
