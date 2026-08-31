import os
import tempfile
import time
import unittest
from types import SimpleNamespace

from backend.capabilities import NodeCapabilities
from backend.fallback_runtime import initialize_fallback_store
from backend.database import DatabaseManager


class FallbackRuntimeIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.path = tempfile.mktemp(suffix=".sqlite")
        self.database = DatabaseManager(self.path)
        await self.database.connect()

    async def asyncTearDown(self):
        await self.database.close()
        os.unlink(self.path)

    async def test_enabled_runtime_initializes_durable_store_on_system_database(self):
        runtime = SimpleNamespace()
        runtime.capabilities = NodeCapabilities(
            can_route=True, can_accept_devices=True, can_fallback_store=True
        )
        store = await initialize_fallback_store(self.database.conn, runtime)
        self.assertIs(store, runtime.fallback_store)
        self.assertTrue(await store.store("device-handle", "envelope-1", "opaque-ciphertext", expires_at=int(time.time()) + 300))
        batch = await store.pull_batch("device-handle")
        self.assertEqual(batch.envelopes, [{"envelope_id": "envelope-1", "opaque_payload": "opaque-ciphertext"}])
        self.assertTrue(await store.acknowledge("device-handle", batch.batch_id, ["envelope-1"]))

    async def test_runtime_with_ineligible_policy_does_not_activate_store(self):
        runtime = SimpleNamespace()
        runtime.capabilities = NodeCapabilities(can_route=True, can_fallback_store=True)
        self.assertIsNone(await initialize_fallback_store(self.database.conn, runtime))
        self.assertIsNone(runtime.fallback_store)


if __name__ == "__main__":
    unittest.main()
