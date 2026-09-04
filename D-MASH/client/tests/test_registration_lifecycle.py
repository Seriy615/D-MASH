import asyncio
import os
import tempfile
import unittest
from unittest.mock import patch

from nacl.encoding import HexEncoder
from nacl.signing import SigningKey

import backend.client_gateway as gateway
import backend.core as core


class RegistrationLifecycleTests(unittest.TestCase):
    def test_startup_wires_dedicated_registry_factory_with_node_crypto(self):
        node_key = SigningKey(b"\x51" * 32)
        node_crypto = core.NodeCryptoManager(
            node_key.encode(encoder=HexEncoder).decode("ascii")
        )
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "registrations.sqlite")
            previous_path = core.REGISTRATION_REGISTRY_PATH
            previous_factory = gateway.registration_registry_factory
            try:
                core.REGISTRATION_REGISTRY_PATH = path
                gateway.registration_registry_factory = None
                core.wire_registration_registry()

                self.assertTrue(callable(gateway.registration_registry_factory))
                registry = gateway.registration_registry_factory(node_crypto)
                try:
                    self.assertEqual(registry.database_path, path)
                    self.assertIsNot(registry.database_path, "system.db")
                    self.assertEqual(registry._node_id, node_crypto.node_id)
                finally:
                    registry.close()

                self.assertTrue(os.path.exists(path))
                self.assertFalse(os.path.exists(os.path.join(directory, "system.db")))
            finally:
                core.REGISTRATION_REGISTRY_PATH = previous_path
                gateway.registration_registry_factory = previous_factory

    def test_startup_failure_after_wiring_resets_registry_factory(self):
        class FakeDatabase:
            conn = object()

            def __init__(self, path):
                self.path = path

            def set_node_crypto(self, node_crypto):
                pass

            async def connect(self):
                pass

            async def rehydrate_notifications(self):
                pass

        class FakeCapabilities:
            can_route = False
            can_accept_devices = False

        node_key = SigningKey(b"\x52" * 32)
        node_key_hex = node_key.encode(encoder=HexEncoder).decode("ascii")
        original_wire = core.wire_registration_registry

        def wire_then_fail():
            original_wire()
            raise RuntimeError("startup failed after registration wiring")

        async def fail_startup():
            with self.assertRaisesRegex(RuntimeError, "startup failed"):
                async with core.lifespan(core.app):
                    self.fail("lifespan must not yield after startup failure")

        previous_factory = gateway.registration_registry_factory
        try:
            with (
                patch.object(core, "ensure_node_identity", return_value=node_key_hex),
                patch.object(core.NodeCapabilities, "from_env", return_value=FakeCapabilities()),
                patch.object(core, "create_crypto_executor"),
                patch.object(core, "DatabaseManager", FakeDatabase),
                patch.object(core, "initialize_fallback_store"),
                patch.object(core.OriginNotificationClient, "from_env", return_value=None),
                patch.object(core, "wire_registration_registry", side_effect=wire_then_fail),
            ):
                asyncio.run(fail_startup())

            self.assertIsNone(gateway.registration_registry_factory)
        finally:
            gateway.registration_registry_factory = previous_factory


if __name__ == "__main__":
    unittest.main()
