"""Regression guard for the retired raw HTTP send path."""

import asyncio
import importlib
import sys
import types
import unittest
from pathlib import Path

from fastapi import HTTPException

# Import the legacy endpoint in isolation: production wires ``core`` back to
# the API router during application startup, while this regression only needs
# to prove the endpoint rejects before touching runtime dependencies.
backend_path = str(Path(__file__).resolve().parents[1] / "backend")
sys.path.insert(0, backend_path)
state = types.SimpleNamespace(db=None)
core_stub = types.ModuleType("core")
core_stub.state = state
sys.modules["core"] = core_stub
for module_name, symbol in (("database", "DatabaseManager"), ("crypto", "CryptoManager")):
    stub = types.ModuleType(module_name)
    setattr(stub, symbol, object)
    sys.modules[module_name] = stub
dsp_stub = types.ModuleType("dsp")
dsp_stub.AudioProcessor = object
sys.modules["dsp"] = dsp_stub
api = importlib.import_module("api")


class LegacySendPrivacyGuardTests(unittest.TestCase):
    def test_legacy_send_is_unavailable_before_raw_persistence_or_routing(self):
        class PersistenceTrap:
            """Any legacy database access is a regression."""

            def __getattr__(self, name):
                raise AssertionError(f"legacy send accessed persistence via {name}")

        previous_db = api.state.db
        try:
            api.state.db = PersistenceTrap()
            with self.assertRaises(HTTPException) as raised:
                asyncio.run(api.send_message(api.SendData(
                    target_id="recipient-id",
                    text="must not be persisted",
                )))
        finally:
            api.state.db = previous_db

        response = raised.exception
        self.assertEqual(response.status_code, 410)
        self.assertEqual(response.detail, api.LEGACY_SEND_UNAVAILABLE_DETAIL)
        self.assertIn("unavailable", response.detail.lower())
        self.assertIn("not attempted", response.detail.lower())
        self.assertNotIn("fallback", response.detail.lower())


if __name__ == "__main__":
    unittest.main()
