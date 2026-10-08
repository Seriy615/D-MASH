"""Three routing actors; socket authentication is covered separately."""
import importlib.util
from pathlib import Path
import unittest

_path=Path(__file__).resolve().parents[3]/'tools/diagnose_node_retry_dedupe_v4.py'
_spec=importlib.util.spec_from_file_location('node_routing_retry_fixture',_path)
_fixture=importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_fixture)

class NodeRoutingRetryV4Tests(unittest.IsolatedAsyncioTestCase):
    async def test_exact_ciphertext_retry_after_downstream_loss_and_new_grant(self):
        await _fixture.main()
