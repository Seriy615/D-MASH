import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from nacl.signing import SigningKey
from websockets.server import serve

from backend.crypto import NodeCryptoManager
from backend.database import DatabaseManager
from backend.network import P2PNode
from backend.tact import TactEngine
from backend import node_session


class NodeSessionTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.nodes = []
        self.pow = patch.object(node_session, "NODE_POW_DIFFICULTY", 4)
        self.pow.start()
        # Identity-prefix mining is covered separately; this fixture isolates
        # mutual key possession and real directional resource-PoW verification.
        self.identity_pow = patch.object(NodeCryptoManager, "verify_node_pow", return_value=True)
        self.identity_pow.start()
        for name in ("a", "b"):
            db = DatabaseManager(str(Path(self.tmp.name) / f"{name}.db"))
            db.set_node_crypto(NodeCryptoManager(SigningKey.generate().encode().hex()))
            await db.connect()
            self.nodes.append(P2PNode(db, can_route=True))

    async def asyncTearDown(self):
        for node in self.nodes:
            if node.transport_batcher: await node.transport_batcher.close()
            for channel in list(node.active_connections.values()): await channel.close()
            for task in list(node.connection_tasks): task.cancel()
            await asyncio.gather(*node.connection_tasks, return_exceptions=True)
            await node.system_db.close()
        self.pow.stop()
        self.identity_pow.stop()
        self.tmp.cleanup()

    async def test_real_peers_mutual_auth_directional_dnss_and_encrypted_data(self):
        a, b = self.nodes
        b._process_envelope = AsyncMock()
        async with serve(b._handle_incoming, "127.0.0.1", 0) as server:
            address = f"127.0.0.1:{server.sockets[0].getsockname()[1]}"
            self.assertTrue(await a.connect_to(address))
            ca = a.active_connections[b.system_db.node_crypto.node_id]
            for _ in range(100):
                if a.system_db.node_crypto.node_id in b.active_connections: break
                await asyncio.sleep(.01)
            cb = b.active_connections[a.system_db.node_crypto.node_id]
            self.assertEqual(ca.local_dnss, cb.remote_dnss)
            self.assertEqual(ca.remote_dnss, cb.local_dnss)
            self.assertNotEqual(ca.local_dnss, ca.remote_dnss)
            self.assertEqual(ca.secure.session.peer_role, "NODE")
            await ca.send(json.dumps({"t": "REAL", "d": json.dumps({"type": "DMP_C_DATA", "id": "packet-1", "envelope": {"ciphertext": "opaque"}})}))
            for _ in range(100):
                if b._process_envelope.called: break
                await asyncio.sleep(.01)
            self.assertTrue(b._process_envelope.called)
            b._process_envelope.reset_mock()
            packets = [{"type": "DMP_C_DATA", "id": f"batch-{i}", "envelope": {"ciphertext": "opaque"}} for i in range(3)]
            await ca.send_batch(packets)
            for _ in range(100):
                if b._process_envelope.await_count == 3: break
                await asyncio.sleep(.01)
            self.assertEqual([json.loads(json.loads(call.args[0])["d"]) for call in b._process_envelope.await_args_list], packets)
            b._process_envelope.reset_mock()
            engine = TactEngine(a.system_db, a)
            alias = a.transport._blind('window-route')
            await a.system_db.add_route_alias(alias, b.system_db.node_crypto.node_id, 1)
            for packet in packets:
                await a.enqueue_transport_packet({**packet, 'route_id': 'window-route'})
            await asyncio.sleep(.05)
            b._process_envelope.assert_not_called()
            for _ in range(150):
                if b._process_envelope.await_count == 3: break
                await asyncio.sleep(.01)
            self.assertEqual([json.loads(json.loads(call.args[0])["d"])["id"] for call in b._process_envelope.await_args_list], [p['id'] for p in packets])
            self.assertIsNone(engine._timer)
            self.assertFalse(a.transient_transport_outbox)
            await ca.secure.send_json({"type": "PULL"})
            for _ in range(100):
                if not b.active_connections: break
                await asyncio.sleep(.01)
            self.assertFalse(b.active_connections, "Node role must not gain Device operations")

    async def test_one_direction_bad_work_prevents_connection(self):
        a, b = self.nodes
        original = node_session.mine_activation_pow
        def mine(*args):
            proof = original(*args)
            if args[2] == a.system_db.node_crypto.node_id:
                proof["digest"] = "00" * 32
            return proof
        async with serve(b._handle_incoming, "127.0.0.1", 0) as server:
            with patch.object(node_session, "mine_activation_pow", side_effect=mine):
                self.assertFalse(await a.connect_to(f"127.0.0.1:{server.sockets[0].getsockname()[1]}"))
            self.assertFalse(a.active_connections)
            self.assertFalse(b.active_connections)


if __name__ == "__main__": unittest.main()
