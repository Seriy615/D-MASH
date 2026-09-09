import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

from backend.database import DatabaseManager
from backend.tact import TactEngine
from backend.node_session import NodeChannel, MAX_BATCH_PACKETS
from backend.network import P2PNode
from test_transport import FakeNodeCrypto


class TactTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = DatabaseManager(str(Path(self.tmp.name) / 'node.db'))
        self.db.set_node_crypto(FakeNodeCrypto())
        await self.db.connect()
        self.a = SimpleNamespace(send_batch=AsyncMock())
        self.b = SimpleNamespace(send_batch=AsyncMock())
        self.node = SimpleNamespace(can_route=True, active_connections={'a': self.a, 'b': self.b}, transient_transport_outbox=[])
        self.tact = TactEngine(self.db, self.node)

    async def asyncTearDown(self):
        await self.db.close()
        self.tmp.cleanup()

    def enqueue(self, identity, target=None):
        self.node.transient_transport_outbox.append({'packet': {'type': 'DMP_C_DATA', 'id': identity}, 'next_hop_id': target})

    async def test_empty_tick_sends_nothing(self):
        await self.tact._tick()
        self.a.send_batch.assert_not_called()
        self.b.send_batch.assert_not_called()
        self.assertEqual(self.tact.interval, .5)

    async def test_enqueue_limits_and_immutable_snapshot(self):
        packet = {'type': 'DMP_C_DATA', 'envelope': {'ciphertext': 'original'}}
        await P2PNode.enqueue_transport_packet(self.node, packet)
        packet['envelope']['ciphertext'] = 'changed'
        self.assertEqual(self.node.transient_transport_outbox[0]['packet']['envelope']['ciphertext'], 'original')
        with self.assertRaises(ValueError):
            await P2PNode.enqueue_transport_packet(self.node, {'type': 'DMP_C_DATA', 'body': 'x' * (128 * 1024)})
        with self.assertRaises(PermissionError):
            await P2PNode.enqueue_transport_packet(self.node, {'type': 'PULL'})
        self.node.transient_transport_outbox = [self.node.transient_transport_outbox[0]] * 4096
        with self.assertRaises(BufferError): await P2PNode.enqueue_transport_packet(self.node, packet)

    async def test_partial_broadcast_retries_only_failed_peer(self):
        self.enqueue('one'); self.enqueue('two')
        self.b.send_batch.side_effect = OSError('offline')
        await self.tact._tick()
        self.assertEqual(len(self.node.transient_transport_outbox), 2)
        self.assertEqual(len(self.a.send_batch.call_args.args[0]), 2)
        self.b.send_batch.side_effect = None
        await self.tact._tick()
        self.a.send_batch.assert_awaited_once()
        self.assertEqual(self.b.send_batch.await_count, 2)
        self.assertEqual(self.node.transient_transport_outbox, [])

    async def test_disconnected_target_retained_and_batch_bounded(self):
        for i in range(MAX_BATCH_PACKETS + 1): self.enqueue(str(i), 'c')
        await self.tact._tick()
        self.assertEqual(len(self.node.transient_transport_outbox), MAX_BATCH_PACKETS + 1)
        self.node.active_connections['c'] = self.a
        await self.tact._tick()
        self.assertEqual(len(self.a.send_batch.call_args.args[0]), MAX_BATCH_PACKETS)
        self.assertEqual(len(self.node.transient_transport_outbox), 1)
        await self.tact._tick()
        self.assertEqual(self.node.transient_transport_outbox, [])

    async def test_cancelled_send_retains_packet(self):
        self.enqueue('one', 'a')
        self.a.send_batch.side_effect = asyncio.CancelledError
        with self.assertRaises(asyncio.CancelledError): await self.tact._tick()
        self.assertEqual(len(self.node.transient_transport_outbox), 1)

    async def test_durable_failed_send_retains_row(self):
        await self.db.conn.execute('INSERT INTO outbox (packet_id, next_hop_hash, packet_json) VALUES (?, ?, ?)',
            ('old', 'blind:a', json.dumps({'type': 'DMP_C_DATA', 'id': 'old'})))
        await self.db.conn.commit()
        self.a.send_batch.side_effect = OSError('offline')
        await self.tact._tick()
        async with self.db.conn.execute('SELECT count(*) FROM outbox') as cursor:
            self.assertEqual((await cursor.fetchone())[0], 1)
        self.a.send_batch.side_effect = None
        await self.tact._tick()
        async with self.db.conn.execute('SELECT count(*) FROM outbox') as cursor:
            self.assertEqual((await cursor.fetchone())[0], 0)


class BatchTests(unittest.IsolatedAsyncioTestCase):
    async def test_batch_preserves_order_and_validates_all_before_dispatch(self):
        packets = [{'type': 'DMP_C_DATA', 'id': str(i)} for i in range(3)]
        secure = SimpleNamespace(send_json=AsyncMock(), receive_json=AsyncMock(return_value={'type': 'MESH_BATCH', 'packets': packets}))
        channel = NodeChannel(secure, 'a', 'b')
        await channel.send_batch(packets)
        secure.send_json.assert_awaited_once_with({'type': 'MESH_BATCH', 'packets': packets})
        for packet in packets:
            self.assertEqual(json.loads(json.loads(await anext(channel))['d']), packet)
        secure.receive_json.assert_awaited_once()
        secure.receive_json.return_value = {'type': 'MESH_BATCH', 'packets': [packets[0], {'type': 'PULL'}]}
        with self.assertRaises(PermissionError): await anext(channel)
        self.assertFalse(channel._received)
        for bad in ([], packets * 100, [{'type': 'DMP_C_DATA', 'body': 'x' * (512 * 1024)}]):
            with self.assertRaises(PermissionError): await channel.send_batch(bad)
