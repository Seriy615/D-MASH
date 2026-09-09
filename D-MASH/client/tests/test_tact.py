import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

from backend.database import DatabaseManager
from backend.tact import TactEngine
from backend.node_session import NodeChannel, MAX_BATCH_PACKETS, MAX_BATCH_BYTES, canonical
from backend.network import P2PNode
from test_transport import FakeNodeCrypto


class Clock:
    """Deterministic one-shot clock; send/DB tasks run on the real event loop."""
    def __init__(self):
        self.now = 0.0
        self.handles = []
        self.arms = []

    def time(self): return self.now

    def call_at(self, deadline, callback):
        handle = SimpleNamespace(deadline=deadline, callback=callback, cancelled=False)
        handle.cancel = lambda: setattr(handle, 'cancelled', True)
        self.handles.append(handle)
        self.arms.append(deadline)
        return handle

    def advance(self, now):
        self.now = now
        for handle in list(self.handles):
            if not handle.cancelled and handle.deadline <= now:
                handle.cancelled = True
                handle.callback()

    @property
    def active(self): return [h for h in self.handles if not h.cancelled]


async def eventually(predicate):
    async with asyncio.timeout(2):
        while not predicate():
            await asyncio.sleep(.001)


class TactTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = DatabaseManager(str(Path(self.tmp.name) / 'node.db'))
        self.db.set_node_crypto(FakeNodeCrypto())
        await self.db.connect()
        self.a = SimpleNamespace(send_batch=AsyncMock())
        self.b = SimpleNamespace(send_batch=AsyncMock())
        self.c = SimpleNamespace(send_batch=AsyncMock())
        self.node = P2PNode(self.db, can_route=True)
        self.node.active_connections = {'a': self.a, 'b': self.b, 'c': self.c}
        self.routes = {'r': 'a'}
        async def resolve(item):
            if item['packet']['type'] == 'ROUTE_PROBE_V2':
                return tuple(self.node.active_connections) or None
            peer = self.routes.get(item['packet']['route_id'])
            return (peer,) if peer else None
        self.node.resolve_transport_targets = AsyncMock(side_effect=resolve)
        self.clock = Clock()
        self.tact = TactEngine(self.db, self.node, clock=self.clock, retry_delay=.01)
        self.lifecycle = None

    async def asyncTearDown(self):
        if self.lifecycle:
            self.lifecycle.cancel()
            await asyncio.gather(self.lifecycle, return_exceptions=True)
        await self.tact.close()
        await self.db.close()
        self.tmp.cleanup()

    async def enqueue(self, identity, route='r', **fields):
        packet = {'type': 'DMP_C_DATA', 'id': identity, 'route_id': route, **fields}
        await self.node.enqueue_transport_packet(packet, next_hop_id='stale')

    def ids(self, channel):
        return [[p['id'] for p in call.args[0]] for call in channel.send_batch.await_args_list]

    async def test_idle_has_no_timer_or_periodic_tasks(self):
        self.lifecycle = asyncio.create_task(self.tact.start())
        await asyncio.sleep(.02)
        self.clock.advance(100)
        self.assertEqual(self.clock.arms, [])
        self.assertIsNone(self.tact._dispatch_task)
        self.assertFalse(self.tact._workers)
        self.a.send_batch.assert_not_called()
        self.clock.advance(100.123)
        await self.enqueue('first after idle')
        self.assertAlmostEqual(self.tact.deadline, 100.623)

    async def test_first_arrival_fixed_deadline_and_atomic_snapshot_example(self):
        await self.enqueue('P1')
        timer = self.tact._timer
        for at, name in ((.12, 'P2'), (.34, 'P3'), (.499, 'P4')):
            self.clock.advance(at)
            await self.enqueue(name)
            self.assertIs(self.tact._timer, timer)
        self.assertEqual(self.clock.arms, [.5])
        self.node.resolve_transport_targets.assert_not_called()
        self.clock.advance(.5)
        self.assertEqual([i['packet']['id'] for i in self.tact._snapshots[0]], ['P1', 'P2', 'P3', 'P4'])
        self.assertEqual(self.tact._incoming, [])
        self.assertIsNone(self.tact.deadline)
        self.clock.advance(.51)
        await self.enqueue('P5')
        self.assertAlmostEqual(self.tact.deadline, 1.01)
        await eventually(lambda: self.a.send_batch.await_count == 1)
        self.assertEqual(self.ids(self.a), [['P1', 'P2', 'P3', 'P4']])
        self.clock.advance(1.009)
        self.assertEqual(self.a.send_batch.await_count, 1)
        self.clock.advance(1.01)
        await eventually(lambda: self.a.send_batch.await_count == 2)
        self.assertEqual(self.ids(self.a)[1], ['P5'])
        self.assertFalse(self.clock.active)

    async def test_overdue_callback_cannot_extend_window(self):
        await self.enqueue('old')
        self.clock.now = .51  # enqueue scheduled before the delayed callback
        await self.enqueue('new')
        self.assertEqual([i['packet']['id'] for i in self.tact._snapshots[0]], ['old'])
        self.assertEqual([i['packet']['id'] for i in self.tact._incoming], ['new'])
        self.assertAlmostEqual(self.tact.deadline, 1.01)

    async def test_slow_peer_does_not_delay_next_window_or_other_peer(self):
        gate = asyncio.Event()
        async def slow(packets): await gate.wait()
        self.a.send_batch.side_effect = slow
        await self.enqueue('P1')
        self.clock.advance(.5)
        await eventually(lambda: self.a.send_batch.await_count == 1)
        self.clock.advance(.51)
        await self.enqueue('P5')
        self.routes['other'] = 'b'
        await self.enqueue('P6', 'other')
        self.clock.advance(1.01)
        self.assertIsNone(self.tact.deadline)
        await eventually(lambda: self.b.send_batch.await_count == 1)
        self.assertEqual(self.ids(self.b), [['P6']])
        self.assertEqual(self.a.send_batch.await_count, 1)
        self.assertEqual(len(self.tact._peer_queues['a']), 2)
        gate.set()
        await eventually(lambda: not self.node.transient_transport_outbox)
        self.assertEqual(self.ids(self.a), [['P1'], ['P5']])

    async def test_resolve_actual_blind_routes_at_close_and_regroup(self):
        self.node.resolve_transport_targets = P2PNode.resolve_transport_targets.__get__(self.node)
        for i in range(1, 5):
            await self.db.add_route_alias(self.node.transport._blind('r' + str(i)), 'stale', 10)
            await self.enqueue('P' + str(i), 'r' + str(i))
        for i, peer in enumerate(('a', 'b', 'a', 'c'), 1):
            await self.db.add_route_alias(self.node.transport._blind('r' + str(i)), peer, 1)
        self.clock.advance(.5)
        await eventually(lambda: not self.node.transient_transport_outbox)
        self.assertEqual(self.ids(self.a), [['P1', 'P3']])
        self.assertEqual(self.ids(self.b), [['P2']])
        self.assertEqual(self.ids(self.c), [['P4']])

    async def test_count_splitting_all_batches_in_one_window(self):
        for i in range(259): await self.enqueue(str(i))
        self.clock.advance(.5)
        await eventually(lambda: not self.node.transient_transport_outbox)
        self.assertEqual([len(x) for x in self.ids(self.a)], [128, 128, 3])
        self.assertEqual(sum(self.ids(self.a), []), [str(i) for i in range(259)])
        self.assertEqual(self.clock.arms, [.5])

    async def test_canonical_byte_splitting(self):
        for i in range(10): await self.enqueue(str(i), body='ж' * 20000)
        self.clock.advance(.5)
        await eventually(lambda: not self.node.transient_transport_outbox)
        self.assertEqual([len(x) for x in self.ids(self.a)], [4, 4, 2])
        for call in self.a.send_batch.await_args_list:
            self.assertLessEqual(len(canonical(call.args[0])), MAX_BATCH_BYTES)
            NodeChannel._validate_batch(call.args[0])

    async def test_exact_canonical_byte_limit_includes_array_separators(self):
        for i, size in enumerate((131071, 131071, 131071, 131070)):
            packet = {'type': 'DMP_C_DATA', 'id': str(i), 'route_id': 'r', 'body': ''}
            packet['body'] = 'x' * (size - len(canonical(packet)))
            await self.node.enqueue_transport_packet(packet)
        await self.enqueue('overflow')
        self.clock.advance(.5)
        await eventually(lambda: not self.node.transient_transport_outbox)
        self.assertEqual([len(x) for x in self.ids(self.a)], [4, 1])
        self.assertEqual(len(canonical(self.a.send_batch.await_args_list[0].args[0])), MAX_BATCH_BYTES)

    async def test_failed_send_retained_fifo_across_windows(self):
        self.a.send_batch.side_effect = OSError('offline')
        await self.enqueue('first')
        self.clock.advance(.5)
        await eventually(lambda: self.a.send_batch.await_count == 1)
        self.clock.advance(.51)
        await self.enqueue('second')
        self.clock.advance(1.01)
        await eventually(lambda: len(self.tact._peer_queues['a']) == 2)
        self.assertEqual(len(self.node.transient_transport_outbox), 2)
        self.a.send_batch.side_effect = None
        await eventually(lambda: not self.node.transient_transport_outbox)
        self.assertEqual(self.ids(self.a)[-2:], [['first'], ['second']])

    async def test_partial_broadcast_retry_does_not_resend_success(self):
        self.b.send_batch.side_effect = OSError('offline')
        await self.node.enqueue_transport_packet({'type': 'ROUTE_PROBE_V2', 'id': 'probe'})
        self.clock.advance(.5)
        await eventually(lambda: self.a.send_batch.await_count and self.b.send_batch.await_count and self.c.send_batch.await_count)
        self.assertEqual(self.node.transient_transport_outbox[0]['pending_peers'], {'b'})
        self.b.send_batch.side_effect = None
        await eventually(lambda: not self.node.transient_transport_outbox)
        self.a.send_batch.assert_awaited_once()
        self.c.send_batch.assert_awaited_once()

    async def test_cancelled_worker_retains_head_and_restarts(self):
        gate = asyncio.Event()
        async def slow(packets): await gate.wait()
        self.a.send_batch.side_effect = slow
        await self.enqueue('one')
        self.clock.advance(.5)
        await eventually(lambda: self.a.send_batch.await_count == 1)
        worker = self.tact._workers['a']
        worker.cancel()
        await asyncio.gather(worker, return_exceptions=True)
        self.assertEqual(len(self.node.transient_transport_outbox), 1)
        gate.set()
        await eventually(lambda: not self.node.transient_transport_outbox)
        self.assertEqual(self.ids(self.a), [['one'], ['one']])

    async def test_shutdown_retains_inflight_and_open_window_for_restart(self):
        gate = asyncio.Event()
        async def slow(packets): await gate.wait()
        self.a.send_batch.side_effect = slow
        await self.enqueue('old')
        self.clock.advance(.5)
        await eventually(lambda: self.a.send_batch.await_count == 1)
        self.clock.advance(.51)
        await self.enqueue('new')
        await self.tact.close()
        self.assertFalse(self.clock.active)
        self.assertEqual(len(self.node.transient_transport_outbox), 2)
        gate.set()
        self.lifecycle = asyncio.create_task(self.tact.start())
        await eventually(lambda: self.a.send_batch.await_count == 2)
        self.clock.advance(1.01)
        await eventually(lambda: not self.node.transient_transport_outbox)
        self.assertEqual(self.ids(self.a)[-2:], [['old'], ['new']])

    async def test_cancel_during_resolution_preserves_already_resolved_work(self):
        entered = asyncio.Event()
        async def resolve(item):
            if item['packet']['id'] == 'second':
                entered.set()
                await asyncio.Future()
            return ('a',)
        self.node.resolve_transport_targets.side_effect = resolve
        await self.enqueue('first'); await self.enqueue('second')
        self.clock.advance(.5)
        await entered.wait()
        await self.tact.close()
        self.assertEqual([i['packet']['id'] for i in self.tact._unresolved], ['second'])
        self.assertEqual(self.tact._peer_queues['a'][0][0]['packet']['id'], 'first')

    async def test_empty_snapshot_sends_nothing(self):
        self.tact._close_window()
        await asyncio.sleep(0)
        self.assertFalse(self.tact._snapshots)
        self.assertFalse(self.clock.active)
        self.a.send_batch.assert_not_called()

    async def test_control_plane_bypasses_open_window(self):
        await self.enqueue('mesh')
        secure = SimpleNamespace(send_json=AsyncMock())
        channel = NodeChannel(secure, 'local', 'remote')
        await channel.send(json.dumps({'t': 'DUMMY'}))
        secure.send_json.assert_awaited_once_with({'type': 'NODE_CONTROL', 'control': 'KEEPALIVE'})
        self.assertEqual(self.clock.arms, [.5])
        self.a.send_batch.assert_not_called()

    async def test_missing_route_does_not_fall_back_to_old_next_hop(self):
        self.node.resolve_transport_targets = P2PNode.resolve_transport_targets.__get__(self.node)
        await self.enqueue('one', 'missing')
        self.clock.advance(.5)
        await eventually(lambda: bool(self.tact._unresolved))
        self.assertFalse(self.tact._workers)
        await self.db.add_route_alias(self.node.transport._blind('missing'), 'b', 1)
        await eventually(lambda: not self.node.transient_transport_outbox)
        self.assertEqual(self.ids(self.b), [['one']])
        self.a.send_batch.assert_not_called()

    async def test_route_becoming_local_delivers_without_network_batch(self):
        self.node.resolve_transport_targets = P2PNode.resolve_transport_targets.__get__(self.node)
        await self.enqueue('local', 'destination')
        alias = self.node.transport._blind('destination')
        await self.db.add_route_alias(alias, 'LOCAL', 0, is_local=True)
        self.node.transport._store_mailbox = AsyncMock()
        self.clock.advance(.5)
        await eventually(lambda: not self.node.transient_transport_outbox)
        self.node.transport._store_mailbox.assert_awaited_once()
        self.a.send_batch.assert_not_called()

    async def test_disconnected_peer_retains_work_until_reconnect(self):
        del self.node.active_connections['a']
        await self.enqueue('one')
        self.clock.advance(.5)
        await eventually(lambda: 'a' in self.tact._workers)
        self.node.active_connections['a'] = self.a
        await eventually(lambda: not self.node.transient_transport_outbox)
        self.assertEqual(self.ids(self.a), [['one']])

    async def test_enqueue_limits_include_inflight_and_immutable_snapshot(self):
        packet = {'type': 'DMP_C_DATA', 'route_id': 'r', 'envelope': {'ciphertext': 'original'}}
        await self.node.enqueue_transport_packet(packet)
        packet['envelope']['ciphertext'] = 'changed'
        self.assertEqual(self.node.transient_transport_outbox[0]['packet']['envelope']['ciphertext'], 'original')
        with self.assertRaises(ValueError):
            await self.enqueue('huge', body='x' * (128 * 1024))
        with self.assertRaises(PermissionError):
            await self.node.enqueue_transport_packet({'type': 'PULL'})
        self.node.transient_transport_outbox = [self.node.transient_transport_outbox[0]] * 4096
        with self.assertRaises(BufferError): await self.enqueue('overflow')

    async def test_durable_failed_send_retains_row(self):
        await self.db.conn.execute('INSERT INTO outbox (packet_id, next_hop_hash, packet_json) VALUES (?, ?, ?)',
            ('old', 'blind:a', json.dumps({'type': 'DMP_C_DATA', 'id': 'old', 'route_id': 'r'})))
        await self.db.conn.commit()
        self.a.send_batch.side_effect = OSError('offline')
        self.lifecycle = asyncio.create_task(self.tact.start())
        await eventually(lambda: bool(self.clock.active))
        self.clock.advance(.5)
        await eventually(lambda: self.a.send_batch.await_count == 1)
        async with self.db.conn.execute('SELECT count(*) FROM outbox') as cursor:
            self.assertEqual((await cursor.fetchone())[0], 1)
        self.a.send_batch.side_effect = None
        await eventually(lambda: not self.node.transient_transport_outbox)
        async with self.db.conn.execute('SELECT count(*) FROM outbox') as cursor:
            self.assertEqual((await cursor.fetchone())[0], 0)


class BatchTests(unittest.IsolatedAsyncioTestCase):
    async def test_batch_preserves_order_and_validates_all_before_dispatch(self):
        packets = [{'type': 'HOP_DATA_V3', 'id': str(i), 'hop_route_label': 'a' * 64,
                    'envelope': {'version': 1, 'ciphertext': 'b3BhcXVl'}} for i in range(3)]
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
