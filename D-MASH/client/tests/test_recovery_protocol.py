"""Authenticated recovery acceptance: real channels, Probe, labels and DATA."""
import asyncio
import json
import tempfile
import unittest
from contextlib import AsyncExitStack
from pathlib import Path
from unittest.mock import AsyncMock, patch

from nacl.signing import SigningKey
from websockets.server import serve

from backend.crypto import NodeCryptoManager
from backend.database import DatabaseManager
from backend.network import P2PNode
from backend.tact import TactEngine
from backend.hop_probes import origin_tag
from backend import node_session


class RecoveryProtocolTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.nodes = []
        self.patches = [patch.object(node_session, 'NODE_POW_DIFFICULTY', 4),
                        patch.object(NodeCryptoManager, 'verify_node_pow', return_value=True)]
        for item in self.patches: item.start()
        self.wire = []
        original = node_session.NodeChannel.send_packet
        async def capture(channel, packet):
            self.wire.append(json.loads(json.dumps(packet)))
            return await original(channel, packet)
        self.capture = patch.object(node_session.NodeChannel, 'send_packet', capture)
        self.capture.start()

    async def make_node(self, identity=None, base=None):
        db = DatabaseManager(str(Path(self.tmp.name) / f'{len(self.nodes)}.db'))
        db.set_node_crypto(NodeCryptoManager(identity or SigningKey.generate().encode().hex(), base or b'x' * 32))
        await db.connect()
        node = P2PNode(db, can_route=True)
        TactEngine(db, node)
        self.nodes.append(node)
        return node

    async def stop_node(self, node):
        await node.transport.hop_probes.close()
        if node.transport_batcher: await node.transport_batcher.close()
        for channel in list(node.active_connections.values()): await channel.close()
        for task in list(node.connection_tasks): task.cancel()
        await asyncio.gather(*node.connection_tasks, return_exceptions=True)
        await node.system_db.close()

    async def asyncTearDown(self):
        for node in self.nodes:
            if node.transport.hop_probes._closed: continue
            await self.stop_node(node)
        self.capture.stop()
        for item in self.patches: item.stop()
        self.tmp.cleanup()

    async def eventually(self, predicate):
        for _ in range(500):
            if predicate(): return
            await asyncio.sleep(.01)
        self.fail('recovery did not converge')

    async def test_fork_restart_fresh_labels_and_actual_data(self):
        a = await self.make_node(base=b'a' * 32)
        b = await self.make_node(base=b'b' * 32)
        c = await self.make_node(base=b'c' * 32)
        d = await self.make_node(base=b'd' * 32)
        # Only the initiator owns the mailbox. No forwarding table is seeded.
        locator, alias, owner = 'local-device-locator', 'blind-mailbox', 'local-owner'
        a.transport._v3_authority_checks[alias] = lambda: True
        a.transport._v3_bindings[alias] = owner
        a.transport.hop_probes.register(locator, alias)
        received = AsyncMock()
        a.transport._store_hop_mailbox = received
        await a.transport.hop_probes.start(owner, locator)
        tag = origin_tag(locator)
        def ready(node):
            return node.transport.hop_probes.status('sender', locator).get('state') == 'ROUTE_READY'
        async def connect_all(center):
            async with serve(center._handle_incoming, '127.0.0.1', 0) as server:
                address = f'127.0.0.1:{server.sockets[0].getsockname()[1]}'
                for node in (a, c, d): self.assertTrue(await node.connect_to(address))
                await self.eventually(lambda: ready(c) and ready(d))
                await self.send_data(c, locator)
                await self.eventually(lambda: received.await_count > 0)
                # Yield the connected topology to inspect it before disconnect.
                return center.transport.hop_probes._candidates(tag)[0], c.transport.hop_probes._candidates(tag)[0]
        old_b, old_c = await connect_all(b)
        old_salt = b.system_db.node_crypto.secret_salt
        identity = b.system_db.node_crypto.signing_key.encode().hex()
        old_label = old_c['outgoing_label']
        b_id = b.system_db.node_crypto.node_id
        await self.stop_node(b)
        fresh_b = await self.make_node(identity=identity, base=b'b' * 32)
        self.assertNotEqual(old_salt, fresh_b.system_db.node_crypto.secret_salt)
        self.assertIsNone(fresh_b.transport.hop_routes.resolve('NODE', c.system_db.node_crypto.node_id, old_label))
        # Wait for replacement aliases, not a stale ROUTE_READY cache.
        original_ready = ready
        def ready(node):
            paths = node.transport.hop_probes._candidates(tag)
            return original_ready(node) and any(p['next_peer'] == b_id and p['outgoing_label'] != old_label for p in paths)
        received.reset_mock()
        new_b, new_c = await connect_all(fresh_b)
        self.assertEqual(old_b['ncrh'], new_b['ncrh'])
        self.assertEqual(old_c['ncrh'], new_c['ncrh'])
        self.assertNotEqual(old_label, new_c['outgoing_label'])
        b_prefix = new_b['ncrh']
        outward = [edge['outward'] for edge in fresh_b.transport.hop_probes.graph_snapshot()
                   if edge['ncrh_out'] == b_prefix]
        peers = {item['peer'] for group in outward for item in group}
        self.assertTrue({c.system_db.node_crypto.node_id, d.system_db.node_crypto.node_id} <= peers)
        root_statuses = {packet['state'] for packet in self.wire
                         if packet['type'] == 'HOP_NCRH_STATUS_V1'
                         and packet['ncrh'] == fresh_b.system_db.node_crypto.derive_ncrh_root()}
        self.assertEqual(root_statuses, {'UNKNOWN', 'KNOWN'})
        # Both branches received the identical prefix before extending it.
        self.assertTrue(any(e['ncrh_in'] == b_prefix for e in c.transport.hop_probes.graph_snapshot()))
        self.assertTrue(any(e['ncrh_in'] == b_prefix for e in d.transport.hop_probes.graph_snapshot()))
        advertisements = [p for p in self.wire if p['type'] in {'HOP_PROBE_V3', 'HOP_ROOT_NCRH_V1'}]
        statuses = {(p['request_id'], p['ncrh']) for p in self.wire if p['type'] == 'HOP_NCRH_STATUS_V1'}
        self.assertTrue(advertisements)
        for packet in advertisements:
            self.assertIn((packet['request_id'], packet['ncrh']), statuses)
        acknowledged = set()
        roots = {p['request_id'] for p in advertisements if p['type'] == 'HOP_ROOT_NCRH_V1'}
        for packet in self.wire:
            if packet['type'] == 'HOP_NCRH_STATUS_V1':
                acknowledged.add((packet['request_id'], packet['ncrh']))
            elif packet['type'] == 'HOP_ALIAS_BIND_V1':
                self.assertIn((packet['request_id'], packet['ncrh']), acknowledged)
                self.assertNotIn(packet['request_id'], roots, 'Root knowledge cannot grant DATA authority')
            elif packet['type'] == 'HOP_PROBE_V3':
                self.assertIsNone(packet['hop_route_label'], 'Do not issue capabilities before semantic replies')
        forbidden = {'route_id', 'route_locator', 'back_route_id', 'account_id', 'device_id', 'dnss'}
        for packet in self.wire:
            self.assertFalse(forbidden.intersection(packet))
        self.assertEqual(received.call_args.args[1]['envelope']['ciphertext'], 'b3BhcXVl')

    async def test_blocked_authenticated_peer_does_not_block_other_recovery(self):
        a = await self.make_node(base=b'a' * 32)
        slow = await self.make_node(base=b'b' * 32)
        fast = await self.make_node(base=b'c' * 32)
        async with serve(a._handle_incoming, '127.0.0.1', 0) as server:
            address = f'127.0.0.1:{server.sockets[0].getsockname()[1]}'
            self.assertTrue(await slow.connect_to(address))
            self.assertTrue(await fast.connect_to(address))
            await self.eventually(lambda: len(a.active_connections) == 2)
            await self.eventually(lambda: not a.transport.hop_probes._pending)
            slow_id = slow.system_db.node_crypto.node_id
            channel = a.active_connections[slow_id]
            entered = asyncio.Event()
            release = asyncio.Event()
            original = channel.send_packet
            async def blocked(packet):
                if packet['type'] == 'HOP_PROBE_V3':
                    entered.set()
                    await release.wait()
                await original(packet)
            channel.send_packet = blocked
            locator, alias = 'initiator', 'blind-box'
            a.transport._v3_authority_checks[alias] = lambda: True
            a.transport._v3_bindings[alias] = 'owner'
            a.transport.hop_probes.register(locator, alias)
            await a.transport.hop_probes.start('owner', locator)
            await asyncio.wait_for(entered.wait(), 1)
            await self.eventually(lambda: fast.transport.hop_probes.status('sender', locator)['state'] == 'ROUTE_READY')
            pending = [(key, value) for key, value in a.transport.hop_probes._pending.items() if value['peer'] == slow_id]
            self.assertTrue(pending)
            request_id = pending[0][0]
            await a.transport.hop_probes._expire_pending(request_id, timeout=0)
            self.assertNotIn(request_id, a.transport.hop_probes._pending)
            self.assertEqual(a.transport.hop_probes._sync[slow_id]['timeouts'], 1)
            release.set()
            await asyncio.sleep(.05)
            self.assertEqual(slow.transport.hop_probes.status('sender', locator)['state'], 'ROUTE_UNKNOWN')
            self.assertEqual(fast.transport.hop_probes.status('sender', locator)['state'], 'ROUTE_READY')

    async def test_downstream_restart_revokes_upstream_capabilities_and_peer_knowledge(self):
        a = await self.make_node(base=b'a' * 32)
        b = await self.make_node(base=b'b' * 32)
        c = await self.make_node(base=b'c' * 32)
        locator, alias = 'restart-origin', 'blind-origin'
        async def register(node):
            node.transport._v3_authority_checks[alias] = lambda: True
            node.transport._v3_bindings[alias] = 'owner'
            node.transport.hop_probes.register(locator, alias)
            node.transport._store_hop_mailbox = AsyncMock()
            await node.transport.hop_probes.start('owner', locator)
        await register(a)
        async with AsyncExitStack() as stack:
            async def listen(node):
                server = await stack.enter_async_context(serve(node._handle_incoming, '127.0.0.1', 0))
                return f'127.0.0.1:{server.sockets[0].getsockname()[1]}'
            self.assertTrue(await b.connect_to(await listen(a)))
            self.assertTrue(await c.connect_to(await listen(b)))
            await self.eventually(lambda: c.transport.hop_probes.status('sender', locator)['state'] == 'ROUTE_READY')
            aid, cid = a.system_db.node_crypto.node_id, c.system_db.node_crypto.node_id
            root_b = b.system_db.node_crypto.derive_ncrh_root()
            bp = b.transport.hop_probes
            await self.eventually(lambda: bp._get('peer-knowledge', [aid, root_b]) is not None)
            old_upstream = c.transport.hop_probes._candidates(origin_tag(locator))[0]['outgoing_label']
            old_device = bp.status('local-sender', locator)['hop_route_label']
            self.assertEqual(b.transport.hop_routes.resolve('NODE', cid, old_upstream)['next_peer'], aid)
            identity = a.system_db.node_crypto.signing_key.encode().hex()
            await self.stop_node(a)
            await self.eventually(lambda: aid not in b.active_connections)
            fresh = await self.make_node(identity=identity, base=b'a' * 32)
            await register(fresh)
            observed = []
            original_reset = bp._reset_peer
            def inspect_reset(peer):
                previous = bp._get('peer-knowledge', [peer, root_b])
                original_reset(peer)
                if peer == aid:
                    observed.append((previous, bp._get('peer-knowledge', [peer, root_b]),
                                     b.transport.hop_routes.resolve('NODE', cid, old_upstream),
                                     b.transport.hop_routes.resolve('DEVICE', 'local-sender', old_device)))
            bp._reset_peer = inspect_reset
            self.assertTrue(await b.connect_to(await listen(fresh)))
            self.assertEqual(len(observed), 1)
            self.assertIsNotNone(observed[0][0])
            self.assertEqual(observed[0][1:], (None, None, None))
            # Transmit the previously valid upstream label over C's real channel.
            rejected = asyncio.Event()
            original_receive = b.transport.receive_hop_data
            async def receive(packet, peer):
                try:
                    await original_receive(packet, peer)
                except PermissionError:
                    if packet['id'] == 'stale-upstream': rejected.set()
                    else: raise
            b.transport.receive_hop_data = receive
            await c.active_connections[b.system_db.node_crypto.node_id].send_packet({
                'type': 'HOP_DATA_V3', 'id': 'stale-upstream', 'hop_route_label': old_upstream,
                'envelope': {'version': 1, 'ciphertext': 'b3BhcXVl'}})
            await asyncio.wait_for(rejected.wait(), 1)
            self.assertFalse(any(item['packet']['id'] == 'stale-upstream' for item in b.transient_transport_outbox))
            await self.eventually(lambda: any(p['outgoing_label'] and p['outgoing_label'] != old_upstream
                for p in c.transport.hop_probes._candidates(origin_tag(locator))))
            await self.send_data(c, locator)
            await self.eventually(lambda: fresh.transport._store_hop_mailbox.called)
            self.assertEqual(fresh.transport._store_hop_mailbox.call_args.args[1]['id'], 'recovery-data')

    async def test_disconnected_exports_sleep_until_authenticated_reconnect(self):
        a = await self.make_node(base=b'a' * 32)
        b = await self.make_node(base=b'b' * 32)
        bp = a.transport.hop_probes
        async with serve(a._handle_incoming, '127.0.0.1', 0) as server:
            address = f'127.0.0.1:{server.sockets[0].getsockname()[1]}'
            self.assertTrue(await b.connect_to(address))
            bid = b.system_db.node_crypto.node_id
            await self.eventually(lambda: bid in a.active_connections)
            await self.eventually(lambda: not bp._pending and not bp._export_tasks)
            entered = asyncio.Event()
            parked = asyncio.Event()
            channel = a.active_connections[bid]
            original_send = channel.send_packet
            async def blocked(packet):
                if packet['type'] == 'HOP_PROBE_V3':
                    entered.set()
                    await parked.wait()
                await original_send(packet)
            channel.send_packet = blocked
            starts = []
            original_flush = bp._flush_exports
            async def count_flush(peer):
                starts.append(peer)
                await original_flush(peer)
            bp._flush_exports = count_flush
            locator, alias = 'dormant-route', 'blind-dormant'
            a.transport._v3_authority_checks[alias] = lambda: True
            a.transport._v3_bindings[alias] = 'owner'
            bp.register(locator, alias)
            await bp.start('owner', locator)
            await asyncio.wait_for(entered.wait(), 1)
            worker = bp._export_tasks[bid]
            identity = b.system_db.node_crypto.signing_key.encode().hex()
            await self.stop_node(b)
            await self.eventually(lambda: bid not in a.active_connections and worker.done())
            self.assertNotIn(bid, bp._export_tasks)
            pending_exports = set(bp._exports)
            self.assertTrue(pending_exports)
            before = len(starts)
            # Covers two old 500ms polling intervals; no worker or timer survives.
            await asyncio.sleep(1.1)
            self.assertEqual(len(starts), before)
            self.assertEqual(bp._exports, pending_exports)
            self.assertNotIn(bid, bp._export_tasks)
            fresh = await self.make_node(identity=identity, base=b'b' * 32)
            self.assertTrue(await fresh.connect_to(address))
            await self.eventually(lambda: fresh.transport.hop_probes.status('sender', locator)['state'] == 'ROUTE_READY')
            self.assertGreater(len(starts), before)
            await self.eventually(lambda: not bp._exports)

    async def send_data(self, node, locator):
        status = node.transport.hop_probes.status('sender', locator)
        await node.enqueue_transport_packet({'type': 'HOP_DATA_V3', 'id': 'recovery-data',
            'hop_route_label': status['hop_route_label'],
            'envelope': {'version': 1, 'ciphertext': 'b3BhcXVl'}}, hop_owner='sender')
