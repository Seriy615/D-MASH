"""Authenticated recovery acceptance: real channels, Probe, labels and DATA."""
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

    async def send_data(self, node, locator):
        status = node.transport.hop_probes.status('sender', locator)
        await node.enqueue_transport_packet({'type': 'HOP_DATA_V3', 'id': 'recovery-data',
            'hop_route_label': status['hop_route_label'],
            'envelope': {'version': 1, 'ciphertext': 'b3BhcXVl'}}, hop_owner='sender')
