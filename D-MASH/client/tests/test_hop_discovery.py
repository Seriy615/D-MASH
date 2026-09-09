import asyncio
import copy
import json
import secrets
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

from backend.database import DatabaseManager
from backend.dnss_mailbox import DnssMailbox
from backend.hop_discovery import HopDiscovery, discovery_tag, validate_discovery
from backend.network import P2PNode
from backend.node_session import NodeChannel
from backend.secure_session import b64
from backend.tact import TactEngine
from test_tact import Clock
from test_transport import FakeNodeCrypto


class DiscoveryTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.clock = Clock()
        self.nodes, self.engines, self.wire = [], [], []
        self.authorized = True
        for i in range(4):
            db = DatabaseManager(str(Path(self.tmp.name) / f'{i}.db'))
            db.set_node_crypto(FakeNodeCrypto()); await db.connect()
            node = P2PNode(db, can_route=True, can_accept_devices=True)
            node.transport.hop_discovery = HopDiscovery(node.transport, clock=self.clock.time)
            node.transport.hop_routes.clock = self.clock.time
            self.nodes.append(node)
            self.engines.append(TactEngine(db, node, clock=self.clock, retry_delay=.01))
        self.mail = DnssMailbox(Path(self.tmp.name) / 'mail.db')
        await self.mail.connect()
        self.nodes[-1].transport.v3_mailbox = self.mail
        for a, b in ((0, 1), (1, 2), (2, 3)):
            self.link(a, b); self.link(b, a)
        for locator, owner in (('destination-one', '11' * 32), ('destination-two', '22' * 32)):
            await self.nodes[-1].transport.register_inbound_locator(locator, blind_dnss=owner,
                authority_check=lambda: self.authorized)

    def link(self, source, target):
        async def send(packets):
            NodeChannel._validate_batch(packets)
            self.wire.append((source, target, copy.deepcopy(packets)))
            for packet in packets:
                await self.nodes[target]._process_envelope(json.dumps({'t': 'REAL', 'd': json.dumps(packet)}), str(source))
        self.nodes[source].active_connections[str(target)] = SimpleNamespace(send_batch=send)

    async def asyncTearDown(self):
        for engine in self.engines: await engine.close()
        for node in self.nodes:
            node.transport.hop_routes.close(); node.transport.hop_discovery.close()
            await node.system_db.close()
        await self.mail.close()
        self.tmp.cleanup()

    async def advance_until(self, condition, steps=30):
        for _ in range(steps):
            if condition(): return
            self.clock.advance(self.clock.time() + .5)
            await asyncio.sleep(.005)
        self.assertTrue(condition(), 'mesh failed to reach expected state')

    def ready(self, owner, route):
        return self.nodes[0].transport.hop_discovery.status(owner, route)

    async def establish(self, owner='sender-dnss', locator='destination-one'):
        await self.nodes[0].transport.hop_discovery.start(owner, locator)
        await self.advance_until(lambda: self.ready(owner, locator)['state'] == 'ROUTE_READY')
        return self.ready(owner, locator)['hop_route_label']

    async def test_probe_installs_four_different_labels_and_delivers_opaque_ciphertext(self):
        label = await self.establish()
        replies = [p for _, _, batch in self.wire for p in batch if p['type'] == 'HOP_REPLY_V3']
        self.assertEqual(len({label, *(p['hop_route_label'] for p in replies)}), 4)
        self.assertEqual(len({p['trajectory'] for p in replies}), 3)
        self.assertNotIn('destination-one', json.dumps(self.wire))
        self.assertNotIn('sender-dnss', json.dumps(self.wire))
        before = len(self.wire)
        cipher = b64(secrets.token_bytes(100))
        result = await self.nodes[0].transport.submit_hop_envelope('sender-dnss', label, {'version': 1, 'ciphertext': cipher})
        self.assertEqual(result.state, 'SUBMITTED_TO_ENTRY')
        await self.advance_until(lambda: all(not n.transient_transport_outbox for n in self.nodes))
        data = [p for _, _, batch in self.wire[before:] for p in batch if p['type'] == 'HOP_DATA_V3']
        self.assertEqual(len(data), 3)
        self.assertEqual(len({p['hop_route_label'] for p in data}), 3)
        self.assertTrue(all(p['envelope']['ciphertext'] == cipher for p in data))
        deliveries = []
        async def collect(value): deliveries.append(value)
        await self.mail.drain('11' * 32, collect, 'pull')
        self.assertEqual(deliveries[0]['entries'][0]['ciphertext'], cipher)
        for node in self.nodes:
            async with node.system_db.conn.execute('SELECT count(*) FROM outbox') as cursor:
                self.assertEqual((await cursor.fetchone())[0], 0)

    async def test_different_pairs_share_local_roads_not_delivery_labels_or_dnss(self):
        source = self.nodes[0].transport
        for owner, route in (('alice-device', 'destination-one'), ('eve-device', 'destination-two')):
            await source.hop_discovery.start(owner, route)
        await self.advance_until(lambda: all(self.ready(o, r)['state'] == 'ROUTE_READY'
            for o, r in (('alice-device', 'destination-one'), ('eve-device', 'destination-two'))))
        first = self.ready('alice-device', 'destination-one')['hop_route_label']
        second = self.ready('eve-device', 'destination-two')['hop_route_label']
        self.assertNotEqual(first, second)
        labels = [first, second]
        roads = []
        for index, node in enumerate(self.nodes):
            owners = ['alice-device', 'eve-device'] if index == 0 else [str(index - 1)] * 2
            role = 'DEVICE' if index == 0 else 'NODE'
            rows = [node.transport.hop_routes.resolve(role, owner, label) for owner, label in zip(owners, labels)]
            self.assertEqual(rows[0]['ncrh_in'], rows[1]['ncrh_in'])
            roads.append(rows[0]['ncrh_in'])
            if index < 3:
                labels = [r['outgoing_label'] for r in rows]
                self.assertNotEqual(*labels)
            else:
                self.assertNotEqual(rows[0]['mailbox_alias'], rows[1]['mailbox_alias'])
        self.assertEqual(len(set(roads)), 4, 'no global NCRH across the trajectory')
        self.assertIsNone(source.hop_routes.resolve('DEVICE', 'eve-device', first))
        for owner, label in (('alice-device', first), ('eve-device', second)):
            await source.submit_hop_envelope(owner, label, {'version': 1, 'ciphertext': b64(b'opaque')})
        await self.advance_until(lambda: all(not n.transient_transport_outbox for n in self.nodes))
        batches = [batch for src, dst, batch in self.wire if src == 0 and dst == 1 and batch[0]['type'] == 'HOP_DATA_V3']
        self.assertEqual(len(batches[-1]), 2)

    async def test_wrong_reply_peer_replay_and_expired_tokens_are_rejected(self):
        discovery = self.nodes[0].transport.hop_discovery
        await discovery.start('sender', 'destination-one')
        probe = self.nodes[0].transient_transport_outbox[0]['packet']
        forged = {'type': 'HOP_REPLY_V3', 'return_token': probe['return_token'], 'hop_route_label': 'a' * 64,
            'trajectory': 'b' * 64, 'metric': 0, 'lifetime': 60}
        with self.assertRaises(PermissionError): await discovery.receive_reply(forged, 'attacker')
        await self.advance_until(lambda: self.ready('sender', 'destination-one')['state'] == 'ROUTE_READY')
        with self.assertRaises(PermissionError): await discovery.receive_reply(forged, '1')
        self.assertEqual(self.ready('other-sender', 'destination-one')['state'], 'ROUTE_UNKNOWN')
        await discovery.start('sender', 'unknown-destination')
        pending = self.nodes[0].transient_transport_outbox[0]['packet']
        discovery.note_sent(pending, ['1'])
        self.clock.now += 61
        with self.assertRaises(PermissionError): await discovery.receive_reply({**forged, 'return_token': pending['return_token']}, '1')

    async def test_unregistered_destination_cannot_install_a_delivery_binding(self):
        self.authorized = False
        await self.nodes[0].transport.hop_discovery.start('sender', 'destination-one')
        for _ in range(8):
            self.clock.advance(self.clock.time() + .5); await asyncio.sleep(.005)
        self.assertEqual(self.ready('sender', 'destination-one')['state'], 'ROUTE_UNKNOWN')
        self.assertFalse(self.nodes[-1].transport.hop_routes._rows)

    async def test_enqueue_failure_rolls_back_pending_probe_for_retry(self):
        node = self.nodes[0]
        original = node.enqueue_transport_packet
        node.enqueue_transport_packet = AsyncMock(side_effect=BufferError('full'))
        with self.assertRaises(BufferError): await node.transport.hop_discovery.start('sender', 'destination-one')
        node.enqueue_transport_packet = original
        label = await self.establish('sender')
        self.assertTrue(label)

    async def test_wire_schema_rejects_raw_route_and_global_ncrh_fields(self):
        probe = {'type': 'HOP_PROBE_V3', 'id': 'a' * 64, 'return_token': 'b' * 64,
            'discovery_tag': discovery_tag('target'), 'hop_limit': 15}
        validate_discovery(probe)
        for field in ('route_id', 'back_route_id', 'ncrh', 'account_id'):
            with self.assertRaises(ValueError): validate_discovery({**probe, field: 'leak'})
        with self.assertRaises(ValueError): validate_discovery({**probe, 'hop_limit': True})

    async def test_revoked_destination_label_cannot_fall_back_to_legacy_mailbox(self):
        label = await self.establish()
        await self.nodes[-1].transport.unregister_inbound_locator('destination-one')
        await self.nodes[0].transport.submit_hop_envelope('sender-dnss', label, {'version': 1, 'ciphertext': b64(b'opaque')})
        for _ in range(8):
            self.clock.advance(self.clock.time() + .5); await asyncio.sleep(.005)
        async with self.nodes[-1].system_db.conn.execute('SELECT count(*) FROM offline_mailbox') as cursor:
            self.assertEqual((await cursor.fetchone())[0], 0)
        self.assertTrue(self.engines[-1]._unresolved)

    async def test_cycle_is_deduplicated_and_zero_hop_probe_cannot_forward(self):
        self.link(0, 2); self.link(2, 0)
        await self.establish()
        probes = [p for _, _, batch in self.wire for p in batch if p['type'] == 'HOP_PROBE_V3']
        self.assertLessEqual(len(probes), 8)
        before = len(self.nodes[1].transient_transport_outbox)
        await self.nodes[1].transport.hop_discovery.receive_probe({**probes[0], 'id': 'f' * 64, 'hop_limit': 0}, '0')
        self.assertEqual(len(self.nodes[1].transient_transport_outbox), before)

    async def test_capacity_failure_does_not_leave_a_phantom_pending_probe(self):
        discovery = self.nodes[0].transport.hop_discovery
        discovery.capacity = 1
        with self.assertRaises(BufferError): await discovery.start('sender', 'destination-one')
        self.assertFalse(discovery._rows)
