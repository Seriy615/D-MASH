import base64
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

from nacl.exceptions import CryptoError
from backend.hop_routes import HopRoutes, validate_hop_packet
from backend.network import P2PNode
from backend.database import DatabaseManager
from backend.tact import TactEngine
from backend.node_session import NodeChannel
from test_transport import FakeNodeCrypto
from test_tact import Clock, eventually


def packet(label):
    return dict(type='HOP_DATA_V3', id='opaque-packet', hop_route_label=label,
                envelope={'version': 1, 'ciphertext': base64.b64encode(b'opaque-device-ciphertext').decode()})


class HopRouteTests(unittest.TestCase):
    def test_scoped_labels_and_local_ncrh_are_encrypted(self):
        table = HopRoutes()
        outgoing = 'a' * 64
        label = table.issue('NODE', 'upstream', next_peer='downstream', outgoing_label=outgoing, ncrh_in='b' * 64)
        route = table.resolve('NODE', 'upstream', label)
        self.assertEqual(route['next_peer'], 'downstream')
        self.assertNotEqual(label, outgoing)
        self.assertNotEqual(route['ncrh_in'], route['ncrh_out'])
        self.assertIsNone(table.resolve('NODE', 'other-peer', label))
        self.assertIsNone(table.resolve('DEVICE', 'upstream', label))
        stored = repr(table._rows)
        for secret in (label, outgoing, 'upstream', 'downstream', route['ncrh_in'], route['ncrh_out']):
            self.assertNotIn(secret, stored)
        other = HopRoutes()
        self.assertNotEqual(table._index('NODE', 'upstream', label), other._index('NODE', 'upstream', label))
        self.assertIsNone(other.resolve('NODE', 'upstream', label))

    def test_expiration_capacity_revocation_and_shutdown(self):
        now = [0]
        table = HopRoutes(clock=lambda: now[0], capacity=1)
        label = table.issue('DEVICE', 'blind-dnss', mailbox_alias='blind-mailbox', ttl=1)
        with self.assertRaises(BufferError): table.issue('NODE', 'peer', mailbox_alias='another')
        now[0] = 1
        self.assertIsNone(table.resolve('DEVICE', 'blind-dnss', label))
        label = table.issue('NODE', 'peer', mailbox_alias='another')
        self.assertTrue(table.revoke('NODE', 'peer', label))
        self.assertFalse(table.revoke('NODE', 'peer', label))
        table.close()
        self.assertFalse(table._rows)
        with self.assertRaises(RuntimeError): table.resolve('NODE', 'peer', label)

    def test_ciphertext_tampering_fails_closed(self):
        table = HopRoutes()
        label = table.issue('NODE', 'peer', mailbox_alias='blind')
        index = table._index('NODE', 'peer', label)
        damaged = bytearray(table._rows[index]); damaged[-1] ^= 1
        table._rows[index] = bytes(damaged)
        with self.assertRaises(CryptoError): table.resolve('NODE', 'peer', label)

    def test_wire_rejects_route_ids_metadata_and_invalid_ciphertext(self):
        good = packet('a' * 64)
        validate_hop_packet(good)
        NodeChannel._validate_batch([good])
        for bad in ({**good, 'route_id': 'raw-route'}, {**good, 'ncrh': 'global'},
                    {**good, 'envelope': {'version': 1, 'ciphertext': '%%%'}},
                    {**good, 'envelope': {**good['envelope'], 'account': 'raw-account'}}):
            with self.assertRaises(ValueError): validate_hop_packet(bad)
            with self.assertRaises(ValueError): NodeChannel._validate_batch([good, bad])


class HopPipelineTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.nodes = []
        self.clocks = []
        self.engines = []
        for i in range(3):
            db = DatabaseManager(str(Path(self.tmp.name) / f'{i}.db'))
            db.set_node_crypto(FakeNodeCrypto()); await db.connect()
            node = P2PNode(db, can_route=True, can_accept_devices=True)
            clock = Clock()
            self.nodes.append(node); self.clocks.append(clock)
            self.engines.append(TactEngine(db, node, clock=clock, retry_delay=.01))

    async def asyncTearDown(self):
        for node, engine in zip(self.nodes, self.engines):
            await engine.close()
            node.transport.hop_routes.close()
            await node.system_db.close()
        self.tmp.cleanup()

    async def test_three_hops_rewrite_labels_keep_ciphertext_and_batch_windows(self):
        a, b, c = self.nodes
        # Explicit fixture installation: production Probe establishment is a
        # separate migration, not claimed by this data-plane acceptance test.
        lc = c.transport.hop_routes.issue('NODE', 'B', mailbox_alias='blind-dnss-locator')
        lb = b.transport.hop_routes.issue('NODE', 'A', next_peer='C', outgoing_label=lc)
        la = a.transport.hop_routes.issue('NODE', 'ENTRY', next_peer='B', outgoing_label=lb)
        self.assertEqual(len({la, lb, lc}), 3)
        received = []
        async def send_b(packets):
            received.append(packets)
            for p in packets: await b.transport.receive_hop_data(p, 'A')
        async def send_c(packets):
            received.append(packets)
            for p in packets: await c.transport.receive_hop_data(p, 'B')
        a.active_connections['B'] = SimpleNamespace(send_batch=send_b)
        b.active_connections['C'] = SimpleNamespace(send_batch=send_c)
        c.transport._store_mailbox = AsyncMock()
        original = packet(la)
        await a.transport.receive_hop_data(original, 'ENTRY')
        self.clocks[0].advance(.5)
        await eventually(lambda: bool(b.transient_transport_outbox))
        self.assertEqual(b.transient_transport_outbox[0]['packet']['hop_route_label'], lb)
        self.assertEqual(self.clocks[1].arms, [.5])
        self.clocks[1].advance(.5)
        await eventually(lambda: bool(c.transient_transport_outbox))
        self.clocks[2].advance(.5)
        await eventually(lambda: c.transport._store_mailbox.await_count == 1)
        for wire in (received[0][0], received[1][0]):
            self.assertEqual(wire['envelope'], original['envelope'])
            self.assertNotIn('route_id', wire)
            self.assertNotIn('ncrh', wire)
        self.assertEqual(c.transport._store_mailbox.call_args.args[0], 'blind-dnss-locator')

    async def test_wrong_peer_and_revocation_before_flush(self):
        node = self.nodes[0]
        label = node.transport.hop_routes.issue('NODE', 'owner', next_peer='next', outgoing_label='f' * 64)
        with self.assertRaises(PermissionError): await node.transport.receive_hop_data(packet(label), 'attacker')
        self.assertFalse(node.transient_transport_outbox)
        sender = SimpleNamespace(send_batch=AsyncMock())
        node.active_connections['next'] = sender
        await node.transport.receive_hop_data(packet(label), 'owner')
        node.transport.hop_routes.revoke('NODE', 'owner', label)
        self.clocks[0].advance(.5)
        await eventually(lambda: bool(self.engines[0]._unresolved))
        sender.send_batch.assert_not_called()
        self.assertEqual(len(node.transient_transport_outbox), 1)
