import asyncio
import hashlib
import hmac
from types import SimpleNamespace
import unittest

from backend.crypto import NodeCryptoManager
from backend.hop_probes import HopProbes, origin_tag, validate_probe
from backend.hop_routes import HopRoutes


class HopProbeSemanticsTests(unittest.TestCase):
    def test_origin_tag_is_not_route_id_on_wire(self):
        self.assertNotEqual(origin_tag('route-a'), 'route-a')
        self.assertEqual(len(origin_tag('route-a')), 64)

    def test_probe_schema_has_no_route_or_identity_fields(self):
        packet = {
            'type': 'HOP_PROBE_V3', 'id': 'a' * 64, 'request_id': 'f' * 64,
            'origin_tag': 'b' * 64, 'hop_route_label': 'c' * 64,
            'ncrh': 'e' * 64,
            'metric': 0, 'hop_limit': 15, 'lifetime': 1800,
            'trace': ['d' * 64],
        }
        validate_probe(packet)
        with self.assertRaises(ValueError): validate_probe({key: value for key, value in packet.items() if key != 'ncrh'})
        for field in ('route_id', 'node_id', 'account_id', 'dnss', 'trajectory'):
            with self.assertRaises(ValueError): validate_probe({**packet, field: 'leak'})

    def test_recursive_ncrh_transform_is_node_runtime_specific(self):
        key_a = b'a' * 32
        key_b = b'b' * 32
        value = b'r' * 32
        domain = b'D-MASH|NCRH|V3\0'
        a1 = hmac.new(key_a, domain + value, hashlib.sha256).digest()
        a2 = hmac.new(key_a, domain + a1, hashlib.sha256).digest()
        b1 = hmac.new(key_b, domain + value, hashlib.sha256).digest()
        self.assertNotEqual(a1, a2)
        self.assertNotEqual(a1, b1)
        self.assertEqual(hmac.new(key_a, domain + value, hashlib.sha256).digest(), a1)

    def test_probe_class_exposes_alternative_path_state(self):
        self.assertTrue(hasattr(HopProbes, '_install'))
        self.assertTrue(hasattr(HopProbes, '_candidates'))


class HopProbeNcrhTests(unittest.IsolatedAsyncioTestCase):
    async def test_graph_is_encrypted_bounded_and_expires(self):
        now = [100.0]
        probes = HopProbes(self._transport(b'a' * 32), clock=lambda: now[0], capacity=2)
        probes._record_edge('peer-A', '1' * 64, '2' * 64, 1, lifetime=5)
        probes._record_edge('peer-B', '1' * 64, '2' * 64, 1, lifetime=10)
        self.assertEqual(len(probes.graph_snapshot()), 2)
        for value in ('peer-A', 'peer-B', '1' * 64, '2' * 64):
            self.assertNotIn(value, repr(probes._graph))
        with self.assertRaises(BufferError):
            probes._record_edge('peer-C', '3' * 64, '4' * 64, 2)
        now[0] = 105
        probes._record_edge('peer-C', '3' * 64, '4' * 64, 2, lifetime=1)
        self.assertEqual({e['peer'] for e in probes.graph_snapshot()}, {'peer-B', 'peer-C'})
        now[0] = 111
        self.assertEqual(probes.graph_snapshot(), [])
        await probes.close()

    async def test_terminal_advertisement_has_semantic_reply_without_binding(self):
        transport = self._transport(b'a' * 32)
        sent = []
        class Channel:
            async def send_packet(self, packet): sent.append(packet)
        transport.node.active_connections = {'peer': Channel()}
        probes = HopProbes(transport)
        packet = {'type': 'HOP_ROOT_NCRH_V1', 'id': '1' * 64,
                  'request_id': '2' * 64, 'ncrh': '3' * 64,
                  'metric': 0, 'hop_limit': 0, 'lifetime': 10, 'trace': ['4' * 64]}
        await probes.receive_root(packet, 'peer')
        self.assertEqual(sent, [{'type': 'HOP_NCRH_STATUS_V1', 'request_id': '2' * 64,
                                'ncrh': '3' * 64, 'state': 'UNKNOWN'}])
        self.assertEqual(len(probes.graph_snapshot()), 1)
        probes._record_edge('another-peer', '3' * 64, '5' * 64, 1)
        await probes.receive_root(packet, 'peer')
        self.assertEqual(sent[-1]['state'], 'KNOWN')
        self.assertEqual(len(probes.graph_snapshot()), 2)
        await probes.close()

    async def test_status_precedes_install_even_when_capacity_is_exhausted(self):
        for kind in ('HOP_ROOT_NCRH_V1', 'HOP_PROBE_V3'):
            transport = self._transport(b'a' * 32)
            sent = []
            class Channel:
                async def send_packet(self, packet): sent.append(packet)
            transport.node.active_connections = {'peer': Channel()}
            probes = HopProbes(transport, capacity=1)
            packet = {'type': kind, 'id': '1' * 64, 'request_id': '2' * 64,
                      'ncrh': '3' * 64, 'metric': 0, 'hop_limit': 0,
                      'lifetime': 10, 'trace': ['4' * 64]}
            if kind == 'HOP_PROBE_V3':
                packet.update(origin_tag='5' * 64, hop_route_label='6' * 64)
            handler = probes.receive_root if kind == 'HOP_ROOT_NCRH_V1' else probes.receive_probe
            await handler(packet, 'peer')
            statuses = lambda: [p for p in sent if p['type'] == 'HOP_NCRH_STATUS_V1']
            self.assertEqual(statuses()[-1]['state'], 'UNKNOWN')
            await handler(packet, 'peer')
            self.assertEqual(statuses()[-1]['state'], 'KNOWN')
            with self.assertRaises(BufferError):
                await handler({**packet, 'request_id': '7' * 64, 'ncrh': '8' * 64}, 'peer')
            self.assertEqual(statuses()[-1], {'type': 'HOP_NCRH_STATUS_V1',
                             'request_id': '7' * 64, 'ncrh': '8' * 64, 'state': 'UNKNOWN'})
            self.assertFalse(probes._exports)
            await probes.close()

    def _transport(self, base):
        crypto = NodeCryptoManager('33' * 32, base)
        routes = SimpleNamespace(issue=lambda *args, **kwargs: 'f' * 64,
                                 resolve=lambda *args: True,
                                 revoke=lambda *args: True)
        node = SimpleNamespace(active_connections={}, can_route=True)
        return SimpleNamespace(system_db=SimpleNamespace(node_crypto=crypto),
                               hop_routes=routes, node=node,
                               _v3_authority_checks={}, _v3_bindings={},
                               _dispatch_mesh_packet=lambda *args, **kwargs: None)

    async def test_probe_requires_ncrh_and_same_peer_keeps_distinct_paths(self):
        transport = self._transport(b'a' * 32)
        probes = HopProbes(transport)
        tag = origin_tag('locator')
        common = {'type': 'HOP_PROBE_V3', 'id': '1' * 64, 'request_id': '6' * 64, 'origin_tag': tag,
                  'hop_route_label': '2' * 64, 'metric': 0, 'hop_limit': 15,
                  'lifetime': 1800, 'trace': ['3' * 64]}
        await probes.receive_probe({**common, 'ncrh': '4' * 64}, 'peer-a')
        await probes.receive_probe({**common, 'ncrh': '5' * 64}, 'peer-a')
        candidates = probes._candidates(tag)
        self.assertEqual(len(candidates), 2)
        self.assertEqual({c['next_peer'] for c in candidates}, {'peer-a'})
        self.assertEqual({c['ncrh'] for c in candidates},
                         {transport.system_db.node_crypto.extend_ncrh('4' * 64),
                          transport.system_db.node_crypto.extend_ncrh('5' * 64)})
        self.assertIsNone(probes.recover_alias('peer-a', '6' * 64),
                          'NCRH alone cannot create a forwarding binding')
        fresh = probes.recover_alias('peer-a', candidates[0]['ncrh'])
        self.assertEqual(fresh, 'f' * 64)
        await probes.close()

    async def test_connection_round_root_response_correlation_and_timeout(self):
        sent = []
        transport = self._transport(b'a' * 32)
        class Channel:
            async def send_packet(self, packet): sent.append(packet)
        transport.node.active_connections = {'peer-a': Channel()}
        probes = HopProbes(transport)
        await probes.peer_connected('peer-a')
        await asyncio.sleep(0)
        self.assertEqual(sent[0]['type'], 'HOP_ROOT_NCRH_V1')
        self.assertEqual(sent[0]['ncrh'], transport.system_db.node_crypto.derive_ncrh_root())
        request_id, ncrh = sent[0]['request_id'], sent[0]['ncrh']
        await probes.receive_status({'type': 'HOP_NCRH_STATUS_V1', 'request_id': request_id,
                                     'ncrh': ncrh, 'state': 'KNOWN'}, 'wrong-peer')
        self.assertIn(request_id, probes._pending)
        await probes.receive_status({'type': 'HOP_NCRH_STATUS_V1', 'request_id': request_id,
                                     'ncrh': ncrh, 'state': 'KNOWN'}, 'peer-a')
        self.assertNotIn(request_id, probes._pending)
        self.assertEqual(probes._sync['peer-a']['replies'], 1)
        await probes.peer_connected('peer-a')
        second = sent[-1]['request_id']
        await probes._expire_pending(second, timeout=0)
        self.assertNotIn(second, probes._pending)
        self.assertEqual(probes._sync['peer-a']['timeouts'], 1)
        await probes.close()

    async def test_two_nodes_exchange_root_and_semantic_status(self):
        a_transport, b_transport = self._transport(b'a' * 32), self._transport(b'b' * 32)
        a = HopProbes(a_transport); b = HopProbes(b_transport)
        class Link:
            def __init__(self, target, source): self.target, self.source = target, source
            async def send_packet(self, packet):
                handlers = {'HOP_ROOT_NCRH_V1': self.target.receive_root,
                            'HOP_PROBE_V3': self.target.receive_probe,
                            'HOP_NCRH_STATUS_V1': self.target.receive_status,
                            'HOP_ALIAS_BIND_V1': self.target.receive_alias_bind}
                await handlers[packet['type']](packet, self.source)
        a_transport.node.active_connections = {'B': Link(b, 'A')}
        b_transport.node.active_connections = {'A': Link(a, 'B')}
        await a.peer_connected('B')
        await asyncio.sleep(0)
        self.assertEqual(a._sync['B']['replies'], 1)
        self.assertEqual(b.graph_snapshot()[0]['ncrh_in'], a_transport.system_db.node_crypto.derive_ncrh_root())
        await a.close(); await b.close()

    async def test_same_logical_path_replaces_label_and_different_ncrh_coexists(self):
        transport = self._transport(b'a' * 32)
        probes = HopProbes(transport)
        tag = origin_tag('locator')
        base = {'type': 'HOP_PROBE_V3', 'id': '1' * 64, 'request_id': '6' * 64,
                'origin_tag': tag, 'metric': 0, 'hop_limit': 15, 'lifetime': 1800,
                'trace': ['3' * 64], 'ncrh': '4' * 64}
        await probes.receive_probe({**base, 'hop_route_label': '2' * 64}, 'peer-a')
        await probes.receive_probe({**base, 'hop_route_label': '5' * 64}, 'peer-a')
        candidates = probes._candidates(tag)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]['outgoing_label'], '5' * 64)
        await probes.receive_probe({**base, 'id': '7' * 64, 'request_id': '8' * 64,
                                    'ncrh': '9' * 64, 'hop_route_label': 'a' * 64}, 'peer-a')
        self.assertEqual(len(probes._candidates(tag)), 2)
        await probes.close()

    async def test_alias_bind_label_routes_data_to_next_peer(self):
        a_transport, b_transport = self._transport(b'a' * 32), self._transport(b'b' * 32)
        a_transport.hop_routes = HopRoutes(); b_transport.hop_routes = HopRoutes()
        a = HopProbes(a_transport); b = HopProbes(b_transport)
        tag = origin_tag('locator')
        common = {'mailbox_alias': None, 'metric': 1, 'ncrh': '4' * 64,
                  'ncrh_in': '3' * 64, 'until': a.clock() + 100,
                  'probe_id': '1' * 64, 'trace': ['2' * 64]}
        a_candidate = {**common, 'path_key': 'a', 'next_peer': 'B', 'outgoing_label': '5' * 64}
        b_candidate = {**common, 'path_key': 'b', 'next_peer': 'C', 'outgoing_label': '6' * 64}
        a._install(tag, a_candidate); b._install(tag, b_candidate)
        class Link:
            async def send_packet(self, packet): await a.receive_alias_bind(packet, 'B')
        b_transport.node.active_connections = {'A': Link()}
        a._pending['7' * 64] = {'peer': 'B', 'ncrh': '4' * 64, 'kind': 'probe'}
        await a.receive_status({'type': 'HOP_NCRH_STATUS_V1', 'request_id': '7' * 64,
                                'ncrh': '4' * 64, 'state': 'KNOWN'}, 'B')
        await b._send_alias_bind('A', '7' * 64, b_candidate)
        fresh = a._candidates(tag)[0]['outgoing_label']
        self.assertNotEqual(fresh, '5' * 64)
        device_label = a._issue('DEVICE', 'device-owner', a._candidates(tag)[0])
        local = a_transport.hop_routes.resolve('DEVICE', 'device-owner', device_label)
        remote = b_transport.hop_routes.resolve('NODE', 'A', fresh)
        self.assertEqual(local['next_peer'], 'B')
        self.assertEqual(local['outgoing_label'], fresh)
        self.assertEqual(remote['next_peer'], 'C')
        await a.close(); await b.close()

    async def test_unsolicited_alias_binding_cannot_replace_candidate(self):
        transport = self._transport(b'a' * 32)
        probes = HopProbes(transport)
        tag = origin_tag('locator')
        candidate = {'path_key': 'path', 'mailbox_alias': None, 'metric': 1,
                     'ncrh': '4' * 64, 'ncrh_in': '3' * 64, 'until': probes.clock() + 100,
                     'probe_id': '1' * 64, 'trace': ['2' * 64],
                     'next_peer': 'B', 'outgoing_label': '5' * 64}
        probes._install(tag, candidate)
        await probes.receive_alias_bind({'type': 'HOP_ALIAS_BIND_V1', 'request_id': '7' * 64,
            'ncrh': '4' * 64, 'hop_route_label': '6' * 64, 'metric': 1, 'lifetime': 100}, 'B')
        self.assertEqual(probes._candidates(tag)[0]['outgoing_label'], '5' * 64)
        await probes.close()
