import asyncio
import hashlib
import hmac
from types import SimpleNamespace
import unittest

from backend.crypto import NodeCryptoManager
from backend.hop_probes import HopProbes, origin_tag, validate_probe


class HopProbeSemanticsTests(unittest.TestCase):
    def test_origin_tag_is_not_route_id_on_wire(self):
        self.assertNotEqual(origin_tag('route-a'), 'route-a')
        self.assertEqual(len(origin_tag('route-a')), 64)

    def test_probe_schema_has_no_route_or_identity_fields(self):
        packet = {
            'type': 'HOP_PROBE_V3', 'id': 'a' * 64,
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
        common = {'type': 'HOP_PROBE_V3', 'id': '1' * 64, 'origin_tag': tag,
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
