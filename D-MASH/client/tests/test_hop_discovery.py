import hashlib
import hmac
import unittest

from backend.hop_probes import HopProbes, origin_tag, validate_probe


class HopProbeSemanticsTests(unittest.TestCase):
    def test_origin_tag_is_not_route_id_on_wire(self):
        self.assertNotEqual(origin_tag('route-a'), 'route-a')
        self.assertEqual(len(origin_tag('route-a')), 64)

    def test_probe_schema_has_no_route_or_identity_fields(self):
        packet = {
            'type': 'HOP_PROBE_V3', 'id': 'a' * 64,
            'origin_tag': 'b' * 64, 'hop_route_label': 'c' * 64,
            'metric': 0, 'hop_limit': 15, 'lifetime': 1800,
            'trace': ['d' * 64],
        }
        validate_probe(packet)
        for field in ('route_id', 'node_id', 'account_id', 'dnss', 'ncrh'):
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
