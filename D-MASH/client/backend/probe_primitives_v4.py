"""Route-scoped NCRH and bounded Probe hop budgets; not route authority."""
import hashlib
import hmac
import re
import secrets

MAX_HOPS = 15
DEFAULT_MIN_HOPS = 4


def _base(value):
    if not isinstance(value, bytes) or len(value) != 32:
        raise ValueError('BaseNCRH must be 32 secret bytes')
    return value


def route_ncrh(base_ncrh, route_id):
    if not isinstance(route_id, bytes) or len(route_id) != 32:
        raise ValueError('RouteID must be 32 decoded bytes')
    return hmac.new(_base(base_ncrh), b'D-MASH|NCRH|V4|ROUTE\0' + route_id, hashlib.sha256).hexdigest()


def extend_ncrh(base_ncrh, incoming):
    if not isinstance(incoming, str) or not re.fullmatch('[0-9a-f]{64}', incoming):
        raise ValueError('Invalid NCRH')
    return hmac.new(_base(base_ncrh), b'D-MASH|NCRH|V4|HOP\0' + bytes.fromhex(incoming), hashlib.sha256).hexdigest()


def sample_hop_ttl(minimum=DEFAULT_MIN_HOPS, maximum=MAX_HOPS):
    if type(minimum) is not int or type(maximum) is not int or not 1 <= minimum < maximum <= MAX_HOPS:
        raise ValueError('Invalid random hop range')
    return minimum + secrets.randbelow(maximum - minimum + 1)


def consume_hop(ttl):
    if type(ttl) is not int or not 1 <= ttl <= MAX_HOPS:
        raise ValueError('Invalid hop TTL')
    # Zero is a local stop sentinel, never an outgoing wire TTL.
    return ttl - 1
