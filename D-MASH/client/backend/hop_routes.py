"""Volatile, peer-scoped hop labels; never a route-ownership authority."""
import hashlib
import hmac
import json
import re
import secrets
import time
import base64

from nacl.secret import SecretBox

_LABEL = re.compile(r'[0-9a-f]{64}')


def validate_hop_packet(packet):
    if not isinstance(packet, dict) or set(packet) != {'type', 'id', 'hop_route_label', 'envelope'} or packet['type'] != 'HOP_DATA_V3':
        raise ValueError('invalid hop packet')
    if not isinstance(packet['id'], str) or not 1 <= len(packet['id']) <= 128 or not packet['id'].isascii():
        raise ValueError('invalid hop packet id')
    if not isinstance(packet['hop_route_label'], str) or not _LABEL.fullmatch(packet['hop_route_label']):
        raise ValueError('invalid hop label')
    envelope = packet['envelope']
    if not isinstance(envelope, dict) or set(envelope) != {'version', 'ciphertext'} or type(envelope['version']) is not int or envelope['version'] != 1:
        raise ValueError('invalid opaque hop envelope')
    ciphertext = envelope['ciphertext']
    if not isinstance(ciphertext, str) or not 1 <= len(ciphertext) <= 65536:
        raise ValueError('invalid hop ciphertext size')
    raw = base64.b64decode(ciphertext, validate=True)
    if not raw or base64.b64encode(raw).decode() != ciphertext:
        raise ValueError('invalid hop ciphertext size')


class HopRoutes:
    def __init__(self, *, clock=time.monotonic, capacity=10000):
        self.clock, self.capacity = clock, capacity
        self._lookup_key = secrets.token_bytes(32)
        self._box_key = secrets.token_bytes(SecretBox.KEY_SIZE)
        self._rows = {}

    def _index(self, role, owner, label):
        if self._lookup_key is None:
            raise RuntimeError('hop routes closed')
        if role not in {'NODE', 'DEVICE'} or not isinstance(owner, str) or not 1 <= len(owner) <= 256:
            raise ValueError('invalid hop owner scope')
        if not isinstance(label, str) or not _LABEL.fullmatch(label):
            raise ValueError('invalid hop label')
        value = json.dumps([role, owner, label], separators=(',', ':')).encode()
        return hmac.new(self._lookup_key, b'D-MASH|HOP-LOOKUP|V3\0' + value, hashlib.sha256).hexdigest()

    def _seal(self, value):
        return bytes(SecretBox(self._box_key).encrypt(json.dumps(value, separators=(',', ':')).encode()))

    def _open(self, row):
        return json.loads(SecretBox(self._box_key).decrypt(row))

    def prune(self):
        now = self.clock()
        for index, row in list(self._rows.items()):
            if self._open(row)['expires'] <= now:
                del self._rows[index]

    def issue(self, role, owner, *, next_peer=None, outgoing_label=None,
              mailbox_alias=None, metric=0, ttl=1800, ncrh_in=None, ncrh_out=None):
        # This internal API is called only after the caller has validated
        # resource authority / a probe path. Knowing NCRH never calls issue.
        if type(ttl) not in (int, float) or not 0 < ttl <= 1800:
            raise ValueError('invalid hop lifetime')
        if type(metric) is not int or not 0 <= metric <= 15:
            raise ValueError('invalid hop metric')
        if mailbox_alias is not None:
            if next_peer is not None or outgoing_label is not None or not isinstance(mailbox_alias, str) or not 1 <= len(mailbox_alias) <= 256:
                raise ValueError('invalid local hop binding')
        elif (not isinstance(next_peer, str) or not 1 <= len(next_peer) <= 256 or
              not isinstance(outgoing_label, str) or not _LABEL.fullmatch(outgoing_label)):
            raise ValueError('invalid outgoing hop binding')
        if ncrh_in is not None and (not isinstance(ncrh_in, str) or not _LABEL.fullmatch(ncrh_in)):
            raise ValueError('invalid local NCRH')
        if ncrh_out is not None and (not isinstance(ncrh_out, str) or not _LABEL.fullmatch(ncrh_out)):
            raise ValueError('invalid outgoing NCRH')
        label = secrets.token_hex(32)
        index = self._index(role, owner, label)
        if len(self._rows) >= self.capacity:
            self.prune()
        if len(self._rows) >= self.capacity:
            raise BufferError('hop route capacity reached')
        self._rows[index] = self._seal(dict(next_peer=next_peer, outgoing_label=outgoing_label,
            mailbox_alias=mailbox_alias, metric=metric, expires=self.clock() + ttl,
            ncrh_in=ncrh_in, ncrh_out=ncrh_out))
        return label

    def resolve(self, role, owner, label):
        index = self._index(role, owner, label)
        row = self._rows.get(index)
        if row is None:
            return None
        value = self._open(row)
        if value['expires'] <= self.clock():
            del self._rows[index]
            return None
        return value

    def revoke(self, role, owner, label):
        return self._rows.pop(self._index(role, owner, label), None) is not None

    def close(self):
        self._rows.clear()
        self._lookup_key = self._box_key = None
