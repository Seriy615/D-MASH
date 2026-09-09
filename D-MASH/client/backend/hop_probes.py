"""Probe advertisements install alternative paths BACK to their initiator."""
import asyncio
import hashlib
import hmac
import json
import re
import secrets
import time

from nacl.secret import SecretBox

_HEX = re.compile(r'[0-9a-f]{64}')


def origin_tag(locator):
    if not isinstance(locator, str) or not 1 <= len(locator) <= 256:
        raise ValueError('invalid advertised locator')
    return hashlib.sha256(b'D-MASH|ROUTE-ADVERTISEMENT|V3\0' + locator.encode()).hexdigest()


def validate_probe(packet):
    required = {'type', 'id', 'origin_tag', 'hop_route_label', 'metric', 'hop_limit', 'lifetime', 'trace'}
    if not isinstance(packet, dict) or not required <= set(packet) or set(packet) - required - {'trajectory'}:
        raise ValueError('invalid hop probe fields')
    if packet['type'] != 'HOP_PROBE_V3': raise ValueError('invalid hop probe operation')
    for name in ('id', 'origin_tag', 'hop_route_label') + (('trajectory',) if 'trajectory' in packet else ()):
        if not isinstance(packet[name], str) or not _HEX.fullmatch(packet[name]):
            raise ValueError('invalid hop probe token')
    for field, low, high in (('metric', 0, 15), ('hop_limit', 0, 15), ('lifetime', 1, 1800)):
        if type(packet[field]) is not int or not low <= packet[field] <= high:
            raise ValueError('invalid hop probe bound')
    trace = packet['trace']
    if not isinstance(trace, list) or not 1 <= len(trace) <= 16 or len(set(trace)) != len(trace):
        raise ValueError('invalid hop probe trace')
    if len(trace) != packet['metric'] + 1: raise ValueError('inconsistent probe trace length')
    if any(not isinstance(token, str) or not _HEX.fullmatch(token) for token in trace):
        raise ValueError('invalid hop probe trace')


class HopProbes:
    def __init__(self, transport, *, clock=time.monotonic, capacity=10000):
        self.transport, self.clock, self.capacity = transport, clock, capacity
        self._key = secrets.token_bytes(32)
        # Runtime-local namespace. Restart rotates it; no BootID or NodeID is
        # included in the commitment.
        self._ncrh_key = secrets.token_bytes(32)
        self._box = SecretBox(secrets.token_bytes(32))
        self._rows = {}
        self._exports = set()
        self._export_task = None
        self._closed = False

    def _index(self, kind, value):
        data = json.dumps([kind, value], separators=(',', ':')).encode()
        return hmac.new(self._key, b'D-MASH|PROBE-STATE|V3\0' + data, hashlib.sha256).digest()

    def _get(self, kind, key):
        index = self._index(kind, key)
        row = self._rows.get(index)
        if row is None: return None
        value = json.loads(self._box.decrypt(row))
        if value['expires'] <= self.clock():
            del self._rows[index]
            return None
        return value

    def _put(self, kind, key, value, ttl):
        index = self._index(kind, key)
        if index not in self._rows and len(self._rows) >= self.capacity:
            for old, row in list(self._rows.items()):
                if json.loads(self._box.decrypt(row))['expires'] <= self.clock(): del self._rows[old]
            if len(self._rows) >= self.capacity: raise BufferError('probe state full')
        self._rows[index] = bytes(self._box.encrypt(json.dumps({**value, 'expires': self.clock() + ttl}, separators=(',', ':')).encode()))

    def register(self, locator, alias):
        self._put('local', origin_tag(locator), {'alias': alias}, 86400)

    def unregister(self, locator):
        tag = origin_tag(locator)
        self._rows.pop(self._index('local', tag), None)
        self._rows.pop(self._index('paths', tag), None)

    def _local(self, tag):
        record = self._get('local', tag)
        if record:
            check = self.transport._v3_authority_checks.get(record['alias'])
            if callable(check) and check(): return record['alias']
        return None

    def _road(self, next_peer=None, downstream=None):
        if downstream is None:
            return secrets.token_hex(32)
        if not isinstance(downstream, str) or not _HEX.fullmatch(downstream):
            raise ValueError('invalid NCRH input')
        return hmac.new(self._ncrh_key, b'D-MASH|NCRH|V3\0' + bytes.fromhex(downstream), hashlib.sha256).hexdigest()

    def _trace_token(self, identity):
        # Per-Probe loop guard, not a stable Node/Boot ID or a node list.
        return self._index('trace', identity).hex()

    def _candidates(self, tag):
        row = self._get('paths', tag) or {}
        return [c for c in row.get('candidates', []) if c['until'] > self.clock()
                and (c['mailbox_alias'] is None or self._local(tag) == c['mailbox_alias'])]

    def _install(self, tag, candidate):
        candidates = self._candidates(tag)
        old = next((c for c in candidates if c['path_key'] == candidate['path_key']), None)
        if old and old['probe_id'] == candidate['probe_id']:
            return False
        others = [c for c in candidates if c['path_key'] != candidate['path_key']]
        if len(others) >= 3 and candidate['metric'] >= max(c['metric'] for c in others):
            return False
        others.append(candidate)
        others.sort(key=lambda c: c['metric'])  # stable tie, never sort by NCRH
        self._put('paths', tag, {'tag': tag, 'candidates': others[:3]}, 1800)
        return True

    def _issue(self, role, owner, candidate):
        ttl = min(1800, candidate['until'] - self.clock())
        if ttl <= 0: raise PermissionError('expired advertised path')
        return self.transport.hop_routes.issue(role, owner,
            next_peer=candidate['next_peer'], outgoing_label=candidate['outgoing_label'],
            mailbox_alias=candidate['mailbox_alias'], metric=candidate['metric'], ttl=ttl,
            ncrh_in=candidate.get('trajectory'), ncrh_out=candidate.get('downstream'))

    def status(self, owner, locator):
        tag = origin_tag(locator)
        candidates = self._candidates(tag)
        if not candidates: return {'state': 'ROUTE_UNKNOWN'}
        connections = self.transport.node.active_connections if self.transport.node else {}
        candidate = min(candidates, key=lambda c: (c['mailbox_alias'] is None and c['next_peer'] not in connections, c['metric']))
        cache_key = [owner, tag, candidate['path_key'], candidate['probe_id']]
        cached = self._get('device', cache_key)
        label = cached['label'] if cached else None
        if not label or not self.transport.hop_routes.resolve('DEVICE', owner, label):
            label = self._issue('DEVICE', owner, candidate)
            self._put('device', cache_key, {'label': label}, candidate['until'] - self.clock())
        return {'state': 'ROUTE_READY', 'hop_route_label': label, 'best_metric': candidate['metric']}

    async def _advertise(self, tag, candidate, peers=None):
        if candidate['metric'] >= 15: return
        connections = self.transport.node.active_connections if self.transport.node else {}
        peers = list(connections) if peers is None else peers
        for peer in peers:
            if peer == candidate['next_peer']: continue
            key = [tag, candidate['path_key'], candidate['probe_id'], peer]
            self._put('export', key, {'tag': tag, 'candidate': candidate, 'peer': peer}, candidate['until'] - self.clock())
            self._exports.add(self._index('export', key))
        if self._exports and (self._export_task is None or self._export_task.done()):
            self._export_task = asyncio.create_task(self._flush_exports())

    async def _flush_exports(self):
        # Backpressure keeps unsent advertisements; successful peer exports
        # are removed individually. This worker never performs socket sends.
        while self._exports and not self._closed:
            for index in list(self._exports)[:64]:
                row = self._rows.get(index)
                value = json.loads(self._box.decrypt(row)) if row else None
                if not value or value['expires'] <= self.clock():
                    self._rows.pop(index, None); self._exports.discard(index)
                    continue
                candidate, peer, tag = value['candidate'], value['peer'], value['tag']
                if candidate['mailbox_alias'] is not None and self._local(tag) != candidate['mailbox_alias']:
                    self._rows.pop(index, None); self._exports.discard(index)
                    continue
                if not self.transport.node.can_route or peer not in self.transport.node.active_connections:
                    continue
                label = None
                try:
                    label = self._issue('NODE', peer, candidate)
                    packet = {'type': 'HOP_PROBE_V3', 'id': candidate['probe_id'], 'origin_tag': tag,
                        'hop_route_label': label, 'metric': candidate['metric'], 'hop_limit': 15 - candidate['metric'],
                        'lifetime': max(1, min(1800, int(candidate['until'] - self.clock()))), 'trace': candidate['trace']}
                    if candidate.get('trajectory') is not None: packet['trajectory'] = candidate['trajectory']
                    await self.transport._dispatch_mesh_packet(packet, next_hop_id=peer)
                except (BufferError, PermissionError):
                    if label: self.transport.hop_routes.revoke('NODE', peer, label)
                    continue
                except BaseException:
                    if label: self.transport.hop_routes.revoke('NODE', peer, label)
                    raise
                self._rows.pop(index, None); self._exports.discard(index)
            if self._exports:
                await asyncio.sleep(.5)

    async def start(self, owner, locator):
        tag = origin_tag(locator)
        alias = self._local(tag)
        if alias is None or self.transport._v3_bindings.get(alias) != owner:
            raise PermissionError('Probe must advertise its registered initiator')
        identity = secrets.token_hex(32)
        candidate = {'path_key': 'local', 'mailbox_alias': alias, 'next_peer': None, 'outgoing_label': None,
            'metric': 0, 'trajectory': self._road(), 'downstream': None, 'until': self.clock() + 1800,
            'probe_id': identity, 'trace': [self._trace_token(identity)]}
        self._install(tag, candidate)
        await self._advertise(tag, candidate)
        return 'SUBMITTED_TO_ENTRY'

    def note_sent(self, packet, peers):
        """Compatibility hook for the aggregation resolver.

        Probe fan-out is represented by the volatile export queue; resolving a
        packet must not consume the advertisement before its peer workers have
        accepted it. The export worker owns that lifecycle.
        """
        return True

    async def receive_probe(self, packet, peer):
        validate_probe(packet)
        tag = packet['origin_tag']
        if not packet['hop_limit'] or packet['metric'] >= 15 or self._local(tag): return
        token = self._trace_token(packet['id'])
        if token in packet['trace']: return
        metric = packet['metric'] + 1
        downstream = packet.get('trajectory')
        road = self._road(peer, downstream)
        path_key = self._index('path', [peer, downstream or packet['hop_route_label']]).hex()
        candidate = {'path_key': path_key, 'mailbox_alias': None, 'next_peer': peer,
            'outgoing_label': packet['hop_route_label'], 'metric': metric, 'trajectory': road,
            'downstream': downstream, 'until': self.clock() + packet['lifetime'],
            'probe_id': packet['id'], 'trace': packet['trace'] + [token]}
        if self._install(tag, candidate):
            await self._advertise(tag, candidate)

    async def peer_connected(self, peer):
        # Event-triggered export of already learned paths; no target search.
        for row in list(self._rows.values()):
            value = json.loads(self._box.decrypt(row))
            if value['expires'] <= self.clock() or 'candidates' not in value: continue
            for candidate in self._candidates(value['tag']):
                await self._advertise(value['tag'], candidate, [peer])

    async def close(self):
        self._closed = True
        if self._export_task:
            self._export_task.cancel()
            await asyncio.gather(self._export_task, return_exceptions=True)
        self._exports.clear()
        self._rows.clear()
        self._key = self._box = self._ncrh_key = None
