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
    required = {'type', 'id', 'request_id', 'origin_tag', 'hop_route_label', 'ncrh', 'metric', 'hop_limit', 'lifetime', 'trace'}
    if not isinstance(packet, dict) or set(packet) != required:
        raise ValueError('invalid hop probe fields')
    if packet['type'] != 'HOP_PROBE_V3': raise ValueError('invalid hop probe operation')
    for name in ('id', 'request_id', 'origin_tag', 'hop_route_label', 'ncrh'):
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


def _validate_hex_packet(packet, required, token_fields):
    if not isinstance(packet, dict) or set(packet) != required:
        raise ValueError('invalid NCRH recovery fields')
    for name in token_fields:
        if not isinstance(packet[name], str) or not _HEX.fullmatch(packet[name]):
            raise ValueError('invalid NCRH recovery token')


def validate_root(packet):
    _validate_hex_packet(packet, {'type', 'id', 'request_id', 'ncrh', 'metric', 'hop_limit', 'lifetime', 'trace'},
                         ('id', 'request_id', 'ncrh'))
    if packet['type'] != 'HOP_ROOT_NCRH_V1': raise ValueError('invalid root advertisement')
    if type(packet['metric']) is not int or not 0 <= packet['metric'] <= 15: raise ValueError('invalid root metric')
    if type(packet['hop_limit']) is not int or not 0 <= packet['hop_limit'] <= 15: raise ValueError('invalid root hop limit')
    if type(packet['lifetime']) is not int or not 1 <= packet['lifetime'] <= 1800: raise ValueError('invalid root lifetime')
    if not isinstance(packet['trace'], list) or not 1 <= len(packet['trace']) <= 16: raise ValueError('invalid root trace')
    if len(packet['trace']) != packet['metric'] + 1 or any(not isinstance(v, str) or not _HEX.fullmatch(v) for v in packet['trace']):
        raise ValueError('invalid root trace')


def validate_ncrh_status(packet):
    _validate_hex_packet(packet, {'type', 'request_id', 'ncrh', 'state'}, ('request_id', 'ncrh'))
    if packet['type'] != 'HOP_NCRH_STATUS_V1' or packet['state'] not in {'KNOWN', 'UNKNOWN'}:
        raise ValueError('invalid NCRH status')


def validate_alias_bind(packet):
    _validate_hex_packet(packet, {'type', 'request_id', 'ncrh', 'hop_route_label', 'metric', 'lifetime'},
                         ('request_id', 'ncrh', 'hop_route_label'))
    if packet['type'] != 'HOP_ALIAS_BIND_V1': raise ValueError('invalid alias binding')
    if type(packet['metric']) is not int or not 0 <= packet['metric'] <= 15: raise ValueError('invalid alias metric')
    if type(packet['lifetime']) is not int or not 1 <= packet['lifetime'] <= 1800: raise ValueError('invalid alias lifetime')


class HopProbes:
    def __init__(self, transport, *, clock=time.monotonic, capacity=10000):
        self.transport, self.clock, self.capacity = transport, clock, capacity
        self._key = secrets.token_bytes(32)
        self._box = SecretBox(secrets.token_bytes(32))
        self._rows = {}
        self._exports = set()
        self._pending = {}
        self._pending_tasks = {}
        self._sync = {}
        self._graph = []
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
            if old == candidate: return False
        others = [c for c in candidates if c['path_key'] != candidate['path_key']]
        if len(others) >= 3 and candidate['metric'] >= max(c['metric'] for c in others):
            return False
        others.append(candidate)
        others.sort(key=lambda c: c['metric'])  # stable tie, never sort by NCRH
        self._put('paths', tag, {'tag': tag, 'candidates': others[:3]}, 1800)
        return True

    def _root_tag(self, peer, ncrh):
        return self._index('root', [peer, ncrh]).hex()

    def graph_snapshot(self):
        """Return the local logical NCRH graph without endpoint identities."""
        return [dict(edge) for edge in self._graph]

    def _record_edge(self, peer, ncrh_in, ncrh_out, metric):
        edge = {'peer': peer, 'ncrh_in': ncrh_in, 'ncrh_out': ncrh_out, 'metric': metric}
        self._graph = [old for old in self._graph
                       if not (old['peer'] == peer and old['ncrh_in'] == ncrh_in)]
        self._graph.append(edge)

    async def _send_control(self, peer, packet):
        channel = self.transport.node.active_connections.get(peer) if self.transport.node else None
        if channel is not None and hasattr(channel, 'send_packet'):
            await channel.send_packet(packet)
            return
        result = self.transport._dispatch_mesh_packet(packet, next_hop_id=peer)
        if hasattr(result, '__await__'): await result

    async def _expire_pending(self, request_id, timeout=10.0):
        try:
            await asyncio.sleep(timeout)
            pending = self._pending.pop(request_id, None)
            if pending:
                self._sync.setdefault(pending['peer'], {'sent': 0, 'replies': 0, 'timeouts': 0})['timeouts'] += 1
        except asyncio.CancelledError:
            raise
        finally:
            self._pending_tasks.pop(request_id, None)

    async def _track_and_send(self, peer, packet, kind):
        request_id = packet['request_id']
        self._pending[request_id] = {'peer': peer, 'ncrh': packet['ncrh'], 'kind': kind,
                                     'sent_at': self.clock()}
        state = self._sync.setdefault(peer, {'sent': 0, 'replies': 0, 'timeouts': 0, 'advertisements': 0})
        state['sent'] += 1
        if kind in {'probe', 'root'}: state['advertisements'] += 1
        # Arm before sending: a blocked socket also has a bounded semantic
        # lifetime, and an immediate reply can cancel the existing timer.
        task = asyncio.create_task(self._expire_pending(request_id))
        self._pending_tasks[request_id] = task
        try:
            await self._send_control(peer, packet)
        except BaseException:
            self._pending.pop(request_id, None)
            task.cancel()
            self._pending_tasks.pop(request_id, None)
            raise

    async def _send_status(self, peer, request_id, ncrh, known):
        await self._send_control(peer, {'type': 'HOP_NCRH_STATUS_V1', 'request_id': request_id,
                                        'ncrh': ncrh, 'state': 'KNOWN' if known else 'UNKNOWN'})

    async def _send_alias_bind(self, peer, request_id, candidate):
        if candidate.get('outgoing_label') is None:
            return
        label = self._issue('NODE', peer, candidate)
        await self._send_control(peer, {'type': 'HOP_ALIAS_BIND_V1', 'request_id': request_id,
                                        'ncrh': candidate['ncrh'], 'hop_route_label': label,
                                        'metric': candidate['metric'],
                                        'lifetime': max(1, min(1800, int(candidate['until'] - self.clock())))})

    def _issue(self, role, owner, candidate):
        if candidate['mailbox_alias'] is None and not candidate.get('outgoing_label'):
            raise PermissionError('logical path has no forwarding capability')
        ttl = min(1800, candidate['until'] - self.clock())
        if ttl <= 0: raise PermissionError('expired advertised path')
        return self.transport.hop_routes.issue(role, owner,
            next_peer=candidate['next_peer'], outgoing_label=candidate['outgoing_label'],
            mailbox_alias=candidate['mailbox_alias'], metric=candidate['metric'], ttl=ttl,
            ncrh_in=candidate.get('ncrh_in'), ncrh_out=candidate.get('ncrh'))

    def status(self, owner, locator):
        tag = origin_tag(locator)
        candidates = [c for c in self._candidates(tag)
                      if c['mailbox_alias'] is not None or c.get('outgoing_label')]
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

    def recover_alias(self, authenticated_peer, ncrh):
        """Issue a fresh hop alias for an already reconstructed NCRH path.

        This is deliberately separate from Probe reconstruction. NCRH is only
        a lookup hint: an authenticated peer and a locally stored candidate
        with the same next hop are both required before a new label is issued.
        """
        if not isinstance(authenticated_peer, str) or not _HEX.fullmatch(ncrh or ''):
            raise ValueError('invalid alias recovery request')
        for row in list(self._rows.values()):
            value = json.loads(self._box.decrypt(row))
            if 'candidates' not in value: continue
            for candidate in self._candidates(value['tag']):
                if candidate['ncrh'] == ncrh and candidate['next_peer'] == authenticated_peer:
                    return self._issue('NODE', authenticated_peer, candidate)
        return None

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
                    packet = {'type': 'HOP_ROOT_NCRH_V1', 'id': candidate['probe_id'], 'request_id': secrets.token_hex(32),
                        'metric': candidate['metric'], 'hop_limit': 15 - candidate['metric'],
                        'lifetime': max(1, min(1800, int(candidate['until'] - self.clock()))), 'trace': candidate['trace']}
                    if candidate['mailbox_alias'] is not None or candidate.get('outgoing_label'):
                        label = self._issue('NODE', peer, candidate)
                        packet.update(type='HOP_PROBE_V3', origin_tag=tag, hop_route_label=label)
                    packet['ncrh'] = candidate['ncrh']
                    await self._track_and_send(peer, packet, 'probe')
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
            'metric': 0, 'ncrh': self.transport.system_db.node_crypto.derive_ncrh_root(),
            'ncrh_in': None, 'until': self.clock() + 1800,
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
        ncrh_in = packet['ncrh']
        ncrh = self.transport.system_db.node_crypto.extend_ncrh(ncrh_in)
        path_key = self._index('path', [peer, ncrh_in]).hex()
        known = any(c['path_key'] == path_key for c in self._candidates(tag))
        candidate = {'path_key': path_key, 'mailbox_alias': None, 'next_peer': peer,
            'outgoing_label': packet['hop_route_label'], 'metric': metric, 'ncrh': ncrh,
            'ncrh_in': ncrh_in, 'until': self.clock() + packet['lifetime'],
            'probe_id': packet['id'], 'trace': packet['trace'] + [token]}
        self._record_edge(peer, ncrh_in, ncrh, metric)
        if self._install(tag, candidate):
            await self._advertise(tag, candidate)
        await self._send_status(peer, packet['request_id'], packet['ncrh'], known)
        await self._send_alias_bind(peer, packet['request_id'], candidate)

    async def receive_root(self, packet, peer):
        validate_root(packet)
        if not packet['hop_limit'] or packet['metric'] >= 15: return
        token = self._trace_token(packet['id'])
        if token in packet['trace']: return
        tag = self._root_tag(peer, packet['ncrh'])
        ncrh = self.transport.system_db.node_crypto.extend_ncrh(packet['ncrh'])
        path_key = self._index('path', [peer, packet['ncrh']]).hex()
        known = any(c['path_key'] == path_key for c in self._candidates(tag))
        candidate = {'path_key': path_key, 'mailbox_alias': None, 'next_peer': peer,
            # Root knowledge grants no DATA capability. Only a correlated
            # peer-issued binding may supply a usable outgoing label.
            'outgoing_label': None, 'metric': packet['metric'] + 1, 'ncrh': ncrh,
            'ncrh_in': packet['ncrh'], 'until': self.clock() + packet['lifetime'],
            'probe_id': packet['id'], 'trace': packet['trace'] + [token]}
        self._record_edge(peer, packet['ncrh'], ncrh, candidate['metric'])
        if self._install(tag, candidate): await self._advertise(tag, candidate)
        await self._send_status(peer, packet['request_id'], packet['ncrh'], known)
        await self._send_alias_bind(peer, packet['request_id'], candidate)

    async def receive_status(self, packet, peer):
        validate_ncrh_status(packet)
        pending = self._pending.get(packet['request_id'])
        if pending is None or pending['peer'] != peer or pending['ncrh'] != packet['ncrh']:
            return
        self._put('semantic-reply', [peer, packet['request_id']],
                  {'ncrh': packet['ncrh'], 'state': packet['state']}, 10)
        self._pending.pop(packet['request_id'], None)
        task = self._pending_tasks.pop(packet['request_id'], None)
        if task: task.cancel()
        state = self._sync.setdefault(peer, {'sent': 0, 'replies': 0, 'timeouts': 0, 'advertisements': 0})
        state['replies'] += 1
        state.setdefault('known', []).append({'ncrh': packet['ncrh'], 'state': packet['state']})

    async def receive_alias_bind(self, packet, peer):
        validate_alias_bind(packet)
        reply_key = [peer, packet['request_id']]
        reply = self._get('semantic-reply', reply_key)
        if reply is None or reply['ncrh'] != packet['ncrh']:
            return
        # A bind is accepted only for a path reconstructed from this peer. The
        # label is runtime state and replaces the old outgoing alias in place.
        for row in list(self._rows.values()):
            value = json.loads(self._box.decrypt(row))
            if 'candidates' not in value: continue
            for candidate in self._candidates(value['tag']):
                if candidate['ncrh'] == packet['ncrh'] and candidate['next_peer'] == peer:
                    candidate = {**candidate, 'outgoing_label': packet['hop_route_label'],
                                 'until': min(candidate['until'], self.clock() + packet['lifetime'])}
                    self._install(value['tag'], candidate)
                    self._rows.pop(self._index('semantic-reply', reply_key), None)
                    return

    async def peer_connected(self, peer):
        # Every authenticated connection starts the same event-driven sync
        # round, whether or not this Node was recently restored.
        root = self.transport.system_db.node_crypto.derive_ncrh_root()
        root_packet = {'type': 'HOP_ROOT_NCRH_V1', 'id': secrets.token_hex(32),
            'request_id': secrets.token_hex(32), 'ncrh': root, 'metric': 0,
            'hop_limit': 15, 'lifetime': 1800, 'trace': [self._trace_token(root)]}
        await self._track_and_send(peer, root_packet, 'root')
        # Event-triggered export of all currently valid reconstructed paths.
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
        for task in list(self._pending_tasks.values()): task.cancel()
        if self._pending_tasks: await asyncio.gather(*self._pending_tasks.values(), return_exceptions=True)
        self._pending.clear(); self._pending_tasks.clear(); self._sync.clear(); self._graph.clear()
        self._rows.clear()
        self._key = self._box = None
