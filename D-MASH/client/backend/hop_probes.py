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
    for name in ('id', 'request_id', 'origin_tag', 'ncrh'):
        if not isinstance(packet[name], str) or not _HEX.fullmatch(packet[name]):
            raise ValueError('invalid hop probe token')
    if packet['hop_route_label'] is not None and (not isinstance(packet['hop_route_label'], str) or not _HEX.fullmatch(packet['hop_route_label'])):
        raise ValueError('invalid offered hop label')
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
    if len(set(packet['trace'])) != len(packet['trace']): raise ValueError('duplicate root trace')
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
        self._graph = {}
        self._export_tasks = {}
        self._connection_tasks = {}
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
        knowledge = {}
        for sealed in list(self._rows.values()):
            value = json.loads(self._box.decrypt(sealed))
            if value['expires'] > self.clock() and {'peer', 'ncrh', 'state'} <= value.keys():
                knowledge.setdefault(value['ncrh'], []).append(
                    {'peer': value['peer'], 'state': value['state']})
        edges = []
        for index, sealed in list(self._graph.items()):
            edge = json.loads(self._box.decrypt(sealed))
            if edge['expires'] <= self.clock():
                del self._graph[index]
            else:
                edges.append({**edge, 'outward': knowledge.get(edge['ncrh_out'], [])})
        return edges

    def _record_edge(self, peer, ncrh_in, ncrh_out, metric, lifetime=1800):
        index = self._index('graph', [peer, ncrh_in])
        if index not in self._graph and len(self._graph) >= self.capacity:
            self.graph_snapshot()  # Reclaim only expired state.
            if len(self._graph) >= self.capacity:
                raise BufferError('NCRH graph capacity reached')
        edge = {'peer': peer, 'ncrh_in': ncrh_in, 'ncrh_out': ncrh_out,
                'metric': metric, 'expires': self.clock() + lifetime}
        self._graph[index] = bytes(self._box.encrypt(json.dumps(edge, separators=(',', ':')).encode()))

    def _knows_ncrh(self, ncrh):
        if ncrh == self.transport.system_db.node_crypto.derive_ncrh_root():
            return True
        return any(ncrh in (edge['ncrh_in'], edge['ncrh_out'])
                   for edge in self.graph_snapshot())

    async def _send_control(self, peer, packet):
        channel = self.transport.node.active_connections.get(peer) if self.transport.node else None
        if channel is not None and hasattr(channel, 'send_packet'):
            try:
                await asyncio.wait_for(channel.send_packet(packet), timeout=10)
            except (TimeoutError, ConnectionError, OSError):
                if hasattr(channel, 'close'): await channel.close()
                raise
            return
        raise ConnectionError('authenticated Node channel unavailable')

    async def _expire_pending(self, request_id, timeout=10.0):
        try:
            await asyncio.sleep(timeout)
            pending = self._pending.pop(request_id, None)
            if pending:
                self._peer_state(pending['peer'])['timeouts'] += 1
        except asyncio.CancelledError:
            raise
        finally:
            task = self._pending_tasks.pop(request_id, None)
            if task and task is not asyncio.current_task(): task.cancel()

    async def _track_and_send(self, peer, packet, kind):
        if len(self._pending) >= self.capacity:
            raise BufferError('NCRH request capacity reached')
        request_id = packet['request_id']
        self._pending[request_id] = {'peer': peer, 'ncrh': packet['ncrh'], 'kind': kind,
                                     'sent_at': self.clock()}
        state = self._peer_state(peer)
        state['sent'] += 1
        if kind in {'probe', 'root'}: state['advertisements'] += 1
        if kind == 'root': state['roots_sent'] += 1
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
        if candidate.get('outgoing_label') is None and candidate['mailbox_alias'] is None:
            return
        label = self._issue('NODE', peer, candidate)
        try:
            await self._send_control(peer, {'type': 'HOP_ALIAS_BIND_V1', 'request_id': request_id,
                                           'ncrh': candidate['ncrh'], 'hop_route_label': label,
                                           'metric': candidate['metric'],
                                           'lifetime': max(1, min(1800, int(candidate['until'] - self.clock())))})
        except BaseException:
            self.transport.hop_routes.revoke('NODE', peer, label)
            raise
        self._peer_state(peer)['bindings_sent'] += 1

    def _issue(self, role, owner, candidate):
        if role == 'NODE' and owner == candidate['next_peer']:
            raise PermissionError('reflected forwarding capability')
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
        cache_key = [owner, tag, candidate['path_key'], candidate['probe_id'], candidate.get('outgoing_label')]
        cached = self._get('device', cache_key)
        label = cached['label'] if cached else None
        if not label or not self.transport.hop_routes.resolve('DEVICE', owner, label):
            label = self._issue('DEVICE', owner, candidate)
            self._put('device', cache_key, {'label': label}, candidate['until'] - self.clock())
        return {'state': 'ROUTE_READY', 'hop_route_label': label, 'best_metric': candidate['metric']}

    async def _advertise(self, tag, candidate, peers=None):
        if candidate['metric'] >= 15 or not candidate.get('propagate', True): return
        connections = self.transport.node.active_connections if self.transport.node else {}
        peers = list(connections) if peers is None else peers
        self._exports.intersection_update(self._rows)
        for peer in peers:
            if peer == candidate['next_peer']: continue
            key = [tag, candidate['path_key'], candidate['probe_id'], peer]
            self._put('export', key, {'tag': tag, 'candidate': candidate, 'peer': peer}, candidate['until'] - self.clock())
            self._exports.add(self._index('export', key))
        for peer in peers:
            self._start_export(peer)

    def _start_export(self, peer):
        if self._closed or peer not in self.transport.node.active_connections:
            return
        task = self._export_tasks.get(peer)
        if task is None or task.done():
            task = asyncio.create_task(self._flush_exports(peer))
            self._export_tasks[peer] = task
            task.add_done_callback(lambda done: self._worker_done(self._export_tasks, peer, done))

    def peer_disconnected(self, peer):
        # Keep encrypted unsent exports, but leave no retry timer for an absent
        # channel. A subsequent authenticated connection restarts the worker.
        for workers in (self._export_tasks, self._connection_tasks):
            task = workers.pop(peer, None)
            if task: task.cancel()

    async def _flush_exports(self, target_peer):
        # Backpressure keeps unsent advertisements; successful peer exports
        # are removed individually. Each peer has its own independent worker.
        while not self._closed:
            if target_peer not in self.transport.node.active_connections:
                return
            own = [index for index in self._exports if index in self._rows
                   and json.loads(self._box.decrypt(self._rows[index]))['peer'] == target_peer]
            if not own: return
            for index in own[:64]:
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
                    return
                label = None
                try:
                    packet = {'type': 'HOP_ROOT_NCRH_V1', 'id': candidate['probe_id'], 'request_id': secrets.token_hex(32),
                        'metric': candidate['metric'],
                        'hop_limit': min(15 - candidate['metric'], candidate.get('remaining_hops', 15)),
                        'lifetime': max(1, min(1800, int(candidate['until'] - self.clock()))), 'trace': candidate['trace']}
                    if candidate['mailbox_alias'] is not None or candidate.get('outgoing_label'):
                        packet.update(type='HOP_PROBE_V3', origin_tag=tag, hop_route_label=None)
                        self._put('offered', packet['request_id'],
                                  {'tag': tag, 'path_key': candidate['path_key'], 'peer': peer}, 10)
                    packet['ncrh'] = candidate['ncrh']
                    await self._track_and_send(peer, packet, 'probe')
                except (BufferError, PermissionError, ConnectionError, OSError, TimeoutError):
                    if label: self.transport.hop_routes.revoke('NODE', peer, label)
                    continue
                except BaseException:
                    if label: self.transport.hop_routes.revoke('NODE', peer, label)
                    raise
                # An alias refresh may replace this export while the socket
                # is suspended. Do not consume the newer advertisement.
                if self._rows.get(index) == row:
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
        known = self._knows_ncrh(packet['ncrh'])
        try:
            self._put('received', [peer, packet['request_id']],
                      {'ncrh': packet['ncrh'], 'tag': tag, 'peer': peer, 'label': None}, min(10, packet['lifetime']))
        except BufferError:
            await self._send_status(peer, packet['request_id'], packet['ncrh'], known)
            raise
        # Reply describes pre-advertisement knowledge, even if installation fails.
        await self._send_status(peer, packet['request_id'], packet['ncrh'], known)
        self._peer_state(peer)['received'] += 1
        token = self._trace_token(packet['id'])
        if (packet['metric'] >= 15 or self._local(tag)
                or token in packet['trace']):
            return
        metric = packet['metric'] + 1
        ncrh_in = packet['ncrh']
        ncrh = self.transport.system_db.node_crypto.extend_ncrh(ncrh_in)
        path_key = self._index('path', [peer, ncrh_in]).hex()
        candidate = {'path_key': path_key, 'mailbox_alias': None, 'next_peer': peer,
            'outgoing_label': (self._get('received', [peer, packet['request_id']]) or {}).get('label'),
            'metric': metric, 'ncrh': ncrh,
            'ncrh_in': ncrh_in, 'until': self.clock() + packet['lifetime'],
            'probe_id': packet['id'], 'trace': packet['trace'] + [token],
            'propagate': bool(packet['hop_limit']), 'request_id': packet['request_id'],
            'remaining_hops': max(0, packet['hop_limit'] - 1)}
        received = self._get('received', [peer, packet['request_id']])
        if received and received.get('binding_until'):
            candidate['until'] = min(candidate['until'], received['binding_until'])
        self._record_edge(peer, ncrh_in, ncrh, metric, packet['lifetime'])
        if self._install(tag, candidate) and packet['hop_limit'] and candidate.get('outgoing_label'):
            await self._advertise(tag, candidate)

    async def receive_root(self, packet, peer):
        validate_root(packet)
        known = self._knows_ncrh(packet['ncrh'])
        # Reply describes pre-advertisement knowledge, even if installation fails.
        await self._send_status(peer, packet['request_id'], packet['ncrh'], known)
        self._peer_state(peer)['received'] += 1
        self._peer_state(peer)['roots_received'] += 1
        token = self._trace_token(packet['id'])
        if packet['metric'] >= 15 or token in packet['trace']:
            return
        tag = self._root_tag(peer, packet['ncrh'])
        ncrh = self.transport.system_db.node_crypto.extend_ncrh(packet['ncrh'])
        path_key = self._index('path', [peer, packet['ncrh']]).hex()
        candidate = {'path_key': path_key, 'mailbox_alias': None, 'next_peer': peer,
            # Root knowledge grants no DATA capability. Only a correlated
            # peer-issued binding may supply a usable outgoing label.
            'outgoing_label': None, 'metric': packet['metric'] + 1, 'ncrh': ncrh,
            'ncrh_in': packet['ncrh'], 'until': self.clock() + packet['lifetime'],
            'probe_id': packet['id'], 'trace': packet['trace'] + [token],
            'propagate': bool(packet['hop_limit']), 'request_id': packet['request_id'],
            'remaining_hops': max(0, packet['hop_limit'] - 1)}
        self._record_edge(peer, packet['ncrh'], ncrh, candidate['metric'], packet['lifetime'])
        if self._install(tag, candidate) and packet['hop_limit']:
            await self._advertise(tag, candidate)

    async def receive_status(self, packet, peer):
        validate_ncrh_status(packet)
        pending = self._pending.get(packet['request_id'])
        if pending is None or pending['peer'] != peer or pending['ncrh'] != packet['ncrh']:
            return
        self._pending.pop(packet['request_id'], None)
        task = self._pending_tasks.pop(packet['request_id'], None)
        if task: task.cancel()
        state = self._peer_state(peer)
        state['replies'] += 1
        self._put('peer-knowledge', [peer, packet['ncrh']],
                  {'peer': peer, 'ncrh': packet['ncrh'], 'state': packet['state']}, 1800)
        offered = self._get('offered', packet['request_id'])
        if offered and offered['peer'] == peer:
            for candidate in self._candidates(offered['tag']):
                if candidate['path_key'] == offered['path_key'] and candidate['ncrh'] == packet['ncrh']:
                    await self._send_alias_bind(peer, packet['request_id'], candidate)
                    break
            self._rows.pop(self._index('offered', packet['request_id']), None)

    async def receive_alias_bind(self, packet, peer):
        validate_alias_bind(packet)
        key = [peer, packet['request_id']]
        received = self._get('received', key)
        if received is None or received['ncrh'] != packet['ncrh'] or received.get('label'):
            return
        # The sender owns the advertised prefix. Its capability leads BACK
        # toward that sender, while our NCRH is the locally extended value.
        ttl = received['expires'] - self.clock()
        if ttl <= 0: return
        self._put('received', key, {**received, 'label': packet['hop_route_label'],
                                        'binding_until': self.clock() + packet['lifetime']}, ttl)
        for candidate in self._candidates(received['tag']):
            if (candidate['ncrh_in'] == packet['ncrh'] and candidate['next_peer'] == peer
                    and candidate.get('request_id') == packet['request_id']):
                self._peer_state(peer)['bindings_received'] += 1
                updated = {**candidate, 'outgoing_label': packet['hop_route_label'],
                           'until': min(candidate['until'], self.clock() + packet['lifetime'])}
                if self._install(received['tag'], updated) and updated.get('propagate', True):
                    await self._advertise(received['tag'], updated)
                break

    def _worker_done(self, workers, peer, task):
        if workers.get(peer) is task: workers.pop(peer, None)
        if not task.cancelled() and task.exception() is not None:
            self._peer_state(peer)['errors'] += 1

    def _peer_state(self, peer):
        if peer not in self._sync and len(self._sync) >= self.capacity:
            connected = self.transport.node.active_connections
            for old in list(self._sync):
                if old not in connected: del self._sync[old]
            if len(self._sync) >= self.capacity: raise BufferError('peer sync capacity reached')
        state = self._sync.setdefault(peer, {})
        for key in ('sent', 'replies', 'timeouts', 'advertisements', 'received',
                    'roots_sent', 'roots_received', 'bindings_sent', 'bindings_received', 'errors'):
            state.setdefault(key, 0)
        return state

    def sync_snapshot(self):
        """Local progress only: a semantic reply never implies DATA authority."""
        return {peer: {**state,
                       'pending': sum(p['peer'] == peer for p in self._pending.values())}
                for peer, state in self._sync.items()}

    def _reset_peer(self, peer):
        # A new authenticated channel must not inherit old semantic grants.
        self.transport.hop_routes.revoke_through_peer(peer)
        self._sync.pop(peer, None)
        worker = self._export_tasks.pop(peer, None)
        if worker:
            worker.cancel()
        for request_id, pending in list(self._pending.items()):
            if pending['peer'] == peer:
                self._pending.pop(request_id, None)
                task = self._pending_tasks.pop(request_id, None)
                if task: task.cancel()
        for index, row in list(self._rows.items()):
            value = json.loads(self._box.decrypt(row))
            if value.get('peer') == peer and ('label' in value or 'path_key' in value or 'state' in value):
                self._rows.pop(index, None)
            if 'candidates' in value:
                candidates = [{**c, 'outgoing_label': None} if c['next_peer'] == peer else c
                              for c in value['candidates']]
                self._put('paths', value['tag'], {**value, 'candidates': candidates},
                          max(.001, value['expires'] - self.clock()))

    def schedule_peer_connected(self, peer):
        self._reset_peer(peer)
        previous = self._connection_tasks.get(peer)
        if previous: previous.cancel()
        async def run():
            try:
                await self.peer_connected(peer, reset=False)
            except (ConnectionError, OSError, TimeoutError, BufferError, RuntimeError):
                # Branch stays unresolved; other peer workers continue.
                pass
        task = asyncio.create_task(run())
        self._connection_tasks[peer] = task
        task.add_done_callback(lambda done: self._worker_done(self._connection_tasks, peer, done))

    async def peer_connected(self, peer, *, reset=True):
        # Every authenticated connection starts the same event-driven sync
        # round, whether or not this Node was recently restored.
        if reset: self._reset_peer(peer)
        root = self.transport.system_db.node_crypto.derive_ncrh_root()
        identity = secrets.token_hex(32)
        root_packet = {'type': 'HOP_ROOT_NCRH_V1', 'id': identity,
            'request_id': secrets.token_hex(32), 'ncrh': root, 'metric': 0,
            'hop_limit': 15, 'lifetime': 1800, 'trace': [self._trace_token(identity)]}
        await self._track_and_send(peer, root_packet, 'root')
        # Event-triggered export of all currently valid reconstructed paths.
        for row in list(self._rows.values()):
            value = json.loads(self._box.decrypt(row))
            if value['expires'] <= self.clock() or 'candidates' not in value: continue
            for candidate in self._candidates(value['tag']):
                await self._advertise(value['tag'], candidate, [peer])
        self._start_export(peer)

    async def close(self):
        self._closed = True
        workers = list(self._export_tasks.values()) + list(self._connection_tasks.values())
        for task in workers: task.cancel()
        if workers: await asyncio.gather(*workers, return_exceptions=True)
        self._export_tasks.clear(); self._connection_tasks.clear()
        self._exports.clear()
        for task in list(self._pending_tasks.values()): task.cancel()
        if self._pending_tasks: await asyncio.gather(*self._pending_tasks.values(), return_exceptions=True)
        self._pending.clear(); self._pending_tasks.clear(); self._sync.clear(); self._graph.clear()
        self._rows.clear()
        self._key = self._box = None
