"""First-arrival-armed mesh aggregation; independent FIFO peer senders."""
import asyncio
import json
from collections import deque

if __package__:
    from .node_session import MAX_BATCH_PACKETS, MAX_BATCH_BYTES, NodeChannel, canonical
else:
    from node_session import MAX_BATCH_PACKETS, MAX_BATCH_BYTES, NodeChannel, canonical


class TactEngine:
    def __init__(self, db, node, interval=0.5, packet_size=None, *, clock=None, retry_delay=1.0):
        self.db, self.node, self.interval = db, node, interval
        self.clock = clock or asyncio.get_running_loop()
        self.retry_delay = retry_delay
        self.running = False
        self._closed = False
        self._timer = None
        self.deadline = None
        self._incoming = []
        self._snapshots = deque()
        self._unresolved = []
        self._dispatch_task = None
        self._wake = asyncio.Event()
        self._space = asyncio.Event()
        self._peer_queues = {}
        self._workers = {}
        self._maintenance = set()
        node.transport_batcher = self
        for item in node.transient_transport_outbox:
            self.accept(item)

    def accept(self, item):
        """Called synchronously with enqueue: no await between arrival and arm."""
        now = self.clock.time()
        # If the event loop ran enqueue before an overdue timer callback, the
        # old window still closes at its original deadline, never at this arrival.
        if self.deadline is not None and now >= self.deadline:
            self._close_window()
        self._incoming.append(item)
        if self.deadline is None:
            self.deadline = now + self.interval
            if not self._closed:
                self._timer = self.clock.call_at(self.deadline, self._close_window)

    def _close_window(self):
        # Synchronous callback: the swap and return to IDLE cannot interleave
        # with enqueue. Routing and socket I/O occur only in separate tasks.
        if self._timer:
            self._timer.cancel()
        self._timer = None
        self.deadline = None
        snapshot, self._incoming = self._incoming, []
        if snapshot:
            self._snapshots.append(snapshot)
            self._kick_dispatch()

    def _kick_dispatch(self):
        self._wake.set()
        if not self._closed and (self._dispatch_task is None or self._dispatch_task.done()):
            self._dispatch_task = asyncio.create_task(self._dispatch())

    async def _dispatch(self):
        # One resolver preserves snapshot order; it never awaits peer sends.
        while self._snapshots or self._unresolved:
            self._wake.clear()
            if self._snapshots:
                self._unresolved.extend(self._snapshots.popleft())
            groups = {}
            blocked_routes = set()
            try:
                for item in list(self._unresolved):
                    if not self.node.can_route:
                        break
                    route_key = item['packet'].get('route_id') or item['packet'].get('route_alias')
                    if route_key and route_key in blocked_routes:
                        continue
                    try:
                        peers = await self.node.resolve_transport_targets(item)
                    except Exception:
                        peers = None
                    if peers is None:
                        if route_key:
                            blocked_routes.add(route_key)
                        continue
                    item['pending_peers'] = set(peers)
                    self._unresolved.remove(item)
                    if not peers:
                        self._complete(item)
                    for peer in peers:
                        groups.setdefault(peer, []).append(item)
            finally:
                # Even cancellation during a later lookup must retain packets
                # already resolved in this pass, in their original FIFO order.
                self._publish_groups(groups)
            if not self._snapshots and self._unresolved:
                # Retry only outstanding unresolved work, not a global tact.
                try:
                    await asyncio.wait_for(self._wake.wait(), self.retry_delay)
                except TimeoutError:
                    pass

    def _publish_groups(self, groups):
        for peer, items in groups.items():
            queue = self._peer_queues.setdefault(peer, deque())
            batch, size = [], 2
            for item in items:
                added = item['queue_bytes'] + bool(batch)
                if batch and (len(batch) == MAX_BATCH_PACKETS or size + added > MAX_BATCH_BYTES):
                    queue.append(batch)
                    batch, size = [], 2
                size += item['queue_bytes'] + bool(batch)
                batch.append(item)
            if batch:
                queue.append(batch)
            self._start_worker(peer)

    def _start_worker(self, peer):
        current = self._workers.get(peer)
        if self._closed or (current is not None and not current.done()):
            return
        task = asyncio.create_task(self._send_peer(peer))
        self._workers[peer] = task
        def finished(done):
            if self._workers.get(peer) is done:
                self._workers.pop(peer, None)
            if not done.cancelled():
                done.exception()  # retrieve unexpected errors; work remains queued
            if self._peer_queues.get(peer) and not self._closed:
                self._start_worker(peer)
        task.add_done_callback(finished)

    async def _send_peer(self, peer):
        queue = self._peer_queues[peer]
        while queue:
            batch = queue[0]  # retain ownership across failed/cancelled awaits
            channel = self.node.active_connections.get(peer)
            if channel is None or not self.node.can_route:
                await asyncio.sleep(self.retry_delay)
                continue
            try:
                async with asyncio.timeout(10):
                    await channel.send_batch([item['packet'] for item in batch])
            except Exception:
                await asyncio.sleep(self.retry_delay)
                continue
            # No suspension between send completion and recording success.
            queue.popleft()
            for item in batch:
                item['pending_peers'].discard(peer)
                if not item['pending_peers']:
                    self._complete(item)
        self._peer_queues.pop(peer, None)

    def _complete(self, item):
        if 'durable_id' in item:
            item['sent'] = True
            self._maintain(self._delete_durable(item))
        else:
            self._release(item)

    def _release(self, item):
        self.node.transient_transport_outbox.remove(item)
        self._space.set()

    def _maintain(self, coroutine):
        task = asyncio.create_task(coroutine)
        self._maintenance.add(task)
        task.add_done_callback(self._maintenance.discard)
        return task

    async def _delete_durable(self, item):
        # A database failure must not resend a successfully written batch.
        while True:
            try:
                await self.db.conn.execute('DELETE FROM outbox WHERE id = ?', (item['durable_id'],))
                await self.db.conn.commit()
            except Exception:
                await asyncio.sleep(self.retry_delay)
                continue
            self._release(item)
            return

    async def _load_legacy(self):
        """One startup scan of existing rows; new mesh packets stay RAM-only."""
        after = 0
        while not self._closed and self.node.can_route:
            async with self.db.conn.execute('SELECT id, next_hop_hash, packet_json, exclude_peer_hash FROM outbox WHERE id > ? ORDER BY id LIMIT 64', (after,)) as cursor:
                rows = await cursor.fetchall()
            if not rows:
                return
            for row in rows:
                after = row['id']
                if any(item.get('durable_id') == after for item in self.node.transient_transport_outbox):
                    continue
                try:
                    packet = json.loads(row['packet_json'])
                    if 'sealed_dmp_c' in packet:
                        packet = self.db.node_crypto.decrypt_from_self(packet['sealed_dmp_c'])
                    NodeChannel._operation(packet)
                    size = len(canonical(packet))
                    if size > 128 * 1024:
                        continue
                except Exception:
                    continue  # preserve unsupported historical rows unchanged
                while (len(self.node.transient_transport_outbox) >= 4096 or
                       sum(i['queue_bytes'] for i in self.node.transient_transport_outbox) + size > 16 * 1024 * 1024):
                    self._space.clear()
                    await self._space.wait()
                item = dict(packet=packet, queue_bytes=size, durable_id=after,
                            next_hop_hash=row['next_hop_hash'], exclude_peer_hash=row['exclude_peer_hash'])
                self.node.transient_transport_outbox.append(item)
                self.accept(item)

    async def start(self):
        self.running = True
        self._closed = False
        if self.deadline is not None and self._timer is None:
            self._timer = self.clock.call_at(self.deadline, self._close_window)
        if self._snapshots or self._unresolved:
            self._kick_dispatch()
        for peer in self._peer_queues:
            self._start_worker(peer)
        for item in self.node.transient_transport_outbox:
            if item.get('sent'):
                self._maintain(self._delete_durable(item))
        self._maintain(self._load_legacy())
        try:
            await asyncio.Future()  # IDLE has no aggregation timer or polling
        finally:
            await self.close()

    async def close(self):
        self.running = False
        self._closed = True
        if self._timer:
            self._timer.cancel()
            self._timer = None
        tasks = list(self._workers.values()) + list(self._maintenance)
        if self._dispatch_task:
            tasks.append(self._dispatch_task)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
