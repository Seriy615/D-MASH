"""Nonempty per-peer transport batches with retry retention."""
import asyncio
import json
import time

if __package__:
    from .node_session import MAX_BATCH_PACKETS, MAX_BATCH_BYTES, canonical
else:
    from node_session import MAX_BATCH_PACKETS, MAX_BATCH_BYTES, canonical


class TactEngine:
    def __init__(self, db, node, interval=0.5, packet_size=None):
        self.db, self.node, self.interval = db, node, interval
        self.running = False

    async def start(self):
        self.running = True
        while self.running:
            started = time.monotonic()
            await self._tick()
            await asyncio.sleep(max(0, self.interval - (time.monotonic() - started)))

    async def _tick(self):
        if not self.node.can_route or not self.node.active_connections or not self.db.node_crypto:
            return
        connections = dict(self.node.active_connections)
        queue = self.node.transient_transport_outbox
        # Retain the original queue across await/cancellation. Successful peers
        # are removed individually so a partial broadcast retries only failures.
        for item in list(queue):
            if "pending_peers" not in item:
                target = item.get("next_hop_id")
                peers = {target} if target else {p for p in connections if p != item.get("exclude_peer_id")}
                if peers:
                    item["pending_peers"] = peers
        async def flush_peer(peer, channel):
            batch, items, size = [], [], 2
            for item in list(queue):
                if peer not in item.get("pending_peers", ()):
                    continue
                packet_size = len(canonical(item["packet"])) + 2
                if len(batch) >= MAX_BATCH_PACKETS or size + packet_size > MAX_BATCH_BYTES:
                    break
                batch.append(item["packet"]); items.append(item); size += packet_size
            if not batch:
                return
            try:
                async with asyncio.timeout(10):
                    await channel.send_batch(batch)
            except Exception:
                return
            for item in items:
                item["pending_peers"].discard(peer)
        await asyncio.gather(*(flush_peer(peer, channel) for peer, channel in connections.items()))
        queue[:] = [item for item in queue if item.get("pending_peers") != set()]

        # Historical durable rows remain accessible until their migration. A
        # disconnected target or failed send must never acknowledge a row.
        active = {self.db.node_crypto.get_blind_hash(p): c for p, c in connections.items()}
        async with self.db.conn.execute("SELECT id, next_hop_hash, packet_json, exclude_peer_hash FROM outbox ORDER BY created_at ASC LIMIT 5") as cursor:
            rows = await cursor.fetchall()
        for row in rows:
            try:
                packet = json.loads(row["packet_json"])
                if "sealed_dmp_c" in packet:
                    packet = self.db.node_crypto.decrypt_from_self(packet["sealed_dmp_c"])
                target = row["next_hop_hash"]
                targets = [active[target]] if target in active else ([] if target else [c for h, c in active.items() if h != row["exclude_peer_hash"]])
                if not targets:
                    continue
                for channel in targets:
                    async with asyncio.timeout(10):
                        await channel.send_batch([packet])
            except Exception:
                continue
            await self.db.conn.execute("DELETE FROM outbox WHERE id = ?", (row["id"],))
        await self.db.conn.commit()
