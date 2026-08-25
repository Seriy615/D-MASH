"""Opaque DMP-C transport bridge.

This module keeps locator handling, mesh packet shaping, and mailbox I/O behind
an easily unit-testable service boundary. It intentionally avoids raw recipient
IDs and never persists raw locators.
"""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass(slots=True)
class TransportSubmission:
    delivery_id: str
    state: str
    packet: Dict[str, Any]


class NodeTransportService:
    def __init__(self, system_db, node=None):
        self.system_db = system_db
        self.node = node
        self._inbound_locators: Dict[str, str] = {}

    def _blind(self, locator: str) -> str:
        if not isinstance(locator, str) or not locator or not self.system_db.node_crypto:
            raise ValueError("invalid route locator")
        return self.system_db.node_crypto.get_blind_hash(locator)

    async def register_inbound_locator(self, locator: str) -> str:
        if not locator:
            raise ValueError("invalid inbound locator")
        locator_handle = await self.system_db.arm_inbound_locator(locator)
        self._inbound_locators[locator_handle] = locator_handle
        return locator_handle

    async def unregister_inbound_locator(self, locator: str) -> bool:
        """Remove a local inbound locator and data addressed to its blind alias."""
        removed = await self.system_db.disarm_inbound_locator(locator)
        self._inbound_locators.pop(self._blind(locator), None)
        return removed

    async def start_probe(
        self,
        route_alias: str,
        back_route_alias: str,
        *,
        hops: int = 0,
        origin_peer_id: str | None = None,
        probe_id: str | None = None,
        ttl: int = 20,
    ) -> TransportSubmission:
        if not route_alias or not back_route_alias:
            raise ValueError("route aliases are required")
        packet = {
            "type": "DMP_C_PROBE",
            "id": probe_id or secrets.token_hex(16),
            "route_id": route_alias,
            "back_route_id": back_route_alias,
            "hops": int(hops),
            "ttl": int(ttl),
        }
        await self.system_db.add_route_alias(
            self._blind(back_route_alias), origin_peer_id or "LOCAL", int(hops),
            is_local=origin_peer_id is None,
        )
        await self._dispatch_mesh_packet(packet, origin_peer_id=origin_peer_id)
        return TransportSubmission(delivery_id=packet["id"], state="SUBMITTED_TO_ENTRY", packet=packet)

    async def submit_envelope(
        self,
        route_alias: str,
        envelope: Dict[str, Any],
        *,
        origin_peer_id: str | None = None,
    ) -> TransportSubmission:
        if not route_alias:
            raise ValueError("route alias is required")
        delivery_id = envelope.get("delivery_id") or envelope.get("packet_id") or secrets.token_hex(16)
        packet = {
            "type": "DMP_C_DATA",
            "id": delivery_id,
            "route_id": route_alias,
            "envelope": envelope,
        }
        route = await self.system_db.get_best_route_alias(self._blind(route_alias))
        if route and route.get("is_local"):
            await self._store_mailbox(self._blind(route_alias), packet)
            return TransportSubmission(delivery_id=delivery_id, state="DELIVERED_TO_DESTINATION_NODE", packet=packet)
        if not route:
            await self._dispatch_mesh_packet(packet, origin_peer_id=origin_peer_id)
            return TransportSubmission(delivery_id=delivery_id, state="ROUTE_NOT_ARMED", packet=packet)
        await self._dispatch_mesh_packet(packet, next_hop_id=route["next_hop_id"], origin_peer_id=origin_peer_id)
        return TransportSubmission(delivery_id=delivery_id, state="SUBMITTED_TO_ENTRY", packet=packet)

    async def pull(self, locator_handle: str) -> list[dict[str, Any]]:
        if not locator_handle:
            raise ValueError("locator handle is required")
        async with self.system_db.conn.execute(
            "SELECT id, packet_json, notification_id FROM offline_mailbox WHERE target_hash = ?",
            (locator_handle,),
        ) as cursor:
            rows = await cursor.fetchall()
        packets: list[dict[str, Any]] = []
        for row in rows:
            try:
                packets.append(json.loads(row["packet_json"]))
            except json.JSONDecodeError:
                continue
        return packets

    async def ack(self, delivery_id: str) -> bool:
        if not delivery_id:
            raise ValueError("delivery id is required")
        if not getattr(self.system_db, "conn", None):
            return False
        async with self.system_db.conn.execute("SELECT id, packet_json FROM offline_mailbox") as cursor:
            rows = await cursor.fetchall()
        ids_to_delete = []
        for row in rows:
            try:
                packet = json.loads(row["packet_json"])
            except json.JSONDecodeError:
                continue
            if packet.get("id") == delivery_id or packet.get("envelope", {}).get("delivery_id") == delivery_id:
                ids_to_delete.append(row["id"])
        if not ids_to_delete:
            return False
        await self.system_db.conn.execute(
            f"DELETE FROM offline_mailbox WHERE id IN ({','.join(['?'] * len(ids_to_delete))})",
            ids_to_delete,
        )
        await self.system_db.conn.commit()
        return True

    async def receive_probe(self, packet: Dict[str, Any], from_peer: str, *, is_destination: bool = False) -> bool:
        back_route_alias = packet.get("back_route_id") or packet.get("back_route_alias")
        route_alias = packet.get("route_id") or packet.get("route_alias")
        hops = int(packet.get("hops", 0))
        candidate_hops = hops + 1
        updated = False
        if back_route_alias:
            updated = await self.system_db.add_route_alias(self._blind(back_route_alias), from_peer, candidate_hops, is_local=False) or updated
        if is_destination and route_alias:
            updated = await self.system_db.add_route_alias(self._blind(route_alias), "LOCAL", candidate_hops, is_local=True) or updated
        return updated

    async def receive_data(self, packet: Dict[str, Any], from_peer: str) -> Optional[TransportSubmission]:
        route_alias = packet.get("route_id") or packet.get("route_alias")
        if not route_alias:
            return None
        route = await self.system_db.get_best_route_alias(self._blind(route_alias))
        if not route:
            return None
        if route.get("is_local"):
            await self._store_mailbox(self._blind(route_alias), packet)
            return TransportSubmission(delivery_id=packet.get("id", ""), state="DELIVERED_TO_DESTINATION_NODE", packet=packet)
        await self._dispatch_mesh_packet(packet, next_hop_id=route["next_hop_id"], origin_peer_id=from_peer)
        return TransportSubmission(delivery_id=packet.get("id", ""), state="ROUTED_IN_D_MASH", packet=packet)

    async def _store_mailbox(self, locator_handle: str, packet: Dict[str, Any]) -> None:
        notification_id = packet.get("id") or secrets.token_hex(16)
        mailbox_packet = dict(packet)
        # The raw route locator is transient mesh metadata and is not needed
        # after the destination edge has been selected.
        mailbox_packet.pop("route_id", None)
        mailbox_packet.pop("back_route_id", None)
        mailbox_packet.pop("route_alias", None)
        mailbox_packet.pop("back_route_alias", None)
        await self.system_db.conn.execute(
            "INSERT INTO offline_mailbox (target_hash, packet_json, notification_id) VALUES (?, ?, ?)",
            (locator_handle, json.dumps(mailbox_packet), notification_id),
        )
        await self.system_db.conn.commit()

    async def _dispatch_mesh_packet(
        self,
        packet: Dict[str, Any],
        *,
        next_hop_id: str | None = None,
        origin_peer_id: str | None = None,
    ) -> None:
        if not self.node:
            return
        await self.node.enqueue_transport_packet(packet, next_hop_id=next_hop_id, exclude_peer_id=origin_peer_id)
