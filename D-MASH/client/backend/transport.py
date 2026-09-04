"""Opaque DMP-C transport bridge.

This module keeps locator handling, mesh packet shaping, and mailbox I/O behind
an easily unit-testable service boundary. It intentionally avoids raw recipient
IDs and never persists raw locators.
"""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from typing import Any, Dict, Optional, Set


@dataclass(slots=True)
class TransportSubmission:
    delivery_id: str
    state: str
    packet: Dict[str, Any]


class NodeTransportService:
    def __init__(self, system_db, node=None, *, can_route: bool = False, can_accept_devices: bool = False):
        self.system_db = system_db
        self.node = node
        self.can_route = can_route
        self.can_accept_devices = can_accept_devices
        self._inbound_locators: Dict[str, str] = {}
        # Runtime-only registry.  It contains blind locator handles and live
        # DMP-C sessions, never user IDs or raw locators.
        self._local_delivery_sessions: Dict[str, Set[Any]] = {}

    def _blind(self, locator: str) -> str:
        if not isinstance(locator, str) or not locator or not self.system_db.node_crypto:
            raise ValueError("invalid route locator")
        return self.system_db.node_crypto.get_blind_hash(locator)

    async def register_inbound_locator(self, locator: str) -> str:
        if not self.can_accept_devices:
            raise PermissionError("device acceptance is disabled by local Node policy")
        if not locator:
            raise ValueError("invalid inbound locator")
        locator_handle = await self.system_db.arm_inbound_locator(locator)
        self._inbound_locators[locator_handle] = locator_handle
        return locator_handle

    async def register_notification_beacon(self, beacon_handle: str) -> str:
        if not self.can_accept_devices:
            raise PermissionError("device acceptance is disabled by local Node policy")
        return await self.system_db.register_notification_beacon(beacon_handle)

    async def unregister_notification_beacon(self, beacon_handle: str) -> bool:
        if not self.can_accept_devices:
            raise PermissionError("device acceptance is disabled by local Node policy")
        return await self.system_db.unregister_notification_beacon(beacon_handle)

    async def bind_locator_notification_beacon(self, locator: str, beacon_handle: str) -> bool:
        if not self.can_accept_devices:
            raise PermissionError("device acceptance is disabled by local Node policy")
        return await self.system_db.bind_locator_notification_beacon(locator, beacon_handle)

    def attach_local_delivery_session(self, locator_handle: str, session: Any) -> None:
        if not self.can_accept_devices:
            return
        if locator_handle:
            self._local_delivery_sessions.setdefault(locator_handle, set()).add(session)

    def detach_local_delivery_session(self, session: Any) -> None:
        for locator_handle in list(self._local_delivery_sessions):
            sessions = self._local_delivery_sessions[locator_handle]
            sessions.discard(session)
            if not sessions:
                self._local_delivery_sessions.pop(locator_handle, None)

    async def unregister_inbound_locator(self, locator: str) -> bool:
        """Remove a local inbound locator and data addressed to its blind alias."""
        if not self.can_accept_devices:
            raise PermissionError("device acceptance is disabled by local Node policy")
        removed = await self.system_db.disarm_inbound_locator(locator)
        locator_handle = self._blind(locator)
        self._inbound_locators.pop(locator_handle, None)
        self._local_delivery_sessions.pop(locator_handle, None)
        return removed

    async def start_probe(
        self,
        route_alias: str,
        back_route_alias: str,
        *,
        hops: int = 0,
        origin_peer_id: str | None = None,
        probe_id: str | None = None,
        ttl: int = 6,
    ) -> TransportSubmission:
        if not self.can_route or not self.can_accept_devices:
            raise PermissionError("routing is disabled by local Node policy")
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
        if not self.can_route or not self.can_accept_devices:
            raise PermissionError("routing is disabled by local Node policy")
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
            delivered_to_session = await self._store_mailbox(self._blind(route_alias), packet)
            state = "DELIVERED_TO_DESTINATION_PWA_SESSION" if delivered_to_session else "DELIVERED_TO_DESTINATION_NODE"
            return TransportSubmission(delivery_id=delivery_id, state=state, packet=packet)
        # DATA must never create an implicit flood.  Route discovery is an
        # explicit Probe operation; callers are required to check
        # ROUTE_STATUS first and an expired/unknown entry is a hard stop.
        if not route:
            return TransportSubmission(delivery_id=delivery_id, state="ROUTE_UNKNOWN", packet=packet)
        await self._dispatch_mesh_packet(packet, next_hop_id=route["next_hop_id"], origin_peer_id=origin_peer_id)
        return TransportSubmission(delivery_id=delivery_id, state="SUBMITTED_TO_ENTRY", packet=packet)

    async def route_status(self, route_alias: str) -> Dict[str, Any]:
        """Return minimal readiness metadata without revealing topology.

        The raw locator is accepted only inside the authenticated client call;
        lookup and all durable state use this Node's blind alias.
        """
        if not self.can_route or not self.can_accept_devices:
            raise PermissionError("routing is disabled by local Node policy")
        if not isinstance(route_alias, str) or not route_alias:
            raise ValueError("route alias is required")
        route = await self.system_db.get_best_route_alias(self._blind(route_alias))
        if not route:
            return {"state": "ROUTE_UNKNOWN"}
        return {
            "state": "ROUTE_READY",
            "best_metric": route["hops"],
            "candidate_count": route["candidate_count"],
            "expires_at": route["expires_at"],
        }

    async def pull(self, locator_handle: str) -> list[dict[str, Any]]:
        if not self.can_accept_devices:
            raise PermissionError("device acceptance is disabled by local Node policy")
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

    async def ack(self, delivery_id: str, *, allowed_locator_handles: Set[str] | None = None) -> bool:
        if not self.can_accept_devices:
            raise PermissionError("device acceptance is disabled by local Node policy")
        if not delivery_id:
            raise ValueError("delivery id is required")
        if not getattr(self.system_db, "conn", None):
            return False
        if allowed_locator_handles is not None and not allowed_locator_handles:
            return False
        query = "SELECT id, packet_json FROM offline_mailbox"
        parameters: list[str] = []
        if allowed_locator_handles is not None:
            placeholders = ",".join("?" for _ in allowed_locator_handles)
            query += f" WHERE target_hash IN ({placeholders})"
            parameters = list(allowed_locator_handles)
        async with self.system_db.conn.execute(query, parameters) as cursor:
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
        if not self.can_route:
            return False
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
        if not self.can_route:
            return None
        route_alias = packet.get("route_id") or packet.get("route_alias")
        if not route_alias:
            return None
        route = await self.system_db.get_best_route_alias(self._blind(route_alias))
        if not route:
            return None
        if route.get("is_local"):
            delivered_to_session = await self._store_mailbox(self._blind(route_alias), packet)
            state = "DELIVERED_TO_DESTINATION_PWA_SESSION" if delivered_to_session else "DELIVERED_TO_DESTINATION_NODE"
            return TransportSubmission(delivery_id=packet.get("id", ""), state=state, packet=packet)
        await self._dispatch_mesh_packet(packet, next_hop_id=route["next_hop_id"], origin_peer_id=from_peer)
        return TransportSubmission(delivery_id=packet.get("id", ""), state="ROUTED_IN_D_MASH", packet=packet)

    async def _store_mailbox(self, locator_handle: str, packet: Dict[str, Any]) -> bool:
        envelope = packet.get("envelope") or {}
        # A call has many encrypted signaling packets (offer/ICE/hangup), but
        # they deliberately share one opaque transport nonce.  Use it as the
        # durable notification identity; ordinary packets keep their delivery
        # ID.  Neither value contains message content or a user identifier.
        notification_id = envelope.get("notification_nonce") or packet.get("id") or secrets.token_hex(16)
        notification_event = envelope.get("notification_event", "MALYAVA")
        if notification_event not in {"MALYAVA", "INCOMING_BAZAR"}:
            notification_event = "MALYAVA"
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
        # Mailbox remains the source of truth until PWA ACK. The live session
        # only receives an opaque availability signal, then PULLs ciphertext.
        delivered = False
        for session in list(self._local_delivery_sessions.get(locator_handle, set())):
            try:
                await session.send_json({
                    "type": "DELIVERY_AVAILABLE",
                    "locator_handle": locator_handle,
                    "delivery_id": packet.get("id"),
                })
                delivered = True
            except Exception:
                self.detach_local_delivery_session(session)
        # The node must not notify a beacon while the PWA has an active local
        # delivery session. The session signal above is intentionally opaque;
        # notification is scheduled only after all live delivery attempts fail.
        if not delivered and self.system_db.notification_trigger:
            notification_handle = await self.system_db.notification_handle_for_locator_alias(locator_handle)
            if notification_handle:
                self.system_db.notification_trigger.schedule(
                    notification_handle, notification_id, event_type=notification_event
                )
        return delivered

    async def _dispatch_mesh_packet(
        self,
        packet: Dict[str, Any],
        *,
        next_hop_id: str | None = None,
        origin_peer_id: str | None = None,
    ) -> None:
        if not self.can_route:
            raise PermissionError("routing is disabled by local Node policy")
        if not self.node:
            return
        await self.node.enqueue_transport_packet(packet, next_hop_id=next_hop_id, exclude_peer_id=origin_peer_id)
