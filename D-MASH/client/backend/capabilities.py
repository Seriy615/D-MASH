"""Universal Python Node capability policy.

This module describes local Node policy only.  It never grants Device access,
contains no Account fields, and does not make fallback, signal, TURN, or blob
protocols available before their own reviewed implementations exist.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from typing import FrozenSet


_CAPABILITY_ENV = {
    "can_route": "DMASH_CAN_ROUTE",
    "can_accept_devices": "DMASH_CAN_ACCEPT_DEVICES",
    "can_fallback_store": "DMASH_CAN_FALLBACK_STORE",
    "can_signal": "DMASH_CAN_SIGNAL",
    "can_be_turn": "DMASH_CAN_BE_TURN",
    "can_relay_blob": "DMASH_CAN_RELAY_BLOB",
}
_PUBLIC_OPERATIONS = frozenset({
    "PING",
    "STATUS",
    "REGISTER_INBOUND_LOCATOR",
    "START_PROBE",
    "ROUTE_STATUS",
    "UNREGISTER_INBOUND_LOCATOR",
    "SUBMIT_ENVELOPE",
    "PULL",
    "ACK",
    "REGISTER_NOTIFICATION_BEACON",
    "UNREGISTER_NOTIFICATION_BEACON",
    "BIND_LOCATOR_NOTIFICATION_BEACON",
})


def _bool_env(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be one of 1/0, true/false, yes/no, on/off")


@dataclass(frozen=True)
class NodeCapabilities:
    """Configured local Node policy, deliberately independent of Accounts."""

    visibility: str = "public"
    can_route: bool = True
    can_accept_devices: bool = False
    can_fallback_store: bool = False
    can_signal: bool = False
    can_be_turn: bool = False
    can_relay_blob: bool = False

    def __post_init__(self) -> None:
        if self.visibility not in {"public", "private"}:
            raise ValueError("DMASH_NODE_VISIBILITY must be public or private")

    @classmethod
    def from_env(cls) -> "NodeCapabilities":
        visibility = os.getenv("DMASH_NODE_VISIBILITY", "public").strip().lower()
        defaults = cls(visibility=visibility)
        values = {
            field: _bool_env(environment, getattr(defaults, field))
            for field, environment in _CAPABILITY_ENV.items()
        }
        return cls(visibility=visibility, **values)

    def advertised_operations(self) -> FrozenSet[str]:
        """Return only implemented legacy operations allowed by local policy.

        DMP-C v2 authenticates a node-scoped Device transport principal. The
        Device-only routing operations remain deliberately unadvertised here:
        capability flags are policy, not a protocol grant, and DMP-D is not
        implemented.
        """
        if not self.can_route or not self.can_accept_devices:
            return frozenset({"PING", "STATUS"})
        return _PUBLIC_OPERATIONS

    def is_operation_allowed(self, operation: str) -> bool:
        return operation in self.advertised_operations()


def allowed_operations(state) -> FrozenSet[str]:
    """Resolve a runtime state's local policy without Account information."""
    capabilities = getattr(state, "capabilities", None)
    # A partially initialized runtime must not accidentally expose routing.
    return capabilities.advertised_operations() if capabilities else frozenset({"PING", "STATUS"})
