"""Runtime activation boundary for capability-gated Node fallback persistence."""
from __future__ import annotations

from typing import Any

try:
    from fallback_store import FallbackStore
except ModuleNotFoundError:
    from .fallback_store import FallbackStore


async def initialize_fallback_store(connection: Any, runtime_state: Any) -> FallbackStore | None:
    """Activate isolated fallback persistence only for an eligible Node policy."""
    capabilities = getattr(runtime_state, "capabilities", None)
    if not capabilities or not (
        capabilities.can_route and capabilities.can_accept_devices and capabilities.can_fallback_store
    ):
        runtime_state.fallback_store = None
        return None
    store = FallbackStore.from_runtime(connection, runtime_state)
    await store.initialize()
    runtime_state.fallback_store = store
    return store
