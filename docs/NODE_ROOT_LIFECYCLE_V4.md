# Managed root lifecycle candidate

Followup to ordinary UI e7817cd; isolated source only, no release or browser PASS.
The candidate explicitly selects `DMASH_NODE_PROFILE=managed-v4` in its loader.
DeviceRoot emits an unlock notification only after successful persisted root
restoration/creation. The lifecycle module also attaches to an already unlocked
root, supporting the lazy loader. No Account, Account key or active chat is used.

One coalesced root-session job starts the existing managed coordinator and connects
its independently pinned v4 catalog. Account logout does not enter this lifecycle.
Global lock/replacement invalidates the job; the coordinator closes its Host and
receipt router. A late asynchronous startup cannot reconnect an obsolete root.
Failed startup leaves identity storage untouched and exposes UNAVAILABLE; explicit
retry uses the same root. No repeated background reconnect loop is introduced.

NodeManager's old unlock hook honors the explicit managed profile: missing module,
failed pin or failed connect is returned as an error, never a v3 autoConnect fallback.
Explicit legacy contact compatibility still exists elsewhere for migration and is
not a completed v3 removal. Existing legacy sockets created before this source was
loaded are not silently relabeled or destroyed. A clean page lifecycle/real upgrade
acceptance must verify this boundary before release.

Unit checks use real DeviceRoot lifecycle notifications plus coordinator doubles:
unlock without Account, coalescing, lock during startup, failed pin preserving root,
explicit retry, observer failure isolation, and refusal of legacy autoConnect.
Existing DeviceRoot acceptance and critical media loader suites remain required.
Real browser root-only transit, Account switch/logout and global lock are pending.
