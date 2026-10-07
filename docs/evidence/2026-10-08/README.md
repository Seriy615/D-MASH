# Evidence snapshot — 8 October 2026, Europe/Moscow

Runtime SHA: `ed200730dab2e64fc8446e344ce54dbd37cfeec5`, release `.24`.
Full tests and deployed public browser acceptance completed with exit 0;
exact verifier checked 205 files without missing/changed. Each copied log's
SHA-256/size is in [manifest.json](manifest.json). Original /tmp paths are
provenance, not paths that must exist on the new server.

These are genuine saved outputs, not independently notarized artifacts. Full
unit regression is separate from real browser behavior. Browser mic/camera are
synthetic; crypto, WSS, EMS and TURN relay are real. Initial route readiness
required retries. Logs include synthetic test identity prefixes, paths and
service metadata; no private keys/credential values were copied.

Older v4 real-transit raw logs cited in the archived handoff are absent on this
machine. Their historical PASS must not be represented as fresh .24 acceptance.
Rerun v4 browser transit/Worker/Inbox on the new server. The local-RTC log is a
separate earlier call fixture; the deployed .24 log contains actual forced-TURN
call evidence. See [CURRENT_HANDOFF](../../../CURRENT_HANDOFF.md) for limits.
