# S-TURN health candidate — not deployed

This changes backend readiness only. It does not enable can_signal or can_relay_blob,
change coturn listeners/secrets, or complete ordinary Account/Node integration.
Existing EMS UDP/TCP 3479 and public WSS were tested; port 3478 was untouched.

Production from_env uses one asynchronous checker. Cached synchronous capability
reads perform no network I/O. Each configured TURN URL (maximum four) must pass
real authenticated allocation and two-way nonce/hash relay; only successful URLs
are returned. The normal public WSS CREATE/work/scoped caller+callee JOIN and
bidirectional signaling must also succeed before can_s_turn becomes true.
Transport readiness admits ordinary signaling before descriptor readiness, avoiding
circular self-test bootstrap without an auth bypass. Failure never creates readiness.

Polling waits 15 seconds after completion; observations expire after 45 seconds.
Each transport attempt is bounded by 12 seconds plus at most 2 seconds cleanup;
WSS is bounded by 12 seconds plus WebSocket close overhead. No overlapping checkers.
PoW stops within 8 seconds and checks cancellation every 1024 iterations. Thus this
is bounded background observation, not an instantaneous outage detector. A failed
transport is removed; one working transport can remain usable. At most two TURN
allocations exist concurrently per checker, requested lifetime 30 seconds, with
explicit REFRESH(0) deletion. Server lifetime policy may differ; client cleanup
always cancels refresh and closes owned sockets even if deletion fails. Signaling
uses ordinary ephemeral sessions; gateway disconnect closes their registry entries.

Dependency: aioice==0.10.2 (requirements.txt). Its low-level TurnClient protocols
are deliberately isolated here: Connection gathering / TurnTransport.sendto and
close create detached tasks, unsuitable for bounded owned health cleanup. Adapter
awaits allocation/send/delete directly and owns every socket. An aioice upgrade
requires rerunning cancellation/failure tests and live probes.

Validation at candidate source, before commit:
- Python 3.12: 16 S-TURN unit tests PASS, including cancellation during allocation,
  failed-delete timeout, no overlapping monitors, stale readiness and partial failure.
- Python gateway + Node.js 24.19 signaling client: 7 tests PASS. Existing TestClient
  anyio resource warnings remain; gateway assertions verify empty session registry.
- tools/qa_sturn_health.py: actual EMS UDP and TCP allocation/relay plus public WSS
  signaling PASS, no additional outstanding asyncio tasks after either relay probe.
  Sanitized evidence: docs/evidence/2026-10-08/qa-node-sturn-health-candidate.log.
- First earlier Connection-based probe failed RuntimeError and subsequent probe
  passed; this is not hidden as continuous availability evidence.

Limits: this backend candidate has not been deployed. It is not full browser call,
file, voice/circle E2EE, offline delivery, cancellation, or user consent acceptance.
Separate Chromium smoke already selected relay candidates on both peers and
verified 32768-byte hash, but did not exercise ordinary UI or Account E2EE. Recorded
media must stay encrypted at sender offline; only bounded encrypted invitation and
authenticated ready response cross Mesh. Media bytes use relay data channel only.

Deployment requires parent review, exact runtime snapshot/rollback and dependency
installation. Do not deploy this worktree wholesale or transfer dev data/identities.
