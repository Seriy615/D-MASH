# D-MASH

Experimental messenger with Account E2EE, encrypted local storage, a Python Node
runtime, browser Node Worker and optional call/file transports.

## Start here

- [CURRENT_HANDOFF.md](CURRENT_HANDOFF.md): complete current handoff, what works,
  what remains, exact runtime SHA, evidence and transfer checklist.
- [AGENTS.md](AGENTS.md): concise context for continuing development.
- [D-MASH_Codex_Development_Plan.md](D-MASH_Codex_Development_Plan.md): authoritative
  full N0–N8 and compatible A–M/E6 requirements.
- [TRANSPORT_V4.md](TRANSPORT_V4.md) and
  [TRANSPORT_V4_DISCOVERY.md](TRANSPORT_V4_DISCOVERY.md): unified Node contract.

**The accepted target is one network role, NODE.** A browser participates in
third-party transit independently of Account login. DeviceRoot is local secret
material, not a separate network role. V4 protocol/routing/Worker primitives and
native `/mesh/v4` exist; ordinary Account/contact UI still uses the v3 migration
adapter. Completing that integration and authenticated migration is the next
major stage. The old Device network model is not the final architecture.

Development branch: `transport-v3` (historical name, includes v4).
Latest deployed runtime: `ed200730dab2e64fc8446e344ce54dbd37cfeec5`, release
`transport-v3-recorded-fragments-20261008.24`. Exact source match: 205 files.
Current full regression: 264 backend + 11 Origin tests + 67 JS suites PASS;
deployed public contact/message/ratchet/recording/playback/TURN-call regression
PASS. Physical mobile, full v4 Account cutover and the complete plan are not
finished. Portable results: [docs/evidence/2026-10-08](docs/evidence/2026-10-08/).

Historical handoffs and routing notes are in
[docs/archive/2026-10-08](docs/archive/2026-10-08/). Do not treat their old status,
commands or SHA as current. V3 contract remains in
[TRANSPORT_V3.md](TRANSPORT_V3.md) for compatibility/migration reference.

## Repository layout

```text
D-MASH PWA/not_messenger/   Browser PWA, Account runtime, Node Worker and JS tests
D-MASH/client/backend/     Python Node, v3 migration gateway and unified v4
D-MASH/client/tests/       Backend protocol, routing, storage and auth tests
origin/                   Notification / personal-bot service
tools/                    Test harnesses, vendor build and operational utilities
docs/evidence/            Portable test/deploy evidence
docs/archive/             Historical context, not active instructions
```

## Development environment

Python 3.12 and Node.js 24.19.0 are the reference versions. Browser harnesses
require Playwright and Chromium/Chrome; set DMASH_PLAYWRIGHT_MODULE and
DMASH_CHROME for the new server. Optional DSP uses ffmpeg; multi-node fixtures
may use Docker/Compose.

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install -r requirements-test.txt
.venv/bin/python tools/test_all.py
```

The runner includes backend, Origin and all PWA `*.test.js` suites. This is not
real browser/transit/TURN/migration acceptance. See CURRENT_HANDOFF for the
separate scripts, scopes and remaining gates. Recreate dependencies on the new
server; do not copy the old macOS virtual environment.

## Deployment and server transfer

Current PWA: https://messenger.d-mash.ru/not_messenger/.
EMS Node v4: `wss://stage-api-ems.d-mash.ru/mesh/v4`.
EMS v3 migration gateway: `wss://stage-api-ems.d-mash.ru/dmp-c/v3`.
The EMS frontend at stage-ems.d-mash.ru and Forge Node are separate deployments.

[NODE_V4_DEPLOYMENT.md](NODE_V4_DEPLOYMENT.md),
[EMS_STURN_DEPLOYMENT.md](EMS_STURN_DEPLOYMENT.md),
[ACCOUNT_RECORDED_MEDIA.md](ACCOUNT_RECORDED_MEDIA.md) and
[CONTACT_REQUEST_RETRY.md](CONTACT_REQUEST_RETRY.md) describe specific slices.
Operational scripts contain EMS paths; they are not a generic new-host installer.
The EMS get_commit.sh is host-local, not tracked in this repository.

Transfer Git source separately from protected runtime identities, encryption
keys, databases/WAL, credentials, systemd/nginx/TLS/firewall and TURN state.
Browser storage is origin-bound and is not transferred by cloning Git. Preserve
state, prove recovery and rollback before routing real traffic to a new host.
The user designated forge-vps for source/context synchronization. See
[FORGE_SYNC.md](FORGE_SYNC.md) for the actual checkout/SHA/result. This does not
move production runtime or protected state. Development is led by an
orchestrator/team lead with delegated agents and mandatory browser-first audit
of every UI control; see CURRENT_HANDOFF section 7 and BROWSER_QA.md.

The project has no completed independent security audit or endpoint-anonymity /
PCS/PFS/PQ completion claim. Working epoch updates and TURN calls do not prove
those properties.

## License

MIT
