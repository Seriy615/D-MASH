# D-MASH

D-MASH is an experimental privacy-oriented messenger prototype. The repository contains a browser client, a Python node runtime, an authenticated client-to-node protocol, encrypted local storage, mesh routing primitives, and optional media transports.

> This is a prototype. It has not received an independent security audit. Do not use it for sensitive communication without reviewing the implementation and threat model.

## Current development state

Active development is on `transport-v3`, based on `aa0ad8a` (2026-09-18).
The current implementation still has distinct DEVICE and NODE network roles.
The PWA does **not** yet relay third-party Mesh packets. The target is a unified
Node runtime, including browsers, with Account-independent transit.

- [CURRENT_HANDOFF.md](CURRENT_HANDOFF.md): current milestone status and evidence.
- [D-MASH_Codex_Development_Plan.md](D-MASH_Codex_Development_Plan.md): development requirements.
- [TRANSPORT_V4.md](TRANSPORT_V4.md): proposed unified contract, source privacy audit,
  migration gates and unresolved architecture decisions.
- [TRANSPORT_V3.md](TRANSPORT_V3.md): historical v3 implementation contract.

N0 is partial. Existing Probe metrics/traces and endpoint-facing resource
operations do not meet the new endpoint-privacy requirement. Neither unit tests
nor renaming a role establishes anonymity or real browser transit.

## Repository layout

```text
D-MASH PWA/                 Browser PWA and legacy HTTP compatibility endpoints
D-MASH/client/backend/      Python node, DMP-C gateway, routing, storage, crypto
D-MASH/client/tests/        Python tests for gateway, transport, mailbox, and notifications
D-MASH/client/docker/       Docker image and startup files
origin/                     Origin notification and personal-bot service
D-MASH/stress_test.py       Local mesh stress-test entrypoint
tools/                      Operational deployment utilities
```

## Requirements

- Python 3.12 for the reference test/runtime environment
- `pip`
- `ffmpeg` for the optional DSP modules
- Docker and Docker Compose for the multi-node local setup
- a modern browser with WebSocket, IndexedDB, Web Crypto, service-worker, camera, and microphone support for the PWA

Python dependencies are listed in `D-MASH/client/requirements.txt`.

## Local Python node

Create an environment and install the dependencies:

```bash
cd D-MASH/client
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
```

Start a node locally:

```bash
cd D-MASH/client/backend
P2P_HOST=127.0.0.1 P2P_PORT=9001 DMASH_HTTP_HOST=127.0.0.1 DMASH_HTTP_PORT=8001 \
  python main.py
```

The HTTP service serves the Python node interface. The P2P listener is used for node-to-node connections. A node identity is created on first start and stored in `node_identity.key`; keep that file private and persistent for a stable node identity.

### Linking verified Node peers

Node peers are deliberately not configured through the public PWA or an HTTP
endpoint. On the host of a running Node, first ensure its P2P TCP port is
reachable, then add the other Node by its `host:P2P-port`:

```bash
sudo -u dmash-node dmash-node-peer add forge.example.net:19090
sudo -u dmash-node dmash-node-peer list
```

`add` completes the Node PoW and signature handshake before it persists the
encrypted peer-directory entry. The Node daemon reconnects known peers every
10 seconds; do not edit `system.db` manually.

## Local multi-node setup

The Compose file starts four development nodes with separate HTTP and P2P ports:

```bash
cd D-MASH/client
docker compose -f user-docker-compose.yml up --build
```

The development HTTP ports are `8001` through `8004`. The corresponding P2P ports are `9001` through `9004`.

## PWA

The application entrypoint is:

```text
D-MASH PWA/not_messenger/index.html
```

The browser loads node endpoints from `nodes.json`. A node session uses a challenge-response Ed25519 signature before the client can issue DMP-C operations.

The PWA transport modes are explicit:

- **D-MASH Mesh** uses the authenticated DMP-C gateway and opaque transport locators.
- **Legacy Relay** uses the compatibility PHP endpoint and must be selected explicitly.

Mesh mode must not silently fall back to the legacy relay. Without an active node or an armed route, delivery is reported as unavailable rather than being presented as delivered.

## Transport and local state

The active v3 gateway authenticates DEVICE sessions and independently authorizes
DNSS, route registration, probes, route status, submission and mailbox drain.
Python Node peers use a separate NODE authorization flow. The proposed v4
contract is not yet enabled. Mesh mode has no silent fallback to the PHP relay.

V3 mailbox PULL leases all currently authorized rows within quota, awaits send,
and deletes only the leased rows after successful send. Send failure retains
mail; a crash between send/delete can duplicate delivery. There is no mandatory
client ACK in this v3 drain. The PWA persists opaque payloads locally and
processes them only under the matching Account. Hop acceptance is not Account
DELIVERED or READ. Bad local Inbox records are isolated during drain and retained
for recovery; persistent quarantine/backoff remains unfinished.

The retired HTTP control API (login/logout/connect/debug/state/peers/messages/
rename/read/send) now returns 410 before touching runtime state. Use the host
peer CLI above for peer administration. It is not a browser admin API.

Node identity and BaseNCRH sidecars are runtime secrets, excluded from source
distribution. Preserve existing files across upgrades. A previously tracked
BaseNCRH requires deployed-instance inventory and controlled rotation if used;
repository removal does not revoke deployed copies or erase Git history.

## Testing

From the repository root, use an isolated Python 3.12 environment:

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install -r requirements-test.txt
.venv/bin/python tools/test_all.py
```

The runner includes backend, Origin and all PWA `*.test.js` suites; Node.js is
required (reference version 24.19.0). ASGI tests explicitly pin `httpx` with the
runtime dependencies. Passing local tests is not real-browser, TURN, deployment
or v4 transit acceptance. Never reset user storage to pass acceptance.

## Deployment model

Development runs on the stage environment. Only a tested build is promoted to production. Runtime services should be managed by a service supervisor such as systemd so they continue after an SSH session closes.

### EMS deployment boundaries

The physical EMS host serves several distinct applications. Keep their nginx
virtual hosts and web roots separate:

- **D-MASH Messenger PWA:** `https://messenger.d-mash.ru/not_messenger/`.
- **EMS application/frontend:** a separate application boundary;
  `stage-ems.d-mash.ru` is an EMS React frontend and is **not** the Messenger
  PWA.
- **EMS D-MASH Node / DMP-C gateway:** the configured test entry endpoint is
  `wss://stage-api-ems.d-mash.ru/dmash-client/v1`.
- **Forge:** contains a separate D-MASH Node only. Never deploy the Messenger
  PWA to Forge unless explicitly required.

Before a PWA promotion, inspect the actual `server_name messenger.d-mash.ru`
nginx block and establish its root/alias, `index`, `try_files`, Service Worker
scope and cache behavior. Do not infer those details from a different EMS
frontend virtual host.

The production PWA promotion utility is:

```bash
tools/dmash-promote-pwa
```

The script promotes only the Messenger PWA from
`/srv/messenger-stage/public_html/not_messenger` to
`/srv/messenger.d-mash.ru/public_html/not_messenger`, creating a backup below
`/srv/messenger.d-mash.ru/backups`. It is not a deployment path for the EMS
application frontend or Forge.

Do not commit private keys, node identities, databases, tokens, certificates, virtual environments, or runtime logs. Keep deployment secrets in the server secret store or environment configuration.

## Known limitations

- The project is a proof of concept and is not independently audited.
- Mesh routing and browser two-session delivery require further end-to-end validation.
- The current legacy Python routing code is retained as a compatibility baseline while opaque multi-hop routing is integrated.
- The legacy PHP relay is not equivalent to D-MASH mesh transport.
- Service-worker cache updates are release-scoped, but browser acceptance should still verify that a new release is active before testing it.
- DSP and audio transports are optional experimental modules and are not part of the basic text-message acceptance path.

## License

MIT
