# D-MASH

D-MASH is an experimental privacy-oriented messenger prototype. The repository contains a browser client, a Python node runtime, an authenticated client-to-node protocol, encrypted local storage, mesh routing primitives, and optional media transports.

> This is a prototype. It has not received an independent security audit. Do not use it for sensitive communication without reviewing the implementation and threat model.

## Current version

The current tree is the code-only M1.5 baseline. It includes:

- browser PWA client in `D-MASH PWA/not_messenger`;
- Python node runtime in `D-MASH/client/backend`;
- authenticated DMP-C WebSocket client gateway;
- node-to-node WebSocket transport with encrypted node-local state;
- opaque locator registration, probe propagation, shortest-route candidate selection, envelope submission, mailbox pull, and acknowledgement operations;
- encrypted local message storage and E2EE message handling;
- service-worker releases with release-scoped static caches;
- optional Tact traffic-shaping and DSP audio modules;
- notification and personal-bot integration under `origin`.

The mesh transport implementation is still being integrated and validated. A connected PWA proves an authenticated control session, not successful end-to-end message delivery. The legacy PHP relay remains in the tree for compatibility and must be treated as a separate transport mode.

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

- Python 3.10 or newer
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

## DMP-C operations

The client gateway currently exposes these authenticated operations over its WebSocket session:

- `PING` and `STATUS` for session and node status;
- `REGISTER_INBOUND_LOCATOR` and `UNREGISTER_INBOUND_LOCATOR`;
- `START_PROBE` for opaque route discovery;
- `SUBMIT_ENVELOPE` for encrypted envelope submission;
- `PULL` for mailbox retrieval;
- `ACK` for confirmed delivery acknowledgement.

The mesh packet carries an opaque route value and encrypted envelope. The node does not need the message plaintext or a public recipient ID to forward the packet. Persistent routing state is stored under node-local blinded aliases.

## Mailbox behavior

A destination node can retain an encrypted envelope when the destination PWA is offline. The client later performs `PULL`, verifies and decrypts the envelope locally, and sends `ACK`. A `PULL` operation alone is not a delivery acknowledgement.

## Testing

Run the Python tests from `D-MASH/client` with the project dependencies installed:

```bash
python -m unittest discover -s tests -v
```

The transport tests cover opaque locators, authenticated gateway behavior, mailbox retention until acknowledgement, shortest-route candidate selection, invalid signatures, and packet metadata invariants.

For a local mesh stress run:

```bash
python D-MASH/stress_test.py
```

A passing unit or synthetic integration test does not replace browser acceptance. End-to-end acceptance must use two real PWA sessions, separate entry nodes, a paired route, and instrumentation proving that the compatibility relay was not called.

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
