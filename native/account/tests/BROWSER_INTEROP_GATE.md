# Private browser/native interoperability gate

Status: **AUTHOR BROWSER API INTEROP PASS** in both offer directions, using
immutable `private-browser-interop-candidate01` (manifest SHA256
`6e96b8e1a2a82025ebc52a0a72fc085fdfa5ef6a671464fe9c031001ba463ef9`).
Default native offer: terminal67599, 29 forwards. Reverse browser offer:
terminal62742, 42 forwards. Both prove actual signed pairing, original Kyber
WASM/native E2EE, bilateral exact history2 and browser Account relogin/history.
Root independently verified source/runtime hashes and then repeated the default
direction: terminal53677 PASS,26forwards/history2/relogin. Exact evidence is
[recorded separately](../../../docs/native/2026-10-20/root-browser-native-interop.json).
Ordinary UI actions remain **NOT RUN**. Schedule only after the orchestrator
releases the single mesh slot; preserve the original owning profiles and pins.

`private_browser_interop.cjs` runs a real Chromium Worker Node and original
`Core.boot`/IndexedDB/Argon2d/Kyber WASM. Its only presentation stub is
`Core.launchWorkspace`; this is an API component gate and cannot substitute for
ordinary UI clicks. Native setup uses normal fresh Root/Account/Node APIs and
private stdin/stdout pipes through `private_browser_interop_server.py`.
The helper does not offer a network credential API. It retains its synthetic
owning profile, browser store and private diagnostic files with owner-only
permissions. Neither endpoint receives the other's Account private keys.

The fixture requires the same installed Node24, Python test requirements,
Playwright/Chromium and permanent Qt/OpenSSL runtime as the other native gates.
Set `DMASH_PYTHON` explicitly to a Python3.12 environment with requirements-test.txt.
`NODE_PATH` points at the already installed test dependencies; `DMASH_CHROME`
optionally selects the pinned Chromium executable. If Playwright is installed
outside `NODE_PATH`, set `DMASH_PLAYWRIGHT_MODULE` to its absolute package path;
the fake-IndexedDB test dependency prefix alone does not contain Playwright.

```sh
DMASH_PYTHON=/home/jcode/.cache/dmash-tools/python-s03-20261020/bin/python \
DMASH_PLAYWRIGHT_MODULE=/home/jcode/.npm/_npx/31e32ef8478fbf80/node_modules/playwright \
DMASH_CHROME=/home/jcode/.cache/ms-playwright/chromium-1248/chrome-linux64/chrome \
/home/jcode/.cache/dmash-tools/node-v24.19.0-linux-x64/bin/node \
native/account/tests/private_browser_interop.cjs \
<immutable-credential-host> <immutable-node-host> <private-cache-directory>
```

Default direction: native creates a signed offer targeted at the browser's real
Account; browser imports/requests it. `DMASH_BROWSER_OFFERS=1` reverses the offer
direction through the same original signed protocol. Run each as a separately
scheduled fresh test rather than concurrent PoW workloads.

Acceptance assertions include default22 admission, no injected contacts/routes,
original directed REQUEST/ACCEPT/CONFIRM, genuine journal prepare/commit/activate,
real native/browser E2EE, one text in each direction, exact two-row histories and
browser Account relogin/rehydration with retained identity/history. The author evidence files under `native/tests/evidence/` record exact source,
binaries, browser/dependency hashes, all48 served JS/WASM hashes and limits.
The component page registers zero service workers and does not load the PWA
release loader. Its archived source metadata release44 is not a claim about the
current PWA page/SW; all48 actually served modules also matched shared3a72492.

The same canonical private runtime/control modules run in both environments.
Native injects its bounded SQLite bootstrap backend and real Account-owned KEM;
browser defaults remain original IndexedDB and original WASM. Public neutral
intake requires its separate runtime/API and is not covered by this gate.
Configured loopback WS transport does not prove NAT, self-organization, deployed
behavior or ordinary client controls. Mesh custody ACKs are unchanged.
