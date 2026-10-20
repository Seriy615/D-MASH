# D-MASH `.38` deployed PRIVATE UI acceptance

Date: 20 October 2026 UTC  
Product SHA: `51b35ff2de810af5ccdf9ebac0839b812f1de38c`  
Target: EMS serving `messenger.d-mash.ru` and `proxy.d-mash.ru`

The exact commit was pushed fast-forward to `transport-v3` and deployed using
that commit's `tools/dmash-deploy-ems`. The deploy completed, the Node service
was active, and rollback backups were created:

- PWA: `/srv/messenger.d-mash.ru/backups/deploy-wrapper-20261020T025734Z`
- Node backend: `/opt/dmash-node/deploy-backups/backend-20261020T025734Z`
- Node frontend: `/opt/dmash-node/deploy-backups/frontend-20261020T025734Z`

Read-only source verification checked **331 PWA/backend files**, with zero
missing or changed files. Public HTTPS release and page report
`transport-v3-node-preparation-20261020.38`. Fresh Chromium contexts controlled
`https://messenger.d-mash.ru/not_messenger/sw.js` and only held
`dmash-static-transport-v3-node-preparation-20261020.38`.

The production browser run used two new synthetic Accounts and the real
configured transport. It did not use a source overlay. All **14/14 visible
steps passed**: root/Account setup, Node connect, signed PRIVATE QR create and
copy, peer inspection and request, bilateral key confirmation, text delivery in
both directions, Account logout preserving Node, and reload preserving the
same identity and chat history. All 1,447 captured application source responses
matched the exact candidate. Playwright exposed empty bodies for some
service-worker-served responses, so 216 such response hashes were completed
from the active Cache API; no mismatches remained. A separate read-only cache
check compared 182 cached PWA files against the candidate, all exact. Page error
count was zero.

The initial deployed-run report is preserved as a failed harness result because
its response-body-only capture did not handle service-worker cache responses;
all user-visible steps in that run had passed. The corrected repeat passed the
full scoped gate. Protected raw reports and synthetic browser snapshots remain
outside Git at `/tmp/dmash-deploy-qa/`; they are not production profiles or
backups.

This gate does not accept public routes, call/video, voice/circle, file transfer,
physical Android, the full N4 fault matrix, or the full N0–N8 and compatible
A–M/E6 plan. Full unit tests were not reproducible in the transient checkout in
this session because Python and Node test dependencies were absent; the prior
candidate run had 293 Python and 11 Origin suites pass and all JavaScript test
files pass individually on Node 24.19.0. The attempted fresh aggregate run's
failures were missing test packages (`fake-indexeddb` and Python requirements),
not observed product assertions.
