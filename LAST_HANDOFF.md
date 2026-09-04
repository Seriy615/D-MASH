# Handoff — D-MASH Routing / Device Architecture

## Последние commits

```text
f6e2e12 feat: persist verified gateway registrations
5274256 feat: advertise public routes on device unlock and reissue
e79d880 fix: clear calculator state after device unlock
d6f96d8 feat: add durable blind DNSS registration registry
3d70528 fix: reset calculator before account selection
70dddd9 feat: expose authenticated DNSS and entry grant registration
```

Ранее в этой ветке также были закоммичены:

```text
1375c5c — ROUTE_STATUS перед DATA; запрет blind forwarding неизвестного маршрута
5dbda4a — ROUTE_PROBE_V2, metric/hop_limit=15, NCRH, candidate expiry
9298337 — разделение Account Logout и полного Device Lock
8343872 — Node acceptance lifecycle test
f662e23 — device-scoped DeviceRoutes, RouteCertificateV1, encrypted route keys, fallback current/previous
a56a8d6 — gateway acceptance ROUTE_STATUS/START_PROBE
b463b1e — canonical #/node/... и #/c/... deep links
380dbb9 / 5fc194d — encrypted Quick Name Registry и UI
9de4264 / 638ecf8 — DNSS, NodeID-bound EntryGrant, resource PoW primitives
2216a34 — encrypted pending contact store + CONTACT_REQUEST_V1 / CONTACT_ACCEPT_V1
a645520 — lifecycle integration public routes и pending contacts
```

---

## Что реализовано и подтверждено

### 1. Gateway routing

В `client/backend/client_gateway.py`:

- Device-authenticated DMP-C v2 gateway.
- `ROUTE_STATUS` перед data-plane dispatch.
- `START_PROBE` с отдельными `metric` и `hop_limit`, clamped до `1..15`.
- Неизвестный route не отправляется blind forwarding.
- `REGISTER_DNSS` и `REGISTER_ENTRY_GRANT` добавлены в capability surface только для routing-capable state.
- DNSS принимается в hex/base64url 128-bit форме.
- Gateway возвращает только blind DNSS handle, не raw DNSS.
- EntryGrant проверяется на canonical structure, подпись, expiry и привязку к текущему NodeID.

### 2. Durable DNSS / EntryGrant registry

Commit: **`d6f96d8`**.

Добавлен `client/backend/registration_registry.py`.

Свойства:

- SQLite registry для DNSS registration.
- В persistent DB хранится только node-scoped blind DNSS hash, NodeID, route metadata, EntryGrant signature, expiry и registration time.
- Raw DNSS не сохраняется.
- DNSS должен быть ровно 16 bytes.
- DNSS blind hash устойчив при restart одной Node и различается между Nodes.
- Registry не открывается под другим NodeID.
- EntryGrant проверяется до persist.
- Есть expiry lookup и `purge_expired`.

Тесты в `client/tests/test_registration_registry.py` проверяют persistence после reopen SQLite, отсутствие raw DNSS в SQLite, node scope, expired registration, reject чужого Node grant и reject cross-node DB open.

### 3. Gateway → durable registry seam

Commit: **`f6e2e12`**.

Gateway теперь использует injectable `registration_registry_factory`.

Поведение:

- Если factory отсутствует, registration capabilities не рекламируются: **fail closed**.
- DNSS сначала остаётся только in-memory в authenticated session.
- Persist происходит лишь когда в одной session есть корректный DNSS и корректный Node-bound EntryGrant.
- При последовательности DNSS → grant registry сохраняет запись.
- При auth failure cleanup не обращается к неинициализированному registry.
- Gateway закрывает session-created registry в `finally`.

Есть gateway acceptance, которая проверяет:

```text
REGISTER_DNSS
→ REGISTER_ENTRY_GRANT
→ reopen registry
→ lookup DNSS
→ persisted grant matches canonical wire representation
→ raw DNSS bytes absent from database file
```

**Важно:** factory seam интегрирован и протестирован, но production lifecycle wiring пока находится в незакоммиченном состоянии, см. ниже.

### 4. Device-scoped public route lifecycle

Commit: **`5274256`**.

PWA:

- `Core.unlockDevice()` вызывает `NodeManager.onDeviceUnlocked()`.
- После Device Unlock подключаются eligible configured nodes и активные public DeviceRoutes probe’ятся.
- Account login для public routes не нужен.
- `NodeManager.onDeviceUnlocked()` не добавляет periodic refresh timer.
- `DeviceRoutes.issue()` emits `ROUTE_ISSUED` для первой route и `ROUTE_REISSUED` для последующих.
- Events несут только public route view.

Проверено:

```text
Device routes acceptance: all assertions passed
Device route connection lifecycle: all assertions passed
Core lifecycle acceptance: all assertions passed
```

Не сделано: model/account store для private routes, private route probes на Account login, re-probe private routes только активного Account после reconnect и Account A/B isolation test.

### 5. Calculator stale-state fix

Commits:

```text
3d70528 — regression test
e79d880 — production implementation
```

В `ui_logic.js`:

- добавлен `ui.resetCalculator()`;
- он сбрасывает `curr = "0"`, `hist = ""`, `op = null`;
- после `Core.unlockDevice()` и до account selector вызывается:

```js
this.resetCalculator();
await this.show_gate();
```

Есть executable lifecycle regression, моделирующий async unlock и проверяющий, что selector получает нейтральное состояние calculator.

### 6. Остальные ранее сделанные PWA slices

Реализованы и тестируются Node harness-ами:

- разделение `ACCOUNT_LOGOUT` и full `DEVICE_LOCK`;
- DeviceRoot encrypted storage;
- DeviceRoutes: random signing/box material, encrypted private material, RouteCertificate, current/previous bounded fallback и local account associations;
- canonical deep links: `#/node/<descriptor>` и `#/c/<descriptor>`;
- pending deep links в safe state;
- encrypted Quick Name Registry;
- encrypted pending contact request store;
- strict `CONTACT_REQUEST_V1` / `CONTACT_ACCEPT_V1` payload serialization / validation;
- UI primitives для pending contacts и Quick Names.

---

## Последние пройденные проверки

### Backend / Python

Ранее полностью прошли:

```text
73 tests in 6.744s
OK
```

Focused gateway + registry:

```text
Ran 18 tests in 0.056s
OK
```

Включает `tests.test_client_gateway` и `tests.test_registration_registry`.

### PWA Node executable tests

Все 11 test files прошли:

```text
contact_payloads.test.js
core_lifecycle_acceptance.test.js
device_root.test.js
device_route_lifecycle.test.js
device_routes.test.js
dmash_links.test.js
node_link_integration.test.js
pending_contact_requests.test.js
pending_contact_ui.test.js
quick_name_registry.test.js
quick_name_ui.test.js
```

### Static checks

До последнего незакоммиченного core work:

```text
node --check — passed
py_compile — passed for checked modules
git diff --check — passed
```

---

## Критические незавершённые требования

Не заявлять их как completed.

### A. Production lifecycle installation для registry factory

Незакоммиченные изменения появились в:

```text
D-MASH/client/backend/core.py
D-MASH/client/tests/test_registration_lifecycle.py
```

Цель:

- При startup/lifespan установить `client_gateway.registration_registry_factory`.
- Использовать отдельный путь `DMASH_REGISTRATION_REGISTRY_PATH`, default: `registration_registry.db`.
- Не использовать `system.db`, т.к. он async DB и смешивание с synchronous SQLite connection unsafe.
- На shutdown сбросить factory в `None`, чтобы gateway снова fail-closed.

Текущий незакоммиченный `core.py` уже пытается:

```python
import client_gateway
from registration_registry import RegistrationRegistry
...
def wire_registration_registry():
    ...
    client_gateway.registration_registry_factory = factory
```

и вызывает это после NodeCrypto / database init.

### B. Import compatibility bug в new registry

Во время проверки lifecycle test обнаружен runtime import issue:

- `core.py`, когда импортируется top-level с `PYTHONPATH=backend`, импортирует `registration_registry` top-level;
- `registration_registry.py` содержал только relative imports:

```python
from .dnss import node_blind_hash
from .entry_grant import EntryGrantV1
```

Это ломает top-level runtime import.

Уже внесён **незакоммиченный** minimal compatibility patch:

```python
try:
    from dnss import node_blind_hash
    from entry_grant import EntryGrantV1
except ModuleNotFoundError:
    from .dnss import node_blind_hash
    from .entry_grant import EntryGrantV1
```

Нужно продолжить с:

```bash
cd D-MASH/client
PYTHONPATH="$PWD:$PWD/backend" ../../.venv-m1/bin/python \
  -m unittest tests.test_registration_lifecycle -v
../../.venv-m1/bin/python -m py_compile backend/core.py backend/registration_registry.py
```

После PASS:

```bash
cd D-MASH
git diff --check
git add -p client/backend/core.py client/backend/registration_registry.py client/tests/test_registration_lifecycle.py
git commit -m 'feat: wire durable registration registry at node startup'
```

Сначала убедиться, что `core.py` diff не захватывает параллельные не относящиеся к этому изменения. В `core.py` уже есть unrelated dirty modifications, например `OriginNotificationClient.from_env(state.node_crypto)`, поэтому commit следует делать только hunk-level / через `git add -p`.

### C. Resource PoW enforcement

`resource_pow.py` пока primitive only.

Нужно подключить PoW для:

- new DNSS registration;
- new EntryGrant activation.

Не нужен PoW для DATA, ACK, PULL, reconnect probe и повторной валидной registration.

Нужны:

- node-bound material;
- resource type;
- NodeID;
- device transport pubkey;
- DNSS or RouteID;
- nonce;
- difficulty bits;
- expiry/replay policy;
- tests: Node A proof rejected by Node B, replay rejected, valid proof accepted only once или только в определённом validity window.

Не включать PoW в existing data plane.

### D. Contact transport отсутствует

Есть только PWA-local primitives.

Пока **нет**:

- отправки encrypted `CONTACT_REQUEST_V1` через `SUBMIT_ENVELOPE`;
- приёма/dispatch из `PULL`;
- decrypt to destination RouteBox;
- pending inbox receive integration;
- dedupe by request_id;
- temporary reply-route outbound state;
- `CONTACT_ACCEPT_V1` transport;
- account handshake после accept;
- e2e two-device/multi-node test.

По аудиту `CONTACT_REQUEST_V1` и `CONTACT_ACCEPT_V1` нигде в Python gateway/backend не используются.

### E. Device security / settings незавершены

По аудиту:

- selector не имеет device-level Global Settings `⚙`;
- global settings сейчас не полностью отделены от Account settings;
- legacy `sys_m` SHA-256 verifier остаётся в `localStorage`;
- biometric path всё ещё account-level;
- есть unsafe localStorage/software fallback semantics;
- нет device-level WebAuthn PRF wrapping;
- нет configurable 3-second calculator long-press trigger;
- нет biometric acceptance tests.

### F. Privacy qualification

DMP-C transport/database path имеет blind aliases / encrypted storage, но нельзя утверждать полную node DB privacy:

- legacy `/api/send` и legacy P2P paths могут JSON-persist raw legacy route IDs/packets;
- legacy raw paths надо disable/migrate/remove или отделённо документировать до успешной node DB privacy inspection;
- нет real multi-process two-node integration test;
- нет real browser acceptance.

---

## Browser acceptance

Firefox bridge в этой сессии недоступен:

```text
Firefox is not running, so the browser bridge is not responding.
```

Попытка `browser.open` также не смогла запустить/подключить Firefox.

Поэтому browser/Playwright two-browser contact flow **не выполнен**; не заявлять его passed. PWA lifecycle проверялся dependency-free Node harness.

---

## Working tree: важные предосторожности

В дереве много pre-existing / parallel dirty changes. Не делать широких add/commit.

В частности до последнего шага dirty были:

```text
.env.example
D-MASH PWA/not_messenger/js/device_root.js
D-MASH PWA/not_messenger/js/release.js
D-MASH PWA/not_messenger/js/storage.js
D-MASH PWA/not_messenger/sw.js
client/backend/core.py
client/backend/main.py
client/backend/notification.py
client/tests/test_notification.py
README.md
install-node.sh
origin/*
```

Untracked:

```text
CURRENT_HANDOFF.md
client/backend/entry_grant.py
client/backend/peer_admin.py
client/backend/resource_pow.py
client/tests/test_isolated_crypto_primitives.py
ROUTING_UPDATE.md
diagnose.mjs
```

Некоторые untracked файлы — часть предыдущих routing primitives и уже могут быть logically required imports. Не добавлять их без review и test coverage.

---

## Todo состояние

Completed:

- gateway DNSS/EntryGrant validation;
- durable blind registry;
- gateway registry seam;
- public route event-driven lifecycle;
- calculator neutral-state reset;
- backend/PWA executable suites;
- architecture/privacy audit.

Pending:

1. lifecycle-owned registry factory + runtime import compatibility;
2. PoW enforcement;
3. private route lifecycle;
4. real contact transport;
5. device-level settings/security/WebAuthn;
6. real browser acceptance.
