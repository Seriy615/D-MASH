# D-MASH — актуальный хендофф для нового сервера

Дата среза: **8 октября 2026 года, Europe/Moscow**. Этот файл — единственная
текущая сводка состояния. Старые checkpoints сохранены в
[docs/archive/2026-10-08](docs/archive/2026-10-08/). Они не задают текущий план.

## 1. Что требуется в итоге

**Решение пользователя уже принято: устройство работает как полноценная Node.**
В новой сетевой модели есть одна роль `NODE`; браузер принимает и пересылает
чужие пакеты, участвует в тех же auth/routing/queue алгоритмах, что и Python Node.
Account отвечает за контакты, E2EE и свою историю; transit не обращается к
активному Account. Account logout и полная локальная блокировка различаются:
первое не должно выключать разблокированную Node, второе закрывает runtime/keys.
`DeviceRoot` может оставаться названием локального root secret; это не отдельная
сетевая роль и не основание сохранять `ROLE_DEVICE` в итоговом протоколе.

Устройство не должно объявлять себя особым клиентом/endpoint. Одно название
`NODE` ещё не доказывает сокрытие начала/конца маршрута: нужны проверки wire,
control plane, timing, resource access и границ browser/media fingerprinting.

Полное задание: [D-MASH_Codex_Development_Plan.md](D-MASH_Codex_Development_Plan.md),
**N0–N8 и совместимые A–M/E6**. Не сокращать его до исправлений в текущем v3.
Не останавливать разработку на локальном PASS. DHT не входит в текущий scope.
Дополнительные указания пользователя: NCRH привязан к маршруту; случайный hop
TTL для Probe; route-carried DUMMY/cover с корректным terminal discard; Probe
может прийти до импорта contribution/QR; самостоятельно проверять UI контактов.
Текущее поручение пользователя — автономно завершить N0–N8 и совместимые A–M/E6
на Forge с делегированной реализацией и полной браузерной приёмкой. Постоянная
цель активна в текущем Codex chat; полный DONE не достигнут.
Пользователь назначил `forge-vps` для синхронизации source/context. Проверить
существующий checkout и работать оттуда; итоговые path/branch/SHA фиксируются
в FORGE_SYNC.md после операции. Перенос production runtime/доменов/секретов
не следует из синхронизации репозитория. EMS не является новым dev-хостом.

**Forge source sync выполнен:** checkout `/home/jcode/D-MASH`, user `codex`,
ветка `transport-v3`. Базовый handoff `c14b0b07f9229988f8bbb83f88b3b73504784272`
проверен по HEAD/tree и file hashes; локальный прежний context сохранён в
protected off-checkout backup. Итог и GitHub SSH limitation —
[FORGE_SYNC.md](FORGE_SYNC.md). Origin fetch теперь HTTPS, write auth требует
настройки; production runtime/данные не переносились. Последний documentation
commit также доставляется на Forge, его полный SHA получить из Git.

## 2. Текущий Forge checkpoint и опубликованный baseline

На 8 октября 2026 работа идёт на `forgeai.isgood.host`, user `codex`,
`/home/jcode/D-MASH`, `transport-v3`. Постоянная цель активна; N3/N4 и полный
browser-first inventory ещё не завершены. Реализация делегирована агентам;
лид независимо проверяет интеграцию и опубликованный UI.

Текущий source checkpoint **`b9e405f70a8d6fed6578907d51992f4419e7ee76`**:
managed Node owner proof+PREPARED/ACTIVE/RETIRED, Account four-row journal,
private commit receipts и fixed receipt router. Лид independently проверил реальный
Worker+IndexedDB same-Host A→B→A:25checks PASS, loaded source hashes совпали.
Exact detached suite280backend+11Origin+76JS PASS. Harnessfix7ce0b87
добавляет missing Worker import и CDP self-close: exact real Worker transit PASS
после initial fixtureFAIL; CDP ownership retest69261 PASS (self.close, не OS kill). Pushed7ce0b87, Forge HEAD=origin проверены. Ordinary adapter/UI ещё не подключён; authenticated replacement/renewal,
bootstrap/public neutral exchange и mailbox migration ещё не готовы.
Предыдущий pushed checkpoint0ad1767 включает source a70ebb9 exact280backend+
11Origin+74JS PASS и .26 pending controls4PASS. Новая разработка bootstrap/adapter
остаётся вне текущего checkpoint; N4 агент работает в отдельном worktree.

Текущий runtime commit **`3c513601ef3990b6514e247d879324b7b72da494`**, release
**`transport-v3-node-preparation-20261008.26`**, pushed и deployed на EMS.
Exact-source проверка: **214 checked, missing=[], changed=[]**. Обновлены PWA
и только backend `route_discovery_v4.py`, зависимости/config не менялись.
До замены backend Node остановлен, согласованный protected runtime snapshot:
`/root/dmash-runtime-backups/release26-20261008T004030Z` (6 SQLite quick_check PASS).
После restart все4 identity/key files побайтно равны backup. Static PWA backup:
`/srv/messenger.d-mash.ru/backups/manual-rollback-20261008T004036Z`.
Секреты/snapshot вне Git; production на Forge не переносился. Scoped deploy
wrapper сохранён `/root/deploy-release26.sh`; existing get_commit.sh использован
для PWA (его regex release сообщает unknown, browser/SW проверяются отдельно).

.26 сохраняет PUBLIC request до сетевого PoW, сразу показывает честную очередь,
имеет подготовку/cancel и guards root/Account/same-slot relogin. Shared JS/Python
DiscoveryCertificate/reply теперь отвергает small-order/noncanonical Ed/X keys
и R/S malleability; прежняя identity-point owner forgery воспроизведена лидом.
Это не full prime-subgroup/PQ/security DONE. Inactive pairing codec и root Node
coordinator добавлены, но **ordinary Account path всё ещё v3**. .25 wrong-key,
scanner/navigation/catalog fixes сохранены. Полный N3 cutover не реализован.

Exact .26 isolated worktree `/tmp/dmash-release26-3c51360`:
**266 backend +11 Origin +72 JS suites PASS**, real Python N1→Chrome Worker B→N2
transit/discovery/Inbox/root-lock PASS; независимый fresh PUBLIC Request/Accept/
Confirm/key exchange/messages both directions PASS, все loaded assets exactSHA,
source-overlay SW BLOCKED. Это не deployed SW acceptance.
Deployed .26 independent PUBLIC run завершён **13/13 PASS**, page/SW обеих
profiles.26, **135 loaded assets match exactSHA**, errors=[], exit0. Readiness
CDP observation может влиять на timing, это не latency acceptance. После PASS
тот же retained browser (handle11809/CDP9447) штатно закрыт SIGUSR2; больше ждать
его не нужно. Evidence/limits — `docs/evidence/2026-10-08/qa-release26-manifest.json`.

.25 baseline wrong-key/correctretry/isolation6PASS, controls9PASS, реальный
.24→.25 upgrade сохранил identity/history. Предыдущие PUBLIC runs бывали timeout
до delivery; отдельная readiness diagnosis открыта, source .26 полный PASS не
закрывает intermittent сценарий. Account deletion/video toggle/filepolicy/N4
остаются открыты. Next inactive modules (binding receipts/journal/mailbox/profile)
в рабочем дереве не входят в deployed3c51360; проверять отдельным checkpoint.

Среда: Python3.12.14 `.venv`, Node24.19.0 (официальный checksum),
Playwright1.64.0/Chromium156.0.8078.4 вне checkout. Свежий .24 baseline:
24 calculator и27 Account/media/master-rewrap checks PASS; Node Inbox/ownership,
real loopback Worker N1→B→N2 transit и deployed pinned WSS auth/reconnect PASS.
Это не ordinary UI v4 приёмка. Ведомость и открытые баги: [BROWSER_QA.md](BROWSER_QA.md).
Account deletion сохраняет записи общего vault; video call toggle и attachment
policy/readiness остаются открыты. N3 pairing/binding/store codecs и root coordinator уже зафиксированы; агенты
интегрируют managed ownership/Account journal и same-Host Account switching. Cutover не реализован;
сильная N4 диагностика выявила recovery gaps поверх зелёного старого H1/H2/H3.

Forge SSH GitHub push недоступен; HTTPS fetch работает. Публикация exact commits
через incremental bundle и отдельный temporary bare EMS publisher от codex,
обычный fast-forward push, затем Forge origin fetch. Production checkout и
секреты не включались в bundle. Подробности — [FORGE_SYNC.md](FORGE_SYNC.md).

### Опубликованный runtime baseline (историческая приёмка до текущего аудита)

| Параметр | Значение |
|---|---|
| Репозиторий | https://github.com/Seriy615/D-MASH |
| Ветка разработки | `transport-v3` — имя историческое, здесь также лежит v4 |
| Последний runtime commit | `ed200730dab2e64fc8446e344ce54dbd37cfeec5` |
| Опубликованный release | `transport-v3-recorded-fragments-20261008.24` |
| PWA | https://messenger.d-mash.ru/not_messenger/ |
| v3 gateway, временный migration path | `wss://stage-api-ems.d-mash.ru/dmp-c/v3` |
| Native unified Node endpoint | `wss://stage-api-ems.d-mash.ru/mesh/v4` |
| Signaling | `wss://stage-api-ems.d-mash.ru/signal/v1` |
| EMS source checkout | `/home/jcode/D-MASH`, Git owner `codex` |
| EMS backend / frontend | `/opt/dmash-node/backend` / `/opt/dmash-node/frontend` |
| EMS PWA root | `/srv/messenger.d-mash.ru/public_html/not_messenger` |

Runtime SHA выше committed, pushed и deployed; EMS checkout синхронизирован через
его существующий `tools/get_commit.sh FULL_SHA`. Exact verifier дважды проверил
**205 файлов: missing=[], changed=[]**. `dmash-node`, `dmash-sturn`, `coturn`:
active/running, NRestarts=0. Последние PWA-изменения не требовали restart backend.
Коммит документации хендоффа будет новее runtime SHA; его брать из `git rev-parse
HEAD`. Это не отдельный новый runtime release и не доказательство нового deploy.

Сохранённая регрессия предыдущего сеанса: **264 backend-теста + 11 Origin-тестов + 67 JS-наборов PASS**.
Реальный Chrome на опубликованной `.24`: page и active SW одной версии; новый
публичный контакт Request/Accept/Confirm; намеренная потеря первого запроса и
автономный retry; видимые waiting cards и реальные клики по чатам; initial
exchange; сообщения в обе стороны; ratchet epochs 1/2; delayed old epoch;
disconnect/reconnect; голосовая и видеозапись; forced TURN звонок; control
retirement. Процесс завершился exit 0, больше ждать session 1487 не нужно.

Голосовая запись: **17526 encoded characters**, видеокружок: **256394**.
В каждом случае один receiving history row, Blob playback продвигается,
финальный receipt удаляет активную операцию из outbox. Микрофон/камера
синтетические, transport, crypto, браузерные APIs и EMS настоящие. Это не
проверка физического телефона, Safari или видеозвонка. До initial exchange
были `Route unavailable` и SOS/retry; eventual PASS не означает немедленную
готовность маршрута. Эту задержку нужно отдельно диагностировать и улучшить.

Доказательства перенесены из локального `/tmp` в
[docs/evidence/2026-10-08](docs/evidence/2026-10-08/): full tests, deployed browser,
exact source, deploy, service state, EMS inventory и локальный RTC.
[manifest.json](docs/evidence/2026-10-08/manifest.json) содержит hash/size каждого
лога и exit codes. Логи не заменяют независимый повтор на новом сервере.

## 3. Что действительно реализовано

### Unified Node foundation — есть, UI cutover ещё нет

В JS/Python есть v4 channel/auth/registration/admission/relationships/routing;
native `/mesh/v4` реально включён на EMS. Browser Worker умеет peering/transit,
label replacement, bounded queues, discovery и local delivery. Есть
DeviceRoot-bound persisted Node identity, directional relationships, свежая
session binding, exclusive browser ownership, API version checks и cancellation.
Полная root lock закрывает Worker. Секреты routing/local recipient отделены
от Account E2EE keys; чужой transit не должен требовать Account login.

Исторические записи сообщают PASS реального Python N1 → Chrome B → Python N2
без прямого обхода, позднего local binding, root lock, identity persistence,
cover discard, UI heartbeat, public Worker reconnect и native N1→EMS→N2.
**Сырые старые v4 `/tmp`-логи на текущей машине уже отсутствуют.** Это историческая
приёмка, не свежий DEPLOYED PASS на `.24`; scripts и unit tests сохранены.
На новом сервере повторить эти browser/network сценарии до дальнейшего cutover.

Account adapters `account_node_transport_v4.js` / `account_node_inbox_v4.js`
уже умеют explicit host attachment, per-Account guards, authenticated peer mapping
и bounded Inbox pagination (32 records, до 4 pages/pass). В `.24` Core явно
передаёт свой lexical Storage adapter: `window.Storage` в настоящем браузере —
DOM constructor и не является vault. VM fixtures не должны скрывать этот баг.
Ручной attach в controlled tests не заменяет ordinary UI bootstrap.

Ключевые модули PWA: `node_runtime_host_v4.js`, `node_runtime_worker_v4.js`,
`node_channel_v4.js`, `node_socket_v4.js`, `node_registration_v4.js`,
`node_admission_v4.js`, `node_relationships_v4.js`, `node_routing_v4.js`,
`node_local_delivery_v4.js`, `node_inbox_v4.js`, `recipient_payload_v4.js`.
Backend counterparts — в `D-MASH/client/backend/`; контракт в
[TRANSPORT_V4.md](TRANSPORT_V4.md) и
[TRANSPORT_V4_DISCOVERY.md](TRANSPORT_V4_DISCOVERY.md).

**Главная незавершённость:** обычный PWA bootstrap не запускает/не подключает
NodeRuntimeHostV4 для контактов и переписки. `Core.attachNodeTransportV4(host)`
и `attachNodeInboxV4(host)` существуют, но обычный вход их не вызывает.
`Core._ensureAutomaticMeshRoute` всё ещё устанавливает `PrivateRoutesV3` через
`NodeManager.installPrivateRouteV3`. Большинство live Account проверок выше
прошло по этому migration path. Это незаконченный переход к уже принятой Node
архитектуре, а не допустимая альтернативная конечная Device-модель.

### NCRH, Probe, cover

В v4 route NCRH: HMAC-SHA256 с независимым секретным BaseNCRH и доменом
`D-MASH|NCRH|V4|ROUTE\0` над 32 декодированными байтами RouteID. Не AccountID и
не публичный NodeID. Транзит использует отдельный HOP domain; BaseNCRH не
передаётся. Общий device root advertisement из старой схемы в v4 не переносить.

Новый Probe выбирает CSPRNG hop TTL в диапазоне 4–15; копии сохраняют budget,
каждый receiver расходует один hop. Без clear initial TTL/path/absolute metric.
Ретраи bounded/event-driven, не global periodic refresh. У верхнего TTL остаётся
distance inference; случайность не доказывает анонимность.

Opaque cover/DUMMY идёт по существующим grants обычным DATA/offer framing,
без DUMMY wire flag, с quota и уступкой реальной очереди. Terminal invalid MAC
при известных recipient keys может быть discard, missing keys — deferred.
Есть opt-in scheduler; production generator не включён. Наличие этой функции
не является полноценной защитой от traffic analysis.

### Контакты, initial handshake и ratchet

Исправления `.17–.22`: retained attempt IDs/capsules; детерминированный winner
при встречном initial; Kyber final держится до authenticated Account key
confirmation, а не Node acceptance; повторы confirmation не попадают в history;
concurrent initial encrypt creation объединяется по Account/peer; guards после
await; failure одного contact state не должен прерывать unrelated states.

Для публичного первого запроса exact encrypted intent сохраняется до lookup/
submit. Retry 5 s → 5 min, максимум 256 attempts / 24 h, Account owner закреплён.
Accept останавливает initial retry; Accept/Confirm send=false не establishment.
Показываются pending/outgoing/accepted cards, peer после confirm появляется в
sidebar, чат открывается реальным click. Рекламируется reply route конкретного
запроса, не запускается глобальный refresh всех routes.

Private contact deletion использует подписанный `UNREGISTER_ROUTE`, чистит
локальные peer/route/outbound/policy/pending mappings, допускает повторный импорт.
Warning при неподтверждённой remote cleanup остаётся правдивым; offline Entry
revocation/retry и v4 equivalents требуют дальнейшей работы.

**Не закрыто N4:** полная pending/ESTABLISHED state machine и transcript binding;
replay-safe recovery после односторонней потери state; exhaustive collision,
loss/reorder/restart/crash matrix. Исторический H2 PASS означает ответ на новый
init после one-sided loss, не доказательство полной защищённой recovery.
Работающий ratchet epoch не доказывает PCS/PFS/PQ.

### Вход, recorded media, звонки

`.21` registry: IDB transaction создаётся после async alias/encryption; legacy
migration шифрует до transaction, атомарно пишет accounts/marker, удаляет old
rows только после успеха; ошибка сохраняет старое и допускает retry. Есть real
Chrome delayed WebCrypto/migration/CRUD tests. Исходный `IDBObjectStore.get:
transaction inactive` исправлен. Это не общий аудит всех vault transactions.

`.20` playback: корректная граница `;base64,` для MIME с `codecs=vp8,opus`, Blob
player, bounded error/retry/download. Panic gesture подавляется при recording/
scanner, stale samples сбрасываются; явная настройка panic сохраняется. Пользователь
сообщал вылет «на калькулятор»; один воспроизведённый trigger исправлен, все причины
такого поведения на реальном телефоне не проверены.

`.24` large notes: `account_recorded_media.js`, authenticated profile
`DMASH_NOTE_FRAGMENTS_V1`, 4096-character slices под существующим Account
ratchet/signature, window 8 до durable peer receipts, один final digest receipt.
Outbox/assembly шифруются локально; стабильные logical IDs, dedupe, restart,
Quota/expiry, unsupported peer fail closed. Верхняя граница — 16 MiB **encoded
DataURL**, не 16 MiB исходного файла; receiver 4 active / 2 per peer, 32 MiB
reserved, 64 ledger entries including tombstones, 24 h retention. Terminal
failure освобождает duplicate source в outbox и отмечает local history FAILED.
Проверены потеря fragment/final receipt, чужой Account, storage failure,
conflicting duplicate, crash intent→local history и receiver history→assembly.
Recorder держит original peer/session; late permission/chat switch останавливает
tracks, Account change подавляет late FileReader send. Размер Node frame не поднят.
Generic file transfer остаётся отдельным consent path. Детали:
[ACCOUNT_RECORDED_MEDIA.md](ACCOUNT_RECORDED_MEDIA.md).

`.23` calls: раньше на запущенной Node не было S-TURN config и `/signal/v1` nginx
proxy. Добавлен отдельный `dmash-sturn`, temporary TURN REST credentials, UI
errors при недоступном service/microphone, timer по actual connected state,
relay-only production ICE, cleanup hangup. `.24` снова доказала actual call UI,
relay candidates обеих сторон и inbound audio RTP. **SDP/ICE signaling сейчас
виден signaling server**; E2EE invitation и DTLS-SRTP не закрывают этот риск.
Video switching, physical phone/mobile networks, broad call/file fault matrix,
ringtone/caller consent и unified v4 invitations ещё не завершены.

### Security / password / локальная история — foundation, не завершённый audit

Legacy public HTTP control login/logout/connect/debug/read/send paths закрыты
до runtime mutation (410 / explicit deny в соответствующих adapters/tests).
Sidecars/identities/DB/env excluded from distribution; private v4 credential
missing не должен превращаться в OPEN fallback. Node password primitives
Argon2id-derived transcript/nonce HMAC, cooldown/session binding/replay checks
есть в JS/Python и покрыты текущими suites. Это password-equivalent Kpwd, не PAKE;
Node policy/provisioning и production failure matrix остаются N6.

Saved Messages/local history password сохранены как Account-local возможности.
Node relationship/Inbox storage шифруется за local root; browser Worker не
защищает от полного same-origin compromise. Master/repair/emergency verifier,
old leaked sidecars, vendor WASM/PQ provenance, runtime backup/restore и полный
compromise model требуют отдельной проверки N5/E6. Не считать ignore-файл,
шифрование локальной DB или passage unit tests законченным security audit.

## 4. Полный остаток N0–N8

| Этап | Статус | Остаток до настоящего DONE |
|---|---|---|
| N0 | PARTIAL | Endpoint/runtime threat model и наблюдаемые различители; миграционные gates; доказательства приватности, а не только общий role |
| N1 | PARTIAL, ядро реализовано | Свежая full interop/production policy матрица, provision/config integration, общий descriptor; закрепить текущие fixtures в CI |
| N2 | PARTIAL, browser transit реализован/исторически проверен | Повторить no-bypass browser transit на текущем SHA; failure/alternative path, fairness/load/loops, local terminal/transit trace comparison |
| N3 | PARTIAL, основной следующий этап | Ordinary UI→Node host; public/private Account/contact mapping; multi-account/locked/public event; durable Node mailbox grants; ownership-preserving existing-state migration |
| N4 | PARTIAL | Full per-peer state machine, replay-safe recovery, stable ordinary outbox IDs/receipts/backoff, quarantine/retry; exhaustive fault/collision/epoch/crash matrix |
| N5 | PARTIAL | Exposure/verifier/dependency/sidecar audit; authenticated storage/mailbox migration; fresh X25519 PCS + verified hybrid PQ suite/provenance; compromise tests/crypto review |
| N6 | PARTIAL | Node resource password policy до/после auth, directory/descriptor/UI wiring, installer password/STURN flags, repeat install/credential change/rollback; минимальные service privileges |
| N7 | PARTIAL | Calls/files/wake/invitations через единую Node; signaling privacy/fingerprint binding; video/mobile, files integrity/resume/cancel/streaming, ringtone/caller policy, truthful statuses |
| N8 | PARTIAL | Вся таблица раздела 13 плана на exact SHA; реальные migration/backup/restore/rollback; CI/vendor/security; итоговая приёмка без подмены узкого PASS полным DONE |

Compatible A/B→N1; C/D→N3 (directional auth и universal mailbox);
E→N3 (local delivery, сетевой Device убирается); F/G→N2/privacy;
H→N6 (password gate для Nodes, не DEVICE-only); I/J/K→N7;
L→N4/N5; M→N8. Эти группы не считаются завершёнными из-за зелёного v3 regression.
E6: Saved Messages и password-protected local history сохранять; отдельный
compromise model, versioned Argon2id/opaque handles/Worker/WASM/storage migration
ещё требуют доказанной реализации. Вложения Saved Messages — отдельный backlog,
не новое обязательное требование. Полный процент выполнения не установлен:
план не завершён, самый большой architectural blocker — N3 cutover/migration.

Приоритетные неисправности/риски после переноса:

1. Долгая готовность private routes после public/private pairing: повторяющиеся
   Route unavailable/SOS, затем eventual success. Снять timeline REGISTER_ROUTE,
   probe/bind/status, expiry/reconnect и initial ownership; не просто увеличить timeout.
2. Existing stale contacts / requests без сохранённого initial ciphertext:
   readable compatibility есть, автоматическая recovery/migration не доказана.
3. Offline revoke locator, sender/recipient lock/restart на реальных vaults,
   encrypted Inbox migration и poisoned-record quarantine/backoff.
4. Recorded-note max quota/tombstone capacity/expiry/cancellation/mobile storage;
   mixed versions, full reorder/crash points и actual v4 delivery. Current unit
   fault storage controlled, не production disk/full-browser crash proof.
5. SDP/ICE confidentiality/authenticated fingerprint binding; capability health
   должна опираться на real relay health, не только env flag/open port.
6. Master verifier/repair/emergency/sys_m paths, old BaseNCRH sidecar history и
   deployed inventory: repository removal не отзывает когда-либо раскрытый secret.
7. В свежем EMS inventory **dmash-node работает User=root**. Новый installer
   должен обеспечить минимальные права с доступом к нужному runtime state.
8. GitHub при последнем push сообщил 7 default-branch dependency advisories
   (3 high, 1 moderate, 3 low); сами advisories не разбирались. Это не готовый
   аудит ветки или bundled WASM. Проверить current vendor inventory/provenance.

## 5. Перенос на новый сервер

Перенос source checkout и перенос работающей production Node — разные операции.
Для новой dev-машины достаточно Git + новая среда; для замены EMS runtime нужны
отдельные protected state/config transfer и приёмка. Пользователь указал forge-vps как target source/context sync. Этот сеанс
синхронизирует checkout; migration production runtime/state остаётся отдельной
операцией.

### Source и среда разработки

Клонировать `transport-v3` с последним handoff commit, зафиксировать `git rev-parse
HEAD` и убедиться, что runtime base `.24` присутствует в ancestry. Не копировать
старую macOS `.venv`, `node_modules`, __pycache__, generated files и локальные
SSH credentials. Python reference: **3.12** (локально 3.12.14), Node.js
**24.19.0**; браузерные scripts требуют Playwright и Chromium/Chrome.

```bash
git clone --branch transport-v3 git@github.com:Seriy615/D-MASH.git
cd D-MASH
git status --short
git rev-parse HEAD
python3.12 -m venv .venv
.venv/bin/python -m pip install -r requirements-test.txt
.venv/bin/python tools/test_all.py
```

Зависимости test runner в requirements-test.txt, backend/Origin requirements;
`tools/vendor/package-lock.json` — vendor build lock. Python test dependencies
не являются полным frozen dependency lock: воспроизводимость нужно усилить.
На Linux задать `DMASH_CHROME` и `DMASH_PLAYWRIGHT_MODULE` по фактически установленным
путям; пути `/Users/afsvu/...` из архивных команд не переносимы. Browser harness
loopback и real WSS должны оставаться отдельными видами evidence.

### Что хранится вне Git и обязательно сохраняется при runtime migration

- Node identity и её sidecars/BaseNCRH; существующие runtime DB, registration /
  peer directory / mailbox / lease state и соответствующие encryption keys.
- `/var/lib/dmash-node-v4`: keys/BaseNCRH/relationships/persistent state; directory
  сейчас 0700. Existing DB без соответствующих keys должна fail closed.
- Host credentials/password equivalents, notification secrets, nginx/TLS,
  systemd units/drop-ins, firewall, service owner/permissions.
- `/etc/dmash-sturn/rest.secret`, `node.env`, `turnserver.conf`, unit; TURN shared
  secret не генерировать заново, если переносится существующая конфигурация.
- Browser Account/root/registry/history/inbox state остаётся на устройстве.
  Git clone не переносит IndexedDB. Смена origin/domain теряет доступ браузера к
  прежнему storage namespace; нужен явный authenticated export/import plan.

SQLite backup должен быть согласованным: корректный backup API/остановка writers,
учесть WAL/SHM. Не копировать только один `.db` из live-changing directory и не
удалять старый ciphertext «для успешного старта». Сначала доказать чтение и owner
proof на новом runtime, затем переводить трафик. Все secrets передавать protected
каналом вне Git; в хендоффе сохранены только paths/mode/metadata, не значения.

### EMS reference inventory, не шаблон безусловного deploy на новый хост

- dmash-node: `/etc/systemd/system/dmash-node.service`, WorkingDirectory
  `/opt/dmash-node/backend`; drop-ins `40-node-v4.conf`, `50-sturn.conf`,
  `notifications.conf`, `routing-discovery-v1.conf`.
- v4 enabled via `DMASH_NODE_V4_ENABLED=1`, state directory above; TLS proxy
  `/mesh/v4` → local backend. Детали: [NODE_V4_DEPLOYMENT.md](NODE_V4_DEPLOYMENT.md).
- dmash-sturn: User/Group turnserver; UDP/TCP **3479**, relay UDP **55000–55999**,
  current external IP **85.198.64.183**; nginx `/signal/v1` → `127.0.0.1:18080`.
  Existing global coturn **3478** оставлен отдельно; не заменить его static auth
  shared-secret mode. Детали: [EMS_STURN_DEPLOYMENT.md](EMS_STURN_DEPLOYMENT.md).
- node.env/rest.secret 0600 root; turnserver.conf 0640 root:turnserver. Новый
  external IP, TLS names, firewall/NAT и TURN URLs должны быть проверены заново.
- EMS Git owner — codex, хотя path содержит jcode. Историческую команду
  `su - jcode` не повторять вслепую; проверить реального пользователя нового хоста.
- EMS `tools/get_commit.sh` — host-local operational script, **не tracked в Git**.
  Его нужно отдельно сохранить/проверить перед переносом operational workflow.
  Текущий checksum и mode лежат в сохранённом inventory. Скрипт не включался
  автоматически в source bundle, его содержимое не проверялось на secrets.
- PWA backup `.24`:
  `/srv/messenger.d-mash.ru/backups/manual-rollback-20261007T231929Z` (UTC имя).
  STURN backup root `/root/dmash-sturn-backups`; отдельные Node/backend backups
  описаны в deploy utility. Это paths существующего EMS, не готовый off-host backup.

Если только dev переносится — не запускать старые hardcoded EMS utilities как
installer нового сервера. Если переносится runtime, адаптировать paths/service
owner/proxy/ports, сохранить identities и state, проверить rollback до cutover.
Публичные NodeID pin брать независимо от WSS peer, не из неподтверждённого
самопредставления. Production identity не клонировать в случайные test Nodes.

## 6. Как воспроизвести и что делать первым

Текущую опубликованную PWA можно проверить следующим скриптом; новый хост может
потребовать другие executable/module paths. Эта команда создаёт fresh synthetic
browser Accounts, не читает пользовательские существующие vaults.

```bash
DMASH_TEST_MEDIA=1 DMASH_TEST_CALL=1 DMASH_CONTACT_MODE=public \
DMASH_TEST_CONTACT_UI=1 DMASH_DROP_INITIAL_CONTACT=1 \
DMASH_EXPECT_RELEASE=transport-v3-recorded-fragments-20261008.24 \
DMASH_CHROME=/absolute/path/to/chromium \
DMASH_PLAYWRIGHT_MODULE=/absolute/path/to/playwright \
node tools/test_pwa_two_accounts.cjs
```

Основные scripts: `tools/test_node_transit_browser.cjs` +
`node_transit_v4_browser_server.py`; `test_node_worker_ownership_browser.cjs`;
`test_node_inbox_browser.cjs`; `test_worker_v4_remote.cjs` (explicit WSS + pinned
NodeID); `test_node_v4_remote.py`; `test_secure_registry_browser.cjs`;
`test_recorded_media_browser.cjs`; `test_call_browser.cjs`; `test_file_browser.cjs`.
Перед запуском прочитать их env/arguments: это не общий одинаковый CLI.
`diagnose_recorded_media_size.cjs` намеренно воспроизводит старый oversized
single-packet failure и может выходить 1; не считать его release regression PASS.
`tools/verify_ems_revision.py FULLSHA --host HOST --pwa-root PATH --node-root PATH`
проверяет deployed source, но не state/security/поведение.

Порядок продолжения с нового сервера:

1. Прочитать этот файл, AGENTS.md, полный план и v4 specs; организовать работу
   агентов и browser-first обход каждой кнопки по разделу 7. Проверить ветку/source,
   новый runtime target и protected state inventory. Повторить baseline tests,
   real browser transit/Worker/inbox и exact deployed acceptance.
2. Сделать **реальное ordinary Account→local Node Worker→EMS→Worker→Account**:
   root lifecycle, local binding/certificate/peer mapping и Account-owned payload.
   Не ограничиваться ручным attach в test harness и не засчитать v3 delivery.
3. Перенести private/public contact Request/Accept/Confirm и old binding/mailbox
   ownership с versioned migration, restart/locked/multi-account tests. Согласовать
   removal horizon v3 migration gateway; не оставить скрытый постоянный fallback.
4. Закрыть N4 recovery/state machine и persist/send fault matrix; затем N5
   криптографические/security gates, N6 provisioning, N7 Node-integrated media/wake,
   N8 full matrix. Сохранять совместимые A–M/E6, не вводить DHT/UI redesign.
5. Commit/push без force; deploy только exact tested SHA на актуально назначенный
   host, проверка source + page/SW + real acceptance + documented rollback. Не
   сливать main только из-за unit PASS и не отмечать полный план DONE по `.24`.

## 7. Обязательный способ работы следующего сеанса

**Работать через агентов.** Основной агент — оркестратор, тимлид, интегратор и
тестировщик. Пользователь явно разрешил и потребовал delegation: тимлид разбивает
работу на конкретные участки, выдаёт агентам задачи по protocol/Node, Account/
contacts/ratchet, UI/media, tests/migration и собирает результат. Не заставлять
одного исполнителя самостоятельно реализовывать весь план. Модели выбирать из
доступных без выдуманных требований к конкретной модели; каждый агент получает
актуальный full scope и выделенный участок. Параллельные edits изолировать
worktrees/branches либо явно непересекающимися файлами, не затирать чужую работу.
Тимлид проверяет diffs, конфликты контрактов и итоговый product flow; сообщение
агента «done» не заменяет самостоятельную приёмку и не означает весь план DONE.

**Всё проверять браузером. Перед началом новой разработки проверить каждую
кнопку и доступный пользовательский сценарий.** Не ограничиваться unit tests
или вызовами Core из console. Оркестратор ведёт BROWSER_QA.md: inventory controls,
исходные условия/версия страницы и active SW, action, expected/actual, evidence,
severity, назначенный агент, fix SHA и browser retest. Динамические controls,
модальные окна, dropdown/context menu, disabled/loading/error/cancel состояния
тоже входят в inventory. Не засчитывать недоступное/непроверенное как PASS.

Минимальный обход: calculator setup/unlock/master/wipe (wipe только fresh test
profile), Account create/login/logout/switch/recovery, navigation/settings,
node request/connect/disconnect/password, QR create/scan/import, private/public
route create/disable/delete, Request/Accept/Confirm/pending cards, every chat
button/SEND/history/delete/read, Saved Messages/local history password,
voice/circle record/SEND/cancel/playback/retry/download, call start/accept/decline/
hangup/audio/video, files request/consent/progress/cancel/complete, notifications
и все дополнительные найденные controls. Для destructive сценариев использовать
тестовые Accounts/profiles и согласованный staging target, не пользовательские
production данные. Реальные click/input плюс видимый результат обязательны;
console/RTC stats/transport logs — дополнительное доказательство, не замена UI.

Найденные баги воспроизвести, назначить агентам, исправить и повторно проверить
в браузере на интегрированном состоянии. Проверить два Accounts, public/private
flows, denied permissions, offline/locked/reconnect, stale SW и актуальные mobile
limits. Physical phone/WebAuthn и недоступные среды отмечать NOT RUN до настоящей
проверки. Использовать имеющиеся browser harnesses там, где они покрывают action;
расширять инвентарь и тесты для непокрытых кнопок. Общая регрессия/crypto tests
сохраняются; browser-first аудит не сокращает архитектурный N0–N8 scope.

В текущем аудите добавляются QA harnesses/evidence; ui_inventory получил
изолированное владение node_manager.js/acceptance_fixes.js для UI blockers.
Полная цель не завершена; после browser-first gate продолжить архитектурный переход.
Проверять живые handles текущего chat прежде повторного запуска test processes.
