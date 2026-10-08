# Предыдущие разделы 2–3 CURRENT_HANDOFF.md до release .30

Историческая сводка; актуальные SHA и статусы см. в корневом CURRENT_HANDOFF.md.

## 2. Текущий Forge checkpoint и опубликованный baseline

На 8 октября 2026 работа идёт на `forgeai.isgood.host`, user `codex`,
`/home/jcode/D-MASH`, `transport-v3`. Постоянная цель активна; N3/N4 и полный
browser-first inventory ещё не завершены. Реализация делегирована агентам;
лид независимо проверяет интеграцию и опубликованный UI.

Текущий опубликованный source checkpoint ветки `transport-v3` —
**`1a75299adf24423126d598dedc9db903e574d3ea`**, merge узкого UI release
`637c9bb02c2c57a05e8edc815678b6fb204f632c` и Node routing checkpoint
`62f97d7cf5562943d545681fa788c31378523d87`. На exact merge:
**281 backend + 11 Origin + 82 JS PASS**. Routing DATA dedupe теперь учитывает
аутентифицированного peer и проверенный hop grant; отдельные Python/JS
двух-hop retry regression PASS. Это не закрывает потерянный ACK после consume
Node Inbox и не завершает N4. В source остаются inactive foundation и private
bootstrap; обычный Account/contacts/UI всё ещё использует v3. WIP агентов
в shared checkout не входит в этот SHA и не должен попадать в deploy случайно.

Предыдущий source checkpoint **`3474eeed916d07f44df693391e594e0bec140508`**
включает N4 foundation (inactive) поверх проверенного Account UI checkpoint
`a4fd2aa24f31f07c372da5573f638f8d331df8af`:
на exact checkout **280 backend+11 Origin+78 JS PASS** и отдельный Chromium/IDB
mechanism PASS. N4 использует явно именованный legacy Kyber suite, signed
fresh-key handshake, encrypted 3-row CAS ledger/state/binding и fail-closed
binding migration. Это **не** ordinary UI recovery, не transport end-to-end и
не доказательство PCS/PFS/PQ. Evidence:
`docs/evidence/2026-10-08/qa-n4-foundation-3474eee.json`.

Предыдущий проверенный source/QA checkpoint **`a4fd2aa24f31f07c372da5573f638f8d331df8af`**
(`efbc9c42ddff903af1d2db17399c92d6a00e7709` + только QA helper):
managed Node owner proof, Account four-row journal и same-Host A→B→A
зафиксированы в предыдущем `b9e405f`; Core теперь публикует отдельную
подтверждённую Account-сессию и отзывает её до замены vault/logout, не отзывает
при ошибке пароля. Исторический signed route snapshot различает истёкшее offer,
истёкший certificate и старые rows без verification epoch, сохраняя их.
На exact checkout `efbc9c4`: **280 backend+11 Origin+76 JS PASS**, реальный
IndexedDB journal PASS. На exact `a4fd2aa`: свежий browser UI 29/29 PASS,
56/56 loaded assets совпали по SHA, SW BLOCKED source overlay; это не DEPLOYED
приёмка нового source. Тест инструментирует гонку wrong-key и подтверждает,
что реальный click logout отзывает сессию до зануления ключей. Evidence:
`docs/evidence/2026-10-08/qa-account-lifecycle-manifest.json`.
Отдельно exact `7ce0b87` real Python→Chrome Node→Python transit и Worker
ownership/Inbox PASS. Публичный PWA всё ещё работает через v3; ordinary
Account adapter, private/public bootstrap, mailbox migration, N4 recovery
и полный browser inventory не завершены. Новые незакоммиченные файлы агентов
не входят в эти exact-SHA проверки. Последний published source SHA и Forge
origin сверить после следующего docs/checkpoint push; production ниже отдельно.

Текущая production PWA на EMS — узкий commit
**`fd2a7505ba7325ee0d47e38cb2cfc8271cbfc0c1`**, release
**`transport-v3-node-preparation-20261008.28`**. Он достижим из published
source branch; media/Node-миграция не развёрнуты. После узкого backend
S-TURN health deploy точный combined PWA+backend target
**`b944d26136261182494a3c8e1686ac6aa17dcc28`**: **218 checked,
missing=[], changed=[]**. Два свежих Chromium profiles на
опубликованной странице: **16/16 real UI actions PASS**, page/SW обе `.28`,
136 loaded sources exact SHA, errors 0, immediate key feedback 157 ms;
Request/Accept/Confirm, двусторонние сообщения и оба FlipLock controls проверены.
Supplemental deployed owner-conflict UI fixture: **7/7 actual UI actions PASS**,
synthetic incoming metadata/send failure, без claim реальной remote delivery;
history и signed owner state сохранены. Перед публикацией immutable source-overlay `.28`: первый public
run прошёл Request/Accept/Confirm и immediate feedback, но завершение обмена
зависло при DNSS pending; второй fresh run **16/16 PASS** с DNSS ready, 135
loaded sources exact SHA, errors 0. Intermittent `ROUTE-READY-01` остаётся OPEN.
Предыдущая `.27` deployed 16/16 — historical evidence. Physical mobile
orientation NOT RUN. PWA-only deploy через EMS `get_commit.sh`; static backup:
`/srv/messenger.d-mash.ru/backups/manual-rollback-20261008T024105Z`.
Этот PWA deploy не менял Node backend/keys/DB; отдельный health deploy ниже.

Backend EMS — `.26` foundation
**`3c513601ef3990b6514e247d879324b7b72da494`** плюс ровно четыре Python
файла S-TURN health из reachable `b944d26` (`core.py`, `s_turn.py`,
`s_turn_health.py`, `signaling_gateway.py`) и pinned `aioice==0.10.2`.
`DMASH_CAN_S_TURN=1`, `DMASH_CAN_RELAY_BLOB=1` на EMS test target; `can_signal`
не включён. Health требует authenticated TURN allocation, bidirectional nonce/hash
UDP/TCP и обычный WSS ticket flow, freshness ≤45 s. После остановки Node
protected runtime snapshots:
`/root/dmash-runtime-backups/sturn-health-20261008T025452Z` и
`/root/dmash-runtime-backups/sturn-relay-flag-20261008T025653Z`; 3 active SQLite
quick_check PASS в каждом, identity files byte hashes равны после restart,
service active. Последующий Chromium forced relay/relay 32 KiB/hash PASS и
Python UDP/TCP/WSS PASS. Ранее `.26` snapshot
`/root/dmash-runtime-backups/release26-20261008T004030Z` остаётся для rollback.
Секреты/snapshots вне Git; production на Forge не переносился. Full media UI
приёмка ещё не выполнена, capability может быть отозвана через сохранённый env.

Совместный live test с пользователем на его `.26` и отдельном synthetic
Account подтвердил двусторонний E2EE чат: текст получен, authenticated READ
receipt виден, ответ пользователя сохранён; входящее голосовое 2.3 s получено
и audio metadata decoded. Пользовательские pairing/data/audio не включены в Git.
Однако у отправителя записанное медиа показывало ожидание; independent synthetic
browser baseline: 2.3 s voice → 13 Mesh fragments → ~54 s до receiver audio,
затем outbox empty/history DELIVERED, но открытый sender DOM оставался с ⌛ до
переоткрытия чата. Повторный synthetic burst из трёх записей дал
`Recorded-note queue full` на третьем SEND: третья запись не была сохранена,
две предыдущие оставались в durable outbox. Stage timings: profile handshake
~3.5 s, fragment dispatch/ACK ~1–2 s каждый; задержка не равна одному долгому
вызову шифрования.
Новый контракт от пользователя: voice/circle media bytes только через EMS
S-TURN; Account-encrypted ordinary messages несут лишь invitation/receipt
metadata. Offline запись зашифрована на устройстве отправителя до подтверждения
online peer; bounded retry invitation без отдельного presence oracle. Старые
pending rows сохранить. На EMS теперь real health + relay capability, но новая
PWA media `.29` пока **candidate** `a524bc0` в isolated worktree: encrypted
offline intent, only metadata through Account message, bytes relay-only,
bounded retry/ACK/reload/Account switch mechanism PASS; actual ordinary UI
browser run выполняется, не DEPLOYED. Ни live call/file UI, ни новый recorded-note
ordinary UI path ещё не PASS. Owner agents: qa_account_media (media), node_audit (Node public/KEM), ui_inventory
(браузерная приёмка). Полная N7/N3 цель остаётся открытой.

`Contact acceptance owner mismatch` воспроизведён без изменения существующего
ciphertext: сохранённый Accept принадлежит первому Account slot, повтор под
другим Account должен направлять к исходному владельцу, а не переподписывать.
Fix `dd357e1132c98a73d07f86bccbe193281d69caac` имеет 6 targeted UNIT,
7 synthetic source-overlay UI PASS и 7/7 deployed `.28` UI PASS. Он направляет
к сохранённому Account-владельцу, повторяет точное подписанное принятие и
отказывает истёкшей подписи без смены ключей/истории. Реальная remote delivery
в owner-conflict fixture не проверялась; обычный двухсторонний public flow
прошёл отдельный deployed browser run 16/16.

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

### Исторический `.24` runtime baseline (не текущий deploy)

| Параметр | Значение |
|---|---|
| Репозиторий | https://github.com/Seriy615/D-MASH |
| Ветка разработки | `transport-v3` — имя историческое, здесь также лежит v4 |
| `.24` runtime commit | `ed200730dab2e64fc8446e344ce54dbd37cfeec5` |
| `.24` release | `transport-v3-recorded-fragments-20261008.24` |
| PWA | https://messenger.d-mash.ru/not_messenger/ |
| v3 gateway, временный migration path | `wss://stage-api-ems.d-mash.ru/dmp-c/v3` |
| Native unified Node endpoint | `wss://stage-api-ems.d-mash.ru/mesh/v4` |
| Signaling | `wss://stage-api-ems.d-mash.ru/signal/v1` |
| EMS source checkout | `/home/jcode/D-MASH`, Git owner `codex` |
| EMS backend / frontend | `/opt/dmash-node/backend` / `/opt/dmash-node/frontend` |
| EMS PWA root | `/srv/messenger.d-mash.ru/public_html/not_messenger` |

Этот `.24` SHA ранее был deployed; он не описывает текущую `.27` PWA/`.26`
backend. Исторический exact verifier проверил **205 файлов**.
`dmash-node`, `dmash-sturn`, `coturn`:
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

**Текущий независимый DEPLOYED UI gate:** exact `5a2439834a2fc22db8f6ecd0b9674d533397ea8a`, actual HTTPS EMS, page и active controlling SW `.29`, без overlay. PUBLIC Request/Accept/Confirm, key/text в обе стороны, voice burst/hash/relay/decrypt/playback, offline/reload/visible cancel/retry/Account switch/reconnect, circle и безопасное удаление контакта PASS на свежей synthetic паре. Исходное прерывание Settings входящим notification сохранено; после actual OK тот же профиль прошёл 27/27 continuation checks.206 loaded responses exact (122 from SW), pageerrors0. SEND→durable203/251/263ms; все три delivered через45.641s после первого durable save — это не обещание постоянной скорости доставки. Corrupt-owner refusal сохраняет history/keys/media/route/epoch; valid deletion сохраняет unknown opaque row и identity. [Матрица и ограничения](docs/evidence/2026-10-08/qa-deployed5a-summary.md). N4 safety-only, не full recovery/migration. Legacy pending migration NOT RUN (CDP9452 unavailable); user9449 untouched, synthetic9490 retained. Full N0–N8/A–M/E6 и оставшиеся controls не объявлены DONE.


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
