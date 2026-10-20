# Самостоятельный сетевой daemon: границы и план

20 октября 2026. **Проект, не реализованный native daemon.** Кодовая база проверки: `9446c22f27309131456942870971d477f6f2358f`. Состояние реализации — [CURRENT_IMPLEMENTATION.md](CURRENT_IMPLEMENTATION.md); порядок работ — [TELEGRAM_INTEGRATION_PLAN.md](TELEGRAM_INTEGRATION_PLAN.md); переходы и приёмка — [NETWORK_ALGORITHMS.md](NETWORK_ALGORITHMS.md).

## 1. Принятые ограничения и факты кода

A→B, B→A и A→C обозначают **разные направленные маршруты**, а не разные identity устройства A. Последняя пользовательская концепция: один постоянный Device public key, не раскрываемый в wire, Account public key связан с паролем. Из неё не следуют per-peer static Device keys, случайные receiver-minted route IDs, Noise, новый directory или обязательный клиентский mailbox ACK. Эти замены в план не входят.

Фактический код различает следующие сущности:

| Сущность | Проверенный источник и следствие |
|---|---|
| DeviceRoot | Случайный локальный root; signing/agreement identity выводятся через domain-separated derivation. Это не Account public key: [device_root.js](https://github.com/Seriy615/D-MASH/blob/9446c22f27309131456942870971d477f6f2358f/D-MASH%20PWA/not_messenger/js/device_root.js), `deviceIdentity:365+`, создание root `558+`. |
| Account keys | Фактический legacy Argon2d от passphrase и identity+salt (неверный enum при намерении вызвать id; actual vendor proof — [CURRENT_IMPLEMENTATION](CURRENT_IMPLEMENTATION.md)); sign/box из разных участков результата: [core_engine.js](https://github.com/Seriy615/D-MASH/blob/9446c22f27309131456942870971d477f6f2358f/D-MASH%20PWA/not_messenger/js/core_engine.js), `341+`. `pub_hex:387` соединяет Account sign+box и installation KEM public key; это не DeviceRoot public key и не полностью password-only public bundle. |
| Private directional routes | Сохранённая случайная contribution (`ensurePairingContribution:465`), root из двух contributions без AccountID (`derivePairingLocators:473`); основной v3 path вызывает `PrivateRoutesV3.pair`, устанавливает inbound/outbound routes (`518+`). [private_routes_v3.js](https://github.com/Seriy615/D-MASH/blob/9446c22f27309131456942870971d477f6f2358f/D-MASH%20PWA/not_messenger/js/private_routes_v3.js), `7–37`: direction/generation → signing+box → locator=hash(signing public). |
| Recipient envelope | [node_manager.js](https://github.com/Seriy615/D-MASH/blob/9446c22f27309131456942870971d477f6f2358f/D-MASH%20PWA/not_messenger/js/node_manager.js), `855+`, `927+`: sealing на box public key маршрута; inbound secrets сохранены за root. [device_envelope.js](https://github.com/Seriy615/D-MASH/blob/9446c22f27309131456942870971d477f6f2358f/D-MASH%20PWA/not_messenger/js/device_envelope.js), `25–39`: ephemeral box envelope. Это дополнительный внешний слой над Account payload. |
| Node wire identity | [node_identity.js](https://github.com/Seriy615/D-MASH/blob/9446c22f27309131456942870971d477f6f2358f/D-MASH%20PWA/not_messenger/js/node_identity.js), `58+`: отдельный сохранённый Ed25519/PoW Node key. [secure_session.py](https://github.com/Seriy615/D-MASH/blob/9446c22f27309131456942870971d477f6f2358f/D-MASH/client/backend/secure_session.py), `123+`: HELLO включает signing `public_key`. Это отдельный Node wire key; его нельзя отождествлять с Device encryption public key пользователя или утверждать отсутствие любых стабильных wire keys. |

В default legacy-migration UI PRIVATE QR — `DMASH_PAIRING_V1` с Account signing ID и contribution; PUBLIC — сертификат public route: [acceptance_fixes.js](https://github.com/Seriy615/D-MASH/blob/9446c22f27309131456942870971d477f6f2358f/D-MASH%20PWA/not_messenger/js/acceptance_fixes.js), `60–69`, `142+`. В managed-v4 `showMyQR` переопределён: [node_account_ui_v4.js](https://github.com/Seriy615/D-MASH/blob/9446c22f27309131456942870971d477f6f2358f/D-MASH%20PWA/not_messenger/js/node_account_ui_v4.js), `108+`; Account-signed V2 bundle включает Account public keys и inbound certificate: [public_account_orchestrator_v4.js](https://github.com/Seriy615/D-MASH/blob/9446c22f27309131456942870971d477f6f2358f/D-MASH%20PWA/not_messenger/js/public_account_orchestrator_v4.js), `50+`. QR/приглашение не равно внешнему hop wire, но нынешний QR нельзя описывать как Device-public-only. Расхождение с пользовательской концепцией требует отдельного решения Q1, не выдуманной криптозамены.

Вклад пары позволяет **обеим сторонам вывести оба directional signing/box secrets**. Это shared route authority, не доказательство Account sender identity, не защита маршрута от второго участника пары. Получивший обе contributions тоже выводит эти ключи. Существующая self contribution повторно используется; disclosure/linkability и отзыв требуют анализа. Account E2EE проверяет отправителя независимо. Нельзя обещать исключительное владение получателя или недоступность route envelope второму обладателю материала.

## 2. Владение и локальный handoff

Account/application владеет plaintext, Account private keys, E2EE handshake/ratchet, историей и смыслом DELIVERED/READ. Daemon владеет только непрозрачными пакетами, transport routes/grants, соседями, очередями и ключами внешнего Node/channel/recipient-route слоя. Вскрытие route envelope даёт opaque Account payload, не право вскрыть Account E2EE. Account actors внутри daemon отсутствуют. Полный DeviceRoot и credential unwrap остаются в локальном root broker вне network process; Node получает лишь scoped transport materials. Это важно: legacy installation Kyber secret хранится под полным root и используется Account bundle, поэтому передача всего root демону нарушила бы строгую границу KEM. Managed-v4 Account KEM защищён Account master key; legacy material не стирается без inventory и сохранения decrypt capability.

После устойчивого handoff daemon сам выполняет discovery, retry, reconnect, relocation и передачу ciphertext; **сеть не вызывает Account**. Account logout, закрытый чат и окно не блокируют принятые jobs/transit/Inbox. Полный root lock закрывает ключи/каналы и оставляет encrypted queue. Новый E2EE переход после unlock — новое opaque задание приложения; существующий сетевой job не ждёт его для своего transport progress.

Проект локального IPC:

```text
installDestination(localOwnerCapability, versionedRouteMaterial) -> opaque DestinationHandle
submit(callerCapability, DestinationHandle, callerOperationId, opaqueBytes) -> JobHandle
query(JobHandle); cancel(JobHandle); events(cursor)
inbox(localOwnerCapability, cursor) -> opaque records
commitConsumption(recordHandle, applicationCommitToken)
admin.applyPolicy(policyVersion, policy)  // отдельное OS/UI permission
```

Account не передаёт IP/список Nodes/direct preference на каждую capsule. DestinationHandle — локальная capability, не wire AccountID. IPC аутентифицируется OS identity и scoped capabilities. Транзакция daemon сохраняет собственную копию bytes, digest, caller/destination-scoped idempotency key, expiry и job **до** возврата durable acceptance. Иной digest с тем же ключом — conflict; disk full/quota — отказ до acceptance. После неопределённого IPC результата caller повторяет тот же submit. Account outbox удаляет собственный transport intent только после подтверждения handoff; E2EE receipt ожидание остаётся отдельным прикладным состоянием.

Inbox commit и local consumption тоже раздельны: приложение decrypt/verify/persist, затем отмечает consumption. Crash между ними допускает повтор чтения; прикладной operation ID предотвращает второй commit. Wire не сообщает terminal flag или Account delivery state. Transport acceptance не является DELIVERED.

## 3. Native host и единственный владелец

Переиспользовать протокол/route logic существующих JS/Python модулей; первый native slice сохраняет согласованный NODE/WSS профиль. [node_runtime_host_v4.js](https://github.com/Seriy615/D-MASH/blob/9446c22f27309131456942870971d477f6f2358f/D-MASH%20PWA/not_messenger/js/node_runtime_host_v4.js) уже запускает Worker и запрещает второго owner **одной root session в своём JS realm**; это не process-wide Desktop/Android daemon lock.

Broker unwrap/start отделён от сетевого процесса: как `NodeRuntimeHostV4.startMaterials` в текущем Worker path, переносит только seed/storageKey/BaseNCRH/разрешённые route keys. Произвольный `deviceMaterial`/Account key API в daemon отсутствует. UI close может забыть broker root и оставить авторизованный Node bundle; full root lock отзывает bundle/закрывает Node. OS-wrapped transport-only bundle для reboot — отдельная policy, не unattended полный root. Native IPC заменяет browser `rootGuard/currentAccount` проверками owner/capability/generation; это новая реализация, не готовая гарантия startMaterials. Same-UID/OS compromise не объявляется изолированным.

Desktop host: отдельный процесс службы, закрытый локальный IPC, OS-protected transport-bundle wrapping (полный root остаётся в broker), transactional encrypted ledger. Android host: тот же логический runtime за platform service/IPC, явные состояния OS suspended/permission denied; lifecycle/wake adapter не обещает постоянное исполнение. Выбор runtime packaging и Android background режима — Q3. PWA/Service Worker не считать постоянно живущим daemon.

Новый owner coordinator: OS process lock + monotonic durable owner generation; каждое queue/grant изменение проверяет generation. Старый owner после рестарта/lease loss fenced; adapter запрещает его новые sends. UI переподключается к одному host. Нельзя одновременно передать одни Node keys двум независимым writers. Резервная копия не создаёт второго активного владельца с прежней generation.

Компоненты: Root/Owner coordinator → authenticated IPC → encrypted job/Inbox ledger → route/grant manager → bounded scheduler/batcher → peer session manager → WSS/direct adapter. Отдельные admin и telemetry scopes; payload/credentials в logs не попадают. Account vault не открывается для network boot.

## 4. Самоорганизация и достижимость

Сначала использовать существующие trusted/pinned descriptors и directory semantics. Несколько настроенных bootstrap seeds, сохранённые peers и ограниченные introductions дополняют discovery без нового глобального Account/device directory и без DHT. Нет trusted seed/peer — `NO_BOOTSTRAP`. Introduction не даёт route/mailbox authority. Лимиты соседей, источников, dial attempts, handshakes, CPU/PoW, TTL и bytes задаются проверяемым policy profile; source/subnet diversity уменьшает eclipse, не доказывает независимость участников.

Сохранить route advertisement semantics: Probe объявляет путь **назад к инициатору**, NCRH/UNKNOWN recovery относится к route context; импорт contribution может произойти после Probe. NCRH не identity и не permission. Сохранить path alternatives/shorter-path selection, loop guards, bounded random Probe hop limit и first-arrival 500 ms aggregation; не вводить глобальный periodic refresh. Точный delta от нынешнего общего NCRH root/metric/trace фиксируется отдельно в Q2: [hop_probes.py](https://github.com/Seriy615/D-MASH/blob/9446c22f27309131456942870971d477f6f2358f/D-MASH/client/backend/hop_probes.py), `21+`, `350+`, и [tact.py](https://github.com/Seriy615/D-MASH/blob/9446c22f27309131456942870971d477f6f2358f/D-MASH/client/backend/tact.py), `13–56`.

Direct NAT path — отдельный carrier slice. Обмен candidate capsule идёт через имеющийся authenticated путь и связывает expected peer, attempt, route/auth generation, expiry и свежие ICE credentials. Доступность IP и ICE password не заменяют D-MASH authentication/resource grant. Никаких проб на произвольные IP из непроверенных introductions; endpoint classes/ports/rates ограничены. Endpoint metadata (host/reflexive/relay IP, port, network type, expiry) локально чувствительны; отправляются только разрешённому peer в scoped encrypted capsule, не в общий catalog/log.

ICE проверяет candidate pairs; STUN сам не обеспечивает весь traversal; TURN даёт relay, не долговременный file buffer. Для части NAT/firewall relay обязателен: [RFC 8445](https://www.rfc-editor.org/rfc/rfc8445.html), [RFC 8489](https://www.rfc-editor.org/rfc/rfc8489.html), [RFC 8656](https://www.rfc-editor.org/rfc/rfc8656.html). Consent freshness и binding keepalive различаются: [RFC 7675](https://www.rfc-editor.org/rfc/rfc7675.html).

При direct-off daemon немедленно запрещает gathering/probes, новые direct payload и **уже queued retransmissions**, отменяет checks и удаляет запрещённые candidates. При отсутствии relay — `WAITING_ALLOWED_PATH`; старый direct channel не используется для «drain». Wi-Fi/mobile/IP change, sleep, expiry → bounded recheck/ICE restart и fresh session auth; logical jobs сохраняются. WSS сам по себе UDP hole punching не выполняет. Carrier choice, interoperability и NAT evidence — Q4.

## 5. Сохранность, ограничения и privacy

Нынешний remote mailbox контракт: bounded ALL snapshot → lease → `await send` → delete; failed send освобождает lease: [node_mailbox_v4.py](https://github.com/Seriy615/D-MASH/blob/9446c22f27309131456942870971d477f6f2358f/D-MASH/client/backend/node_mailbox_v4.py), `186–247`. Успешный socket send не доказывает durable recipient commit: crash получателя до Inbox persist после server delete — **loss window**. Не добавлять обязательный клиентский ACK и не менять этот контракт молча. Durable local handoff обязателен независимо от remote mailbox. Предлагаемый отдельный negotiated `durable-custody-v1` описан в [BUFFERED_FILES.md](BUFFERED_FILES.md) и NETWORK_ALGORITHMS: cached directional Inbox grant, 1..3 fixed anchors/job, sealed invitation и encrypted signed locator bundle; mutable providers выбирает daemon без Account callback. Все anchors потеряны → unavailable. Его persist ACK/retention/grants не меняют legacy PULL; mixed-version не обещает отсутствующую durability (Q5).

Очереди ограничены по caller/route/peer/global bytes, jobs, attempts, времени и CPU. Per-peer FIFO и fairness исключают блокировку остальных медленным соседом. RAM transit может быть droppable и не обещает custody. Уже принятое durable хранение нельзя стирать из-за снижения quota; expiry/cancel/revoke имеют явные правила. Backpressure возвращает контролируемый отказ, не бесконечную очередь.

Направленные IDs и hop label replacement не скрывают неизменный ciphertext/timing/length от сговаривающихся Nodes. Нынешние Node HELLO key, Probe metric/trace и media endpoints — предмет privacy gate. Одинаковая роль NODE не доказывает анонимность. Смена channel keys, route generations, wrapping keys не меняет Account/Node identity. Ротация скомпрометированной identity — отдельная подтверждённая recovery процедура, не обычный reconnect.

## 6. Последовательность и незакрытые решения

1. Зафиксировать Q1/Q2 и схемы IPC/ledger/policy, воспроизвести crash/loss regressions на текущем коде.
2. Общие host/IPC/storage ports и параллельно Desktop user daemon и Android service: один owner, WSS, durable local handoff/Inbox и Account-free retry; retained-state migration и restore. Platform lifecycle gates принимаются отдельно; Desktop prototype не заменяет Android acceptance.
3. Bounded bootstrap/introductions и существующий route discovery; затем authenticated direct/relay carrier и mobility. File relocation использует daemon-owned location state; immutable ciphertext не требует переподписи Account после logout.
4. Реализация negotiated durable-custody-v1 только после решения Q5. Exact-SHA browser/native/NAT gates из NETWORK_ALGORITHMS; production release отдельно.

Каждое OPEN имеет самостоятельный reviewable результат; решение одного не закрывает остальные:

| ID / OPEN | Design resolution | Независимый gate |
|---|---|---|
| Q1: Device/Node/QR модель | Сопоставить требуемый один нераскрываемый Device key с отдельным действующим Node HELLO key и двумя QR profiles; утвердить поля/visibility/trust continuity без пересоздания identity. | QR export/import в каждом profile + wire traces B/C; сохранены прежние root, Account/Node keys/history; route IDs AB≠BA≠AC. |
| Q2: route authority/privacy | Специфицировать contribution exposure/revocation, shared authority bounds, route-bound NCRH и допустимый metric/trace delta; не подменять Account sender auth. | Holder с обеими contributions не получает Account E2EE identity; forged owner/wrong direction/session reject; Probe-before-import/UNKNOWN/shorter path и comparative traces. |
| Q3: native owner/storage/platform | Выбрать Desktop/Android packaging, root protection, fencing, OS lifecycle и recovery floors. | Два процесса, kill на каждой tx границе, stale writer/backup, locked root, физический Android sleep/reboot/permissions; ciphertext/identity сохранены. |
| Q4: direct carrier/policy | Выбрать native ICE carrier с framing/MTU/reliability и authenticated rendezvous binding; численные budgets/policy defaults. | Два реальных NAT, forced relay, candidate tamper/replay/SSRF, mobility, direct-off во время queued retry; отсутствие запрещённого трафика в capture. |
| Q5: custody/retention | Зафиксировать предлагаемый durable-custody-v1: directional cached grants, fixed anchors, receipt schema, retry/dedupe horizons; отдельно сохранить legacy loss-window поведение. | Fault matrix до/после send/delete/recipient commit; lost receipt/restart/quota/expiry; mixed-version не заявляет отсутствующую гарантию. |

**Native daemon, физический Android, NAT/direct и новый custody профиль здесь не реализованы и не проверены.** Этот документ — план; прежние scoped browser PASS не являются его acceptance.
