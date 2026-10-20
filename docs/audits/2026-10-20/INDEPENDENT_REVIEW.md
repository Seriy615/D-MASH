# Независимый review планового пакета

20 октября 2026 UTC. Product baseline: `9446c22f27309131456942870971d477f6f2358f`.

**Плановый пакет ACCEPTED в описанном ниже scope. Известных блокирующих фактических противоречий в замороженных документах не осталось. Приложение НЕ ГОТОВО; production vulnerabilities НЕ ИСПРАВЛЕНЫ этим review.** Расширенная цель пользователя — работающие Android и Desktop с закрытием найденных проблем — остаётся активной работой реализации в [IMPLEMENTATION_BACKLOG.md](IMPLEMENTATION_BACKLOG.md). Закрытие анализа не закрывает эту цель.

## Независимость и точный объект проверки

Reviewer не писал основные архитектурные, файловые, policy, Telegram и backlog документы. Он проверил actual source, создал отдельные actual-crypto runners и specification fault model, повторил отдельные предоставленные proofs и проверил исправленные версии документов. Единственное изменение чужого test runner — совместимый guard для native `global.crypto` на reference Node 24; это audit tooling, не product fix.

Прочитаны AGENTS, CURRENT_HANDOFF и development plan. Проверены CURRENT_IMPLEMENTATION, REPOSITORY_AUDIT, TELEGRAM_INTEGRATION_PLAN, IMPLEMENTATION_BACKLOG, NETWORK_DAEMON_ARCHITECTURE, NETWORK_ALGORITHMS, BUFFERED_FILES, SECURITY_CONTROLS, README и verification notes/results, включая MASTER_SECRET_FIX_DESIGN и NATIVE_HOST_FEASIBILITY. Точные замороженные bytes привязаны к [review-input-manifest.json](verification/review-input-manifest.json); manifest содержит SHA-256 каждого входа, без циклического self-hash. Изменение входа требует повторного review соответствующего delta. Product source в этом checkout не изменён; отдельные audit artifacts находятся вне tracked product tree.

## Найденные замечания и их разрешение

| Замечание | Разрешение в пакете | Состояние реализации |
|---|---|---|
| Argon2id claim не соответствовал actual vendor dispatch | Независимый real JS/WASM execution подтвердил undefined top-level enum → Argon2d. Canonical/audit/security/native docs исправлены; legacy Account/root compatibility и versioned rewrap того же root выделены отдельно | S01/S02 OPEN. Наивная глобальная замена enum запрещена: она меняет доступ к прежним ключам |
| Desktop-first последовательность противоречила выбору двух параллельных клиентов | Network architecture, основной план и backlog теперь требуют общие контракты и параллельные platform slices, отдельную приёмку каждого | Оба native клиента OPEN; один Desktop proof не закрывает Android |
| Android Qt Quick shell был не согласован с Java Telegram widgets | Android target — Java/Kotlin Views поверх QtService/JNI/Binder; Qt Quick допустим только как временный status spike. Desktop — Qt Widgets/rendering adaptation | UI extraction/build/flows OPEN; Java widgets не объявлены drop-in Qt Quick компонентами |
| Передача полного DeviceRoot сетевому daemon нарушала бы заявленную границу legacy KEM | Source подтвердил root-backed installation Kyber secret в Account bundle. Новый target передаёт только scoped transport materials; root/credential broker вне network process. Full lock отзывает bundle; broker forget при UI close — отдельное действие | Broker/IPC ещё НЕ реализованы. Same-UID/native/OS compromise не объявлен устранённым; legacy KEM не стирается без ownership inventory |
| Перенесённый master repro падал на Node 24 из-за присваивания read-only global crypto | Добавлен guard, сохраняющий existing native crypto; runner независимо повторён на Node 24.19.0, 7/7 проверок PASS, JSON/doc hashes обновлены | Исправлено только audit tooling |
| Supplementary proofs зависели только от временных файлов | Master runner и native C/JS/stdout сохранены в verification; для native есть build recipe и manifest 25 embedded modules | Воспроизводимость ограничена перечисленными toolchains/ports, не готовым native продуктом |

Разрешение документационного замечания не означает исправление соответствующей уязвимости в приложении. Задания S/C/N/A/F/U/M/R сохраняют реальные TODO/SPIKE/ANALYSIS статусы.

## Требования: покрытие планом и реальное доказательство

| Требование | Проверенный результат / предел |
|---|---|
| Фактические DeviceRoot, Account, Node, route keys и QR | CURRENT_IMPLEMENTATION опирается на source и разделяет legacy/managed-v4. Нет придуманной замены identities per-peer ключами. Account KDF, shared installation KEM, per-Account v4 KEM и стабильный Node HELLO key различаются |
| Направления A→B, B→A, A→C и reconnect | Actual PrivateRoutesV3 с bundled NaCl/HKDF: симметрия противоположных endpoints, разные направления/третья пара/generation. Account ID не входит в helper KDF; generation syntactic validation не выдана за antirollback lifecycle |
| Public/private contribution threat boundary | Self contribution повторно используется в vault. Обе contributions воспроизводят оба route signing/box secrets; это не DH и не исключительное владение recipient. Account sender authentication отделена от outer envelope |
| Устройство сначала полноценная Node | План требует foreign transit без Account и UI на Android/ Desktop; scoped transport host, single owner/fencing, persistent jobs/Inbox и supervisor. Исторический browser Worker transit — основа, не native acceptance |
| Account-independent durable handoff | Account формирует E2EE packet один раз; daemon владеет собственной устойчивой ciphertext копией и retry, без Account callbacks. Local IPC model проверяет crash/reply loss/idempotency; native IPC/storage реализация OPEN |
| Самоорганизация и mobility | Bounded pinned seeds/cached peers/introductions, scoped Probe recovery/shorter paths, 500-ms first-arrival batch, resource limits. Нет нового глобального Account directory/DHT или незаметной смены NCRH/identity модели |
| Direct NAT, relay и немедленная policy | Authenticated rendezvous/peer binding, endpoint/SSRF bounds, ICE/consent/restart, relay fallback и fence queued direct retries. Реальные NAT/Android lifecycle gates NOT RUN; WSS/compile proof не подменяет их |
| Offline encrypted file buffers | Отдельный negotiated custody профиль: fixed inbox anchors/bootstrap, durable invitation+chunks+locator, mutable providers без Account repack. Первый recipient Account unlock нужен для descriptor authorization; сохранность/freshness/retention/cancel/все anchors lost ограничения явные |
| Mailbox reliability contract | Существующий ALL/lease → awaited send → delete сохранён; окно потери до recipient persist названо явно. Mandatory ACK не добавлен молча. Более сильный durable-custody-v1 имеет отдельные grants/receipts/version negotiation |
| Простота и индивидуальные security/resource controls | Presets не скрывают отдельные параметры; обычная отправка без обязательных технических вопросов. CAS/effective policy/queue reconciliation, quotas, root lock/logout/screen-off и custody/DELIVERED различаются |
| Два клиента и Telegram reuse | Общий host contract, параллельные Android/Desktop targets, отдельные platform gates; выбранные rendering/layout части за своими DTO. Telegram transport/login/storage не становятся D-MASH runtime. Dependency closure, licensing и egress review остаются release задачами |
| Закрытие выявленных проблем и retained-state migration | Backlog включает fast verifier, actual KDF compatibility, dependencies, supervisor/mailbox, crypto claims, media, provenance/installer и release gates. Root/identity/history reset ради PASS не разрешён; MASTER_SECRET_FIX_DESIGN учитывает loaded repair/wipe/cancel/cross-store paths |
| Полное описание actual implementation и модель угроз | Явно оставлены release artifacts по фактической реализации. Плановый пакет содержит threat boundaries/limits, но не выдаёт себя за завершённый formal threat model или security audit |
| Честная приёмка | UNIT/SPEC MODEL/limited native compile/BROWSER/DEPLOYED и исторические checkpoints разделены; all-buttons, physical Android, real NAT и complete N0–N8 DONE не заявлены |

## Исполненные проверки

- [Actual route/envelope runner](verification/check_actual_crypto.cjs): 19 checks PASS на Node 24.19.0 с actual repository NaCl/HKDF/modules. Проверены полные directional secrets/locators symmetry, direction/peer/generation separation, generation validation, Account-context independence helper, capture reconstruction, outer roundtrip/wrong-key rejection, wire без static recipient field и отсутствие Account sender-auth от одного outer box. Это не доказательство independence всех runtime paths или anonymity.
- [Actual Argon2 runner](verification/check_actual_argon2.cjs): real vendor JS + repository WASM, undefined type == explicit d, != explicit id; encoded d. Reduced-cost synthetic vector проверяет dispatch, не real Account login. Отдельный [master runner](verification/check_master_secret_repro.cjs) на Node 24.19.0 подтвердил full-cost synthetic vectors, actual `_encryptRoot` с d и 7/7 checks. Cross-store rewrap — spy; real persistence crash и destructive correct-code wipe не выполнялись.
- Две существующие suites PrivateRoutesV3/DeviceEnvelope повторены, PASS; source hashes в [focused-suite-results.json](verification/focused-suite-results.json). Полный suite здесь заново не запускался; исходный audit runner PASS остаётся только своим записанным evidence scope.
- [SPEC MODEL](verification/spec_fault_model.py): BFS depth 12, 2 in-flight copies, 2875 unique states/21117 transitions в safe custody варианте без bounded counterexample. Negative controls нашли loss при send→delete, volatile ACK→crash, forged receipt, duplicate jobs без dedupe и false DELIVERED от custody. Отдельный local handoff depth 9: safe 14 states/65 transitions; early reply и non-unique commit дали реальные counterexample traces. Offline-Account transit, mobility и durable custody после policy revoke имеют witnesses.
- [Native proof](verification/native-proof/README.md): независимый rerun Linux C/QuickJS executable exit 0, 6 ограниченных checks. Четыре исходных artifact hashes совпали; дополнительно проверены exact hashes и byte inclusion/order всех 25 unchanged module bodies в сохранённом bundle. Это source-load/selected crypto proof, **не** Qt/Android build, WSS/SQLite port или native application acceptance. [Qt primary service documentation](https://doc.qt.io/qt-6/android-services.html) и [QWebSocket API](https://doc.qt.io/qt-6/qwebsocket.html) отдельно проверены как supporting API facts, не доказательство работающего adapter.

## Открытые границы и вердикт

SPEC MODEL — одна логическая операция, атомарная storage abstraction, два одинаковых network экземпляра и perfect symbolic receipt authentication. Она не реализует production protocol, несколько разных сообщений, реальные signatures/keys, fsync, owner IPC, blob/provider/locator state machine, NAT или OS lifecycle. Safety в bounded exploration не доказывает unbounded correctness, fairness или eventual delivery при бесконечной потере/вечном offline. Адресная mobility модели не является испытанием native ICE restart.

Q1–Q5 требуют конкретных versioned схем/interop vectors и независимых gates при реализации. QuickJS/Qt — выбранный путь следующего spike; full dual-target acceptance ещё открыт. Root broker, storage encryption boundaries, policy linearization, grants/revocation/retention и Account facade должны быть подтверждены actual code и failure tests. Перечисленные production risks нельзя считать закрытыми из-за зелёных unit tests или source-load proof.

**Блокирующих замечаний к этому замороженному плановому пакету: 0. Блокирующая готовность приложения/release: OPEN по backlog.** Следующий результат — reviewable implementation slice на обеих платформах с подходящей приёмкой, затем обычные contact/text/file/UI flows и закрытие release blockers; новый implementation checkpoint имеет свой SHA и evidence.


## Проверенный delta после первоначальной заморозки

В IMPLEMENTATION_BACKLOG добавлены только S07 и R03: явная проверка legacy
PHP/Origin/webhook/log surfaces и исправление installer pin/visibility/password,
working-branch CI. Обе строки соответствуют уже зафиксированным audit findings;
PHP exposure остаётся неизвестным, production exploit не заявлен, installer
приёмка ограничена disposable VM и не авторизует production запуск. Статусы
TODO не подменены FIXED. Delta принят без новых blocking замечаний; повторять
crypto/model/native proofs для документального изменения не требуется.
Product source и остальные замороженные входы не изменялись. Input/artifact
manifests обновлены под эти bytes; planning-only вердикт сохраняется.
