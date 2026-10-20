# D-MASH: аудит реализации перед выделением демона и созданием клиентов

Дата: 20 октября 2026, Europe/Moscow. Срез: ветка transport-v3, commit 9446c22f27309131456942870971d477f6f2358f.

## Вывод

У D-MASH есть работающая основа самостоятельного мессенджера: Account E2EE, защищённое локальное хранение, Python Node, JS Node в Worker, проверяемый транзит, подтверждение ключей, durable Account outbox и изоляция Accounts. Эту основу имеет смысл сохранять.

Но отдельного переносимого «ядра, к которому осталось прикрутить Telegram» пока нет. Application runtime находится преимущественно в браузерном JavaScript, использует IndexedDB/WebCrypto/WASM/Worker и связан с глобальными Core/Storage/NodeManager и DOM. Python backend представляет сетевую Node и не заменяет Account SDK.

Пользователь уточнил назначение приложения: основной результат — автономная локальная Node в демоне/сервисе, чтобы сетевой цикл, соединения, транзит и очереди жили независимо от интерфейса. Это первый функциональный этап. Выделение API и platform adapters должно обеспечивать такой runtime; оформление интерфейса Telegram идёт после его проверки. Обязательное предварительное завершение всей PWA не требуется.

Сочетание нескольких поколений runtime, незавершённого v4 lifecycle/store-and-forward и неточных ожиданий от криптографии остаётся отдельным набором замечаний. Демон позволит управлять соединениями и восстановлением вне браузерной страницы; причины задержек discovery/handshake, ошибки grants и гарантии mailbox нужно проверять на нём отдельно. Аудит не установил, что все сетевые задержки вызваны браузерным lifecycle.

Закрытие экрана, уход приложения в фон и системная блокировка экрана отличаются от явной полной блокировки локального root D-MASH. В первом случае daemon lifecycle определяется выбранной политикой приложения и ограничениями ОС; Account logout отзывает Account secrets и оставляет разблокированную Node, а явный root lock останавливает защищённый runtime. Это сохраняет прежнее разделение Node и Account.

Пошаговый план: [TELEGRAM_INTEGRATION_PLAN.md](TELEGRAM_INTEGRATION_PLAN.md). Исправленная карта ключей/QR/KDF: [CURRENT_IMPLEMENTATION.md](CURRENT_IMPLEMENTATION.md); текущая очередь реализации: [IMPLEMENTATION_BACKLOG.md](IMPLEMENTATION_BACKLOG.md). Android и Desktop пользователь выбрал разрабатывать параллельно. Плановый аудит не означает готовое приложение или закрытие перечисленных проблем.

## Область и ограничения проверки

Указанный в чате каталог /home/jcode/D-MASH отсутствует. Найденный D-MASH-Gamma содержит ценный незакоммиченный WIP и старый HEAD; он оставлен без изменений. Для аудита создан отдельный checkout /tmp/dmash-repository-audit-20261020 с актуальной опубликованной веткой transport-v3. Ветка main остаётся на сентябрьской версии и не использовалась как текущая реализация.

Проверены структура всего tracked tree, ключевые пути каждого подсистемного слоя, актуальный handoff, тестовая инфраструктура, deployment/installer, зависимости и фактические зависимости UI Telegram. Критичные пути отдельно разбирались по архитектуре, безопасности и интеграции. Это архитектурный и исходный аудит с выборочной подробной проверкой, а не построчное независимое криптографическое заключение.

Продакшен, реальные Accounts, ключи и базы не менялись. Не запускались installer/deploy, Telegram builds и приёмка на физическом Android. Свежие browser-проверки выполнялись локально на синтетических данных. Ранее записанные DEPLOYED PASS из CURRENT_HANDOFF рассматриваются как исторические свидетельства в их точном scope.

Сводка свежих запусков и ссылки на локальные evidence: [evidence.json](evidence.json). Результат тестов не означает закрытие всего N0–N8.

Свежий полный runner после установки недостающей тестовой зависимости завершился с exit 0: **293 backend-теста, 11 Origin-тестов и 148 JavaScript suites PASS** на Python 3.12.3 / Node 24.19.0. Отдельный real Worker transit browser test также завершился exit 0. Первый запуск с отсутствующим fake-indexeddb сохранён как FAIL среды; product source между запусками не менялся.

Ограниченный локальный UI smoke использует настоящие UI actions, crypto и IndexedDB: calculator setup/unlock, Account login, отправка в Saved Messages, reload, повторный unlock/login и восстановление одной видимой записи без дублирования. Service Workers в этом ручном профиле заблокированы, поэтому update warning ожидаем; это не проверка active SW или production. Полный обход каждого control, текущие PUBLIC/PRIVATE browser flows, звонки/файлы, физическое устройство и полная N4 fault matrix в этом аудите не повторялись.

## Карта репозитория

Всего 766 tracked файлов. Подсчёт строк ниже исключает vendor и tests; он показывает объём кода, не качество.

| Область | Реализация | Размер / назначение |
|---|---|---|
| Browser runtime | D-MASH PWA/not_messenger/js | 100 собственных JS-файлов, 21 802 строки; Account, crypto, storage, Node host, media, UI и compatibility |
| Python Node | D-MASH/client/backend | 49 Python-файлов, 10 166 строк; authenticated transport, admission, routing, persistence, S-TURN |
| Notifications | origin | 3 runtime Python-файла, 624 строки; отдельный Origin и vault ботов |
| Tests | client/tests, not_messenger/tests, origin/tests | 293 backend-теста, 11 Origin-тестов, 148 JS suites в обнаруженном runner scope |
| Harness / операции | tools | 100 Python/CJS/MJS-файлов, 5 200 строк; browser fixtures, QA, верификация, deployment |
| Legacy PHP | D-MASH PWA/api | Отдельные relay/webhook endpoints; другая модель авторизации и приватности |
| Документы | корень, docs/evidence, docs/archive | Спецификации, handoff и значительный объём исторических свидетельств |

В самом browser runtime Core занимает 3 736 строк, runtime_fixes — 820, acceptance_v50 — 797. Это указывает, где особенно важны границы модулей и порядок сборки.

## Сильные стороны

1. **Node и Account имеют разных владельцев ключей и жизненного цикла.** Worker загружает Node identity/admission/routing/local ownership, а не Account UI. Независимый Node seed хранится за локальным root. Account logout и полный root lock различаются. Это правильная основа полноценного локального узла.
2. **Реальный v4 transit уже работает.** В свежем локальном Chromium-тесте два Python Nodes имели единственный путь через browser Worker. У B не было Account runtime и ключей конечных участников; проверены discovery, замена hop labels, opaque payload, late binding, deferred local Inbox и закрытие по root lock.
3. **Есть конкретные механизмы надёжности.** Account outbox сохраняет зашифрованные intent до отправки, использует стабильные operationId и CAS; получатель подтверждает durable commit; sender завершает запись по проверенному receipt. Есть проверки Account generation вокруг async операций.
4. **Handshake выражен состояниями и подтверждает ключи.** INIT/FINAL/CONFIRM/ACK, transcript/context binding, collision policy и authenticated recovery реализованы отдельно. V4 действительно использует fresh X25519 и KEM contributions; suite явно обозначен как legacy Kyber, без ложного ML-KEM claim.
5. **Защита storage и границ не декоративная.** memory-hard root wrap (фактически legacy Argon2d из-за enum mismatch, см. ниже), AES-GCM, owner/context checks, Web Lock для Node, opaque capability handles и отказ пересоздавать root при ошибке unwrap — полезные реализованные механизмы.
6. **Существенная тестовая база.** Проверяются replay/ownership, loss/retry, asynchronous lifetime и реальные browser/Node границы. Существующий Python legacy HTTP router целиком закрыт dependency guard с HTTP 410, что подтверждают и тесты.

Опорные исходники: [Node Worker](https://github.com/Seriy615/D-MASH/blob/9446c22f27309131456942870971d477f6f2358f/D-MASH%20PWA/not_messenger/js/node_runtime_worker_v4.js#L2), [Node identity](https://github.com/Seriy615/D-MASH/blob/9446c22f27309131456942870971d477f6f2358f/D-MASH%20PWA/not_messenger/js/node_identity.js#L51), [Account outbox](https://github.com/Seriy615/D-MASH/blob/9446c22f27309131456942870971d477f6f2358f/D-MASH%20PWA/not_messenger/js/account_app_outbox_v4.js#L59), [session](https://github.com/Seriy615/D-MASH/blob/9446c22f27309131456942870971d477f6f2358f/D-MASH%20PWA/not_messenger/js/account_session_v4.js#L26), [root wrap](https://github.com/Seriy615/D-MASH/blob/9446c22f27309131456942870971d477f6f2358f/D-MASH%20PWA/not_messenger/js/device_root.js#L220), [retired HTTP guard](https://github.com/Seriy615/D-MASH/blob/9446c22f27309131456942870971d477f6f2358f/D-MASH/client/backend/api.py#L17).

## Приоритетные слабые места

P1 — закрыть до широкого распространения нового клиента или до соответствующего обещания. P2 — включить в ближайшие этапы. Отдельно указано, что доказано исходниками, а что требует динамической проверки.

### P1. Быстрый verifier мастер-кода позволяет дешёвый offline-перебор

ui_logic сохраняет sys_m как обычный SHA-256 master PIN, допускает минимум четыре цифры и использует этот verifier также в путях изменения кода. Memory-hard Argon2 защищает root wrap (фактический тип — Argon2d, несмотря на label), но атакующий с копией localStorage может сначала найти PIN по дешёвому verifier и затем попробовать его к root.

Это не утверждение, что одного master PIN достаточно для расшифрования каждого Account vault: Account credentials и сохранённые session/history keys имеют отдельные границы. Конкретный дефект — утрата стоимости KDF при проверке локального master secret.

Доказательство: [запись verifier, строка 404](https://github.com/Seriy615/D-MASH/blob/9446c22f27309131456942870971d477f6f2358f/D-MASH%20PWA/not_messenger/js/ui_logic.js#L404), проверка 416/442–443, повторная запись 433, raw SHA-256 506–509. Изолированный перебор синтетического четырёхзначного PIN потребовал не более 10 000 SHA-256; реальные профили не читались.

План: единая versioned KDF/wrap-проверка во всех master/repair/emergency путях, миграция без смены root/Node/Account identities, подтверждённый backup/restore. Даже после этого короткий PIN имеет ограниченную энтропию.

### P1 совместимости и корректности crypto profile. Argon2id label фактически вызывает Argon2d

Дополнительная проверка плана исполнила настоящий bundled JS/WASM: `argon2.argon2id` отсутствует, `ArgonType.Argon2id` равен 2; вызов с undefined type совпадает с explicit Argon2d, отличается от Argon2id и возвращает encoded `$argon2d$`. Так вызывают KDF текущие DeviceRoot wrap и Account boot. Иной `node_admission_v4` уже выбирает explicit enum и не должен ошибочно попасть под ту же миграцию. [Actual vendor evidence](verification/actual-argon2-results.json), [воспроизводимый runner](verification/check_actual_argon2.cjs).

Это исправляет раннее заключение аудита об эффективном Argon2id: source labels и тестовые stubs оказались недостаточны. Исходный full runner PASS остаётся фактом, но не обнаруживал этот dispatch defect. Сам факт использования memory-hard Argon2d не является доказанным извлечением ключей; риск здесь также в неверных security claims, межплатформенной несовместимости и разрушении доступа при наивном исправлении enum.

План: зафиксировать legacy Account/root derivation vectors, ввести versioned root-wrap profile с реальным Argon2id и переобернуть **тот же root**; не изменять детерминированные Account ключи молча. После миграции требуется retained identity/history, wrong PIN/corrupt profile/reload/crash test с настоящим vendor, а не mock enum. [Fix design](verification/MASTER_SECRET_FIX_DESIGN.md).

### P1. V4 сетевой durable mailbox существует как foundation, но не включён в runtime

Локальный encrypted Inbox браузера и durable outbox отправителя реализованы. Постоянное серверное хранение v4 — отдельная функция.

[node_mailbox_v4.py:1–9](https://github.com/Seriy615/D-MASH/blob/9446c22f27309131456942870971d477f6f2358f/D-MASH/client/backend/node_mailbox_v4.py#L1) прямо описывает inactive store; runtime его не импортирует. [node_store_profile_v4.py](https://github.com/Seriy615/D-MASH/blob/9446c22f27309131456942870971d477f6f2358f/D-MASH/client/backend/node_store_profile_v4.py#L1) — неактивный codec без полного issuance/replay ledger. [NodeServiceV4:95](https://github.com/Seriy615/D-MASH/blob/9446c22f27309131456942870971d477f6f2358f/D-MASH/client/backend/node_service_v4.py#L95) компонует relationships/routing/listener без этого mailbox. Router вынимает batch из RAM перед отправкой и удаляет peer при send failure: [Python:138](https://github.com/Seriy615/D-MASH/blob/9446c22f27309131456942870971d477f6f2358f/D-MASH/client/backend/node_routing_v4.py#L138).

Следствие: подтверждённая доставка при offline получателя пока зависит от сохранённого outbox и возвращения отправителя. Нельзя обещать полноценную доставку из независимой серверной очереди после ухода sender.

План: подключить store через проверяемые grants/owner proof, expiry/quota/replay, миграцию прежнего владения и согласованный lease → send → delete lifecycle. Стабильный logical operationId и Account receipts остаются над mailbox. Нельзя молча заменить существующий контракт обязательным client ACK.

### P1. Managed-v4 не имеет непрерывного supervision соединений

После disconnect socket/channel закрывается, router удаляет peer. Host не передаёт peer-state event в lifecycle, а [node_root_lifecycle_v4.js:12](https://github.com/Seriy615/D-MASH/blob/9446c22f27309131456942870971d477f6f2358f/D-MASH%20PWA/not_messenger/js/node_root_lifecycle_v4.js#L12) продолжает возвращать fulfilled start promise той же root session; READY установлен при первоначальном connect. Coordinator проверяет lifetime root/host, а не реальную связность.

Это подтверждённый исходниками gap opt-in managed-v4, не воспроизведённая неисправность текущего production. В legacy DeviceClientV3 есть свой рабочий backoff; его наличие не закрывает новый lifecycle.

План: один supervisor в Node owner, события disconnected/degraded/ready, bounded retry с jitter, повторная admission и восстановление route/grant по правилам. Account retry не должен владеть reconnect Node.

### P1 для security claims. V4 session cipher пока не даёт per-message ratchet

[account_app_cipher_v4.js:33](https://github.com/Seriy615/D-MASH/blob/9446c22f27309131456942870971d477f6f2358f/D-MASH%20PWA/not_messenger/js/account_app_cipher_v4.js#L33) выводит directional AES-GCM key из session root, а строка 47 использует свежий nonce. Message-key chain с продвижением и удалением старого ключа нет. [account_session_v4.js:30](https://github.com/Seriy615/D-MASH/blob/9446c22f27309131456942870971d477f6f2358f/D-MASH%20PWA/not_messenger/js/account_session_v4.js#L30) возвращает ESTABLISHED без автоматического rekey по времени/числу сообщений.

Раскрытие текущего session root позволяет читать записанные сообщения этой сессии. Свежий X25519/KEM при новом handshake/recovery — реальная сильная сторона, но не автоматическое восстановление секретности после компрометации и не Double Ratchet.

План: отдельно специфицировать compromise/retention модель, условия rekey и невозможность восстановления при постоянном контроле endpoint. Сначала честно описать текущие гарантии; новую ratchet схему не изобретать в ходе переноса UI. Нужны независимый crypto review и compromise tests.

### P2. Legacy Accounts связываются общим installation KEM public key

[core_engine.js:373–387](https://github.com/Seriy615/D-MASH/blob/9446c22f27309131456942870971d477f6f2358f/D-MASH%20PWA/not_messenger/js/core_engine.js#L373) берёт Kyber keypair из installation-wide deviceMaterial и включает один public key в bundle разных Accounts. V3 contact bootstrap передаёт bundle контакту, строка 3179. Сговорившиеся контакты способны сопоставить Accounts на одной установке по этой части bundle.

Замечание относится к legacy/migration path. V4 использует отдельный AccountStaticKemV1. Миграция требует сохранить способность читать старое состояние, а не просто удалить старый материал.

### P2. Композиция runtime зависит от последовательности patches

[release.js:5](https://github.com/Seriy615/D-MASH/blob/9446c22f27309131456942870971d477f6f2358f/D-MASH%20PWA/not_messenger/js/release.js#L5) по умолчанию выбирает legacy-migration. Далее loader последовательно подключает v3, runtime_fixes, несколько acceptance_vNN, затем v4. В них действительно устанавливаются wrappers и polling hooks.

Это создаёт скрытый dependency graph и усложняет подключение второго клиента. Нельзя просто экспортировать весь window.Core как SDK.

План: один composition entrypoint, зависимости через platform interfaces, поведение постепенно переносить в модуль-владелец. Compatibility adapter должен быть явным и ограниченным. Существующий код не переписывать целиком.

### P2. Обычная конфигурация зависит от одной Node

[managed_node_catalog_v4.js:3–10](https://github.com/Seriy615/D-MASH/blob/9446c22f27309131456942870971d477f6f2358f/D-MASH%20PWA/not_messenger/js/managed_node_catalog_v4.js#L3) содержит одну pinned EMS запись. Router допускает до восьми peers. Один сосед не обеспечивает транзит между двумя соседями или независимый failover.

План: отделить проверяемое provisioning/catalog от runtime, поддержать несколько независимо pinned entries и бюджет соединений. DHT не добавлять. Политика приватности и минимальное раскрытие topology требуют отдельного review.

### P2. Media v4 и большие файлы не готовы в объёме Telegram

[node_account_ui_v4.js:12](https://github.com/Seriy615/D-MASH/blob/9446c22f27309131456942870971d477f6f2358f/D-MASH%20PWA/not_messenger/js/node_account_ui_v4.js#L12) явно блокирует медиа для migrated peers. В [orchestrator:109](https://github.com/Seriy615/D-MASH/blob/9446c22f27309131456942870971d477f6f2358f/D-MASH%20PWA/not_messenger/js/public_account_orchestrator_v4.js#L109) FileRuntime должен объявить nodeControlAuthorityV4, которого текущий export не предоставляет.

Рабочий текущий file transport ограничен 64 MiB, накапливает буферы и объявляет resumable:false. Существующие legacy звонки/записи/файлы не равны завершённой v4 интеграции.

План: capabilities управляют UI; сначала text/contact вертикальный сценарий, затем real TURN, файлы с integrity/cancel/expiry, отдельно streaming/resume и физический Android. Кнопки Telegram не должны изображать отсутствующие возможности.

### P2. SDK нужны ограничения размера отказа и справедливое выполнение

AccountSessionRuntime последовательно await-ит peers; discovery может ждать 30 секунд. Это риск задержки независимых контактов, а не новый измеренный latency FAIL. Host сводит многие ошибки к одному сообщению; один RPC deadline может закрыть весь Node host.

Опорные места: [account_session_runtime_v4.js:63](https://github.com/Seriy615/D-MASH/blob/9446c22f27309131456942870971d477f6f2358f/D-MASH%20PWA/not_messenger/js/account_session_runtime_v4.js#L63), [node_runtime_host_v4.js:47/70](https://github.com/Seriy615/D-MASH/blob/9446c22f27309131456942870971d477f6f2358f/D-MASH%20PWA/not_messenger/js/node_runtime_host_v4.js#L47).

План: per-peer serialization при ограниченной параллельности разных peers, типизированные ошибки, различие request cancellation и повреждения actor. Сохранить Account/root fencing.

### P2. Воспроизводимость, supply chain и лицензии требуют доведения

- На чистом checkout documented Python setup не устанавливает fake-indexeddb, который шесть JS suites импортируют напрямую. Первый полный запуск завершился FAIL только в этих шести suites; установленная отдельно версия 6.2.6 и NODE_PATH позволили выполнить исправленный запуск без изменения product source.
- Единственный workflow — CodeQL для push/PR main; рабочая ветка transport-v3 не получает такой gate. Полный test runner, interop/vendor/secret checks в tracked CI отсутствуют.
- Python зависимости pinned напрямую, но транзитивного lock с hashes нет. Свежий pip-audit нашёл 27 записей advisory в FastAPI 0.109.0, python-multipart 0.0.18 и Starlette 0.35.1: после удаления повторяющихся ID — 14 advisory. Совпадение версии не доказывает достижимость каждого exploit. Например, multipart path traversal требует нестандартной конфигурации, а часть DoS касается form parsing. Полный reachability review и совместимое обновление нужны отдельно.
- Vendor Kyber JS/WASM не имеет в tracked tree собственного source/build recipe/upstream revision/license/vectors. Воспроизводимый vendor build сейчас есть для BLAKE3. Это пробел происхождения, не доказательство уязвимости конкретного бинарника.
- README говорит MIT, но корневого файла LICENSE в tracked tree нет. Нужно оформить лицензию собственного кода и inventory third-party notices до распространения SDK/клиентов.

Первичные advisory: [Starlette multipart DoS](https://github.com/Kludex/starlette/security/advisories/GHSA-f96h-pmfr-66vw), [python-multipart non-default configuration](https://github.com/Kludex/python-multipart/security/advisories/GHSA-wp53-j4wj-2cfg).

### P2. Установка и документация расходятся с текущим продуктом

[install-node.sh:12](https://github.com/Seriy615/D-MASH/blob/9446c22f27309131456942870971d477f6f2358f/install-node.sh#L12) по умолчанию устанавливает pinned commit 20a5eb27 от 31 августа 2026. Immutable pin полезен, но это не текущая .38. Выбранная интерактивно VISIBILITY не используется при записи env: строка 83 читает DMASH_NODE_VISIBILITY заново с default public; private password integration сам скрипт считает отсутствующей. Installer не запускался.

README всё ещё называет .24 последним runtime; CURRENT_HANDOFF и release.js уже описывают .38. Это мешает новому разработчику воспроизвести именно текущую систему.

План: один проверяемый release manifest, versioned installer с актуальной acceptance, корректный config migration и smoke на чистой VM. Работа от service user в installer уже предусмотрена. Историческую запись о root в production нельзя выдавать за свежую инвентаризацию хоста.

## Отдельные поверхности и границы приватности

- **Python legacy HTTP** в текущем коде закрыт HTTP 410; не повторять устаревшее утверждение «публичный login открыт» без проверки.
- **PHP relay/webhook** остаётся отдельным кодом вне этого guard. В нём статический X-DMASH-AGENT не является секретом, а Telegram binding имеет другую authority-модель. PWA содержит explicit legacy mode и соответствующие fetch. Не проверялась фактическая публикация PHP; это inventory/exposure question, не подтверждённый production exploit.
- **Transit content** непрозрачно, но forwarding сохраняет payload при смене hop label. Сговорившиеся узлы могут сопоставлять ciphertext; IP, время, размер и availability также остаются наблюдаемыми. Общая роль NODE не доказывает endpoint anonymity.
- **WebRTC** и TURN — отдельный media plane. Direct ICE может раскрывать сетевые адреса; relay ограничивает раскрытие собеседнику, но сам relay знает подключившиеся endpoints.
- **Origin/Telegram notifications** отделены от Node secrets и могут передавать нейтральное событие вместо сообщения. Но provider видит связанные служебные идентификаторы и timing; «ничего не знает» было бы чрезмерным обещанием.
- **Hosting/update/supply chain** входят в доверенную базу браузерного клиента. Вредоносный same-origin JavaScript во время unlock может получить доступ к plaintext/keys. Worker и encryption-at-rest эту угрозу не устраняют.
- **Account password** способен восстановить детерминированную identity, но не заменяет backup случайного installation root, session material, KEM и локальной истории.

## Текущее состояние по областям

| Область | Оценка |
|---|---|
| JS/Python Node auth, directional relationships, routing | Реализованная основа; свежий локальный no-bypass Worker transit PASS |
| Local encrypted Inbox, locked slots, root shutdown | Реализованы; полная migration/crash матрица не закрыта этим аудитом |
| Account handshake, durable text intent, receipts | Реализованы; полный recovery/collision/restart scope остаётся отдельной приёмкой |
| V4 network durable store-and-forward | Foundation существует, runtime integration отсутствует |
| Ordinary v4 migration/default cutover | Частично; default profile ещё legacy-migration |
| Unified v4 calls/files | Частично; текущие legacy media не считать полным v4 |
| Переносимый native Account SDK | Пока отсутствует; есть подходящие внутренние API |
| Автоматическая per-message PFS/PCS | Не следует из текущей session cipher реализации |
| Стандартный ML-KEM conformance | Не доказан; suite честно обозначает legacy Kyber |
| Endpoint anonymity | Не доказана; известны корреляционные ограничения |

## Основа для следующей отдельной документации и модели угроз

Следующий документ должен описывать именно этот проверенный режим работы, отдельно от целевых N0–N8.

Нужны: карта модулей/owner, formats/wire/state machine, identity и KDF domains, root/Account/node lifecycle, durable commit/receipt semantics, recovery/backup/migration, media/notifications, operational deployment и таблица реализованных/планируемых гарантий с test evidence.

В модели угроз зафиксировать активы: plaintext/history, root/Account/Node/session keys, pairing contributions, route/mailbox authority, metadata и availability. Противники: сетевой наблюдатель; malicious/colluding Nodes; получатель с враждебными payload; похититель locked storage; временная компрометация session root; постоянная компрометация endpoint; hosting/update/dependency compromise; notification provider; злоупотребление CPU/PoW/queues.

Для каждого: какие данные он видит, какие полномочия получает, защита, известный остаточный риск, воспроизводимая проверка. Отдельно описать разницу «вышел из Account», «заблокировал устройство», «приложение уснуло», «процесс остановлен», «восстановился из backup». Это план и собранная фактура, а не заявление, что полная документация уже написана.
