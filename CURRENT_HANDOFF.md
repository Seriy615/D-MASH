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

## 2. Текущий Forge и EMS checkpoint

**Source:** Forge `/home/jcode/D-MASH`, ветка `transport-v3`; exact deployed
product source `be6a1d9a58ba9fffeb0daad234a6506e5b269667` сверен с Forge
`origin/transport-v3`. Новейший tip ветки после
обновления документации проверять через `git rev-parse origin/transport-v3`.
Интеграция выполнена в отдельном worktree; shared checkout содержит WIP агентов
и не является release tree. Отправка Git — обычный fast-forward через временный
EMS publisher, Forge origin SHA сверен. Исторические состояния до `.30`
[архивированы](docs/archive/2026-10-08/CURRENT_HANDOFF_PRE30_SECTIONS_2_3.md).

**Production PWA:** EMS `get_commit.sh` развернул exact `be6a1d9...` с
page и active controlling SW `transport-v3-node-preparation-20261008.31`.
Backup PWA: `/srv/messenger.d-mash.ru/backups/manual-rollback-20261008T050352Z`.
На текущем EMS каталог `/home/jcode/D-MASH` существует, но системного пользователя
`jcode` нет: `su - jcode` отказал. Проверен и запущен тот же штатный
`get_commit.sh` от root с scoped Git `safe.directory`, как требует его
`sudo` usage; script сам создал backup, проверил nginx и публичные assets.
Read-only exact verifier: **258/258 source files**, `missing=[]`, `changed=[]`.
Node backend не менялся при `.31`; предыдущие согласованные S-TURN/Node
конфигурация, identities и базы сохранены. После `.30` PWA deploy реальные
authenticated TURN UDP/TCP relay и WSS scoped tickets/signaling были PASS;
на `.31` независимый browser снова передал voice/circle через EMS S-TURN.
Новый backend/runtime migration из Forge source автоматически не следует.

**Тесты `.31` source:** Python **286**, Origin **11** и все JS suites
`tools/test_all.py` PASS с Python3.12/Node24.19.0, включая MIME и captured
recorder/chat alias suites. Первый запуск не имел `node` в `PATH` и не смог
запустить часть тестов; полный повтор с Node24 завершился exit0. В synthetic
Chromium/IndexedDB history-counter fixture PASS: сохранение счётчика при 0x01/0x03,
запрет перезаписи занятого alias, atomic CAS, fail-closed на чужих/неполных
строках. Initial 0x01 раньше обнулял `msgCount` при оставшихся ciphertext —
реальный дефект воспроизведён и закрыт для новых переходов.

**Реальный тестовый Account пользователя в CDP9449:** обновлён на `.30` без
reset. ID, pairing contribution и контакт неизменны. Перед ручной операцией
сделан protected encrypted raw-vault backup вне Git (`0600`); read-only proof
подтвердил ровно три непрерывные принадлежащие этому чату зашифрованные строки
и `msgCount=0`. Guarded CAS поднял только счётчик до 3; ciphertext сообщений
и peer-row остались побайтно прежними. Все три строки снова видны в UI,
входящее audio расшифровывается по реальной кнопке. Одна отправка реальной
кнопкой SEND добавила seq4, старые строки сохранены. Статус **SENT**, не
аутентифицированное DELIVERED/READ; ответа собеседника пока нет. Не повторять
отправку автоматически на основании одного этого статуса.

**Баг пользователя `readAlias`/«Запись не отправлена»:** реальный fresh
source-overlay `.31` browser до исправления воспроизвёл задержанный modal
`Cannot read properties of undefined (reading 'getAlias')` после записи и
перехода в «Избранное». Запись уже сохранялась в encrypted pending intent;
ошибка возникала при добавлении истории через captured vault, которого нет
в WeakMap `DmashChatPassword`. Исправлен `location` для собственного guarded
alias snapshot и сохранён парольный L3 alias. Простой `install(vault)` вызвал бы
вложенный shared history lock. Предыдущий `.30` MIME parser также отвергал
допустимые параметры MediaRecorder; `.31` исправил его без изменения байтов
записи. Никакой reset реальных Account/keys не выполнялся.

**Независимая deployed `.31` browser acceptance:** два новых synthetic PRIVATE
Account, реальные QR/[+]/key exchange/text/voice/circle/Saved/reload UI actions
**22/22 PASS**. Page и active controlling SW `.31` до/после reload,
**268/268** загруженных файлов exact `be6a1d9...`, ошибок страницы/консоли 0.
Audio/mp4 29,565 B и circle 162,353 B прошли durable intent → EMS S-TURN →
receiver decrypt/playback; sender увидел два authenticated DELIVERED, сохранил
по одному voice/circle в истории обеих сторон после Master+Account reload,
освободил retained media bytes. Задержанный FileReader завершился при открытом
«Избранном» без modal. Это media/alias приёмка, не полный Node/N4 DONE.

**Предыдущая `.29` independent deployed acceptance:** 27/27 continued actual
controls PASS для public Request/Accept/Confirm, текста, трёх voice notes,
кружка, offline/reload/retry и защищённого удаления чата; page/active SW `.29`,
206 loaded responses exact `5a2439834a2fc22db8f6ecd0b9674d533397ea8a`.
Это v3 migration path и N4 safety-only, не ordinary Node DONE. Дополнительный
fresh `.29` browser-first проход: calculator 24/24, Account lifecycle 9 PASS/1
FAIL, Saved Messages/media/master 27/27, Node remove-retry 6/6 PASS. Отдельный
1 MiB+13 B реальный file transfer — sender показывает «Передано и проверено»,
receiver `File channel failed`: P1 N7 bug открыт. Account remove UI обещает
стереть всю историю, но повторное создание того же synthetic Account показывает
старое сообщение: `ACCOUNT-DELETE-01` открыт; production данные не удалялись.
Полная матрица и ограничения — [BROWSER_QA.md](BROWSER_QA.md).

**Backend S-TURN:** EMS capability `DMASH_CAN_S_TURN=1`,
`DMASH_CAN_RELAY_BLOB=1` только при реальном health. Предыдущие protected
backend snapshots `/root/dmash-runtime-backups/sturn-gateway-gate-20261008T034751Z`
и `/root/dmash-runtime-backups/backend-exact-20261008T035123Z` вне Git;
три SQLite quick_check и identity hashes были проверены при обновлении.
`.31` не изменил Node backend/DB/keys. Production exact Node profile —
`wss://stage-api-ems.d-mash.ru/mesh/v4` с отдельно проверенным NodeID pin;
старый `/dmp-c/v3` остаётся временным migration path, не скрытым fallback.

## 3. Реальный прогресс и незакрытые блокеры

Unified Node foundation и реальный Python→browser→Python transit уже есть.
Новый изолированный **Core/public→NodeHost→N4→AppCipher/history** synthetic
Chromium прогон exact candidate `0274789...` PASS: signed public pairing,
post-ACTIVE restart, two-party confirmed N4, encrypted text с durable history,
Account switch/root reopen; 100 source hashes unchanged. У него пока
presentation stub: обычный production Account/contacts/chat UI **не** переведён
на NodeRuntimeHostV4. Existing contact/state/mailbox authenticated migration,
locked Account, receipt-backed durable outbox и запрет v3 fallback остаются
обязательными для N3. Агент продолжает isolated UI/loader cutover; интеграцию
и browser/deployed acceptance проверяет лид отдельно.

Изолированный full-shell UI candidate `46c67477...` проверен настоящими
кнопками на сохранённых synthetic профилях: managed Node пережила Account logout,
публичный запрос появился в глобальной панели до Account login, существующий
Account принял и подтвердил его; 10 этапов продолжения PASS. Ранее обнаруженный
повторный `CONNECT` к уже authenticated Node устранён с idempotent reuse только
того же URL/peer и fail-closed password repeat. Проверка остановилась на busy
deadline кнопки «Завершить обмен ключами»; N4/text/history в full-shell ещё
**NOT RUN/PASS**. Browser process уже не жив после остановки агента; повтор
должен использовать сохранённые данные и отдельный QA checkpoint, не reset.

Полный N4 recovery **не завершён**. Новый genuine two-Worker/Python loss fixture
прошёл lost FINAL/ACK-only и restart, но при one-sided state loss застрял:
requester `INIT_PREPARED`, responder `RESPONDER_PENDING`, финального
подтверждения нет. Агент собирает read-only wire/Inbox forensic trace того же
точного сценария, затем исправит доказанную причину. Node Inbox `seen`
tombstone не позволяет выдавать повтор старого application envelope за новый
доставленный ACK; нужен аутентифицированный bounded ACK request/replay либо
эквивалентное durable решение, без удаления tombstone или повторного seal.
Изолированный ACK/outbox candidate `387e9e71...` имеет synthetic UNIT для
authenticated receipt, lost ACK replay и fault/crash ordering, но не прошёл
same-grant real browser. Pending intent пока требует уже `ESTABLISHED` N4:
первое сообщение новому offline peer ещё не может быть поставлено в durable
ожидание. При rekey pending outbox fail-closed, authenticated migration не
реализована. Этот candidate не интегрирован и не опубликован.

N0 endpoint/privacy и threat model, N2 no-bypass failover на текущем SHA,
N5 verifier/legacy exposure/PCS/PQ/security, N6 password/installer, N7 file/call
полная приёмка и N8 migration/rollback/полный UI01–UI14 остаются PARTIAL.
`CURRENT_HANDOFF.md` и [BROWSER_QA.md](BROWSER_QA.md) обновлять на следующем
checkpoint по фактам, не подменяя deployed результат UNIT или synthetic PASS.

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

Текущую `.27` PWA проверять на exact commit следующими командами. Browser
harness создаёт fresh synthetic Accounts, не читает пользовательские vaults;
Node/Playwright/Chromium paths должны соответствовать текущему окружению.

```bash
python3 tools/verify_ems_revision.py 637c9bb02c2c57a05e8edc815678b6fb204f632c
DMASH_EXPECT_SHA=637c9bb02c2c57a05e8edc815678b6fb204f632c \
DMASH_EXPECT_RELEASE=transport-v3-node-preparation-20261008.27 \
DMASH_CHROME=/absolute/path/to/chromium \
DMASH_PLAYWRIGHT_MODULE=/absolute/path/to/playwright \
node tools/qa_ui_hotfix.cjs
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
