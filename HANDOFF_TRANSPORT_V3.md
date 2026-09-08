# D-MASH transport-v3 — общий HANDOFF

Дата: 2026-09-08. Ветка: `transport-v3`.
База: `703a5df` (`main`). Репозиторий: `git@github.com:Seriy615/D-MASH.git`.
Рабочий checkout: `/Users/afsvu/Documents/Codex/D-MASH/D-MASH`.

Это промежуточный checkpoint по отдельному запросу пользователя: написать
HANDOFF и запушить текущее состояние. **Ветка ещё не готова к production.**
Push этого checkpoint не является разрешением считать исходную задачу
завершённой или запускать deployment до завершения оставшейся приёмки.
Полный hash checkpoint нужно брать из `git rev-parse HEAD`; hash и результат
push сообщаются пользователю после коммита, чтобы не создавать самоссылку.

## Задание и последнее уточнение пользователя

Исходный запрос — большой рефакторинг Account / Device / DMP-C / Mesh,
DNSS mailbox, control-plane authority, hop-local labels, batching 500 ms,
password Nodes, S-TURN/coturn, calls/files, epoch ratchet, тесты и deployment.
Подробный executable baseline и wire specification: `TRANSPORT_V3.md`.

Последнее уточнение обязательно сохранить:

- Account RouteID на устройстве хранится как **слепой алиас** для определения
  Account slot. Не сохранять raw Account RouteID в Device lookup или pending
  Inbox record, даже просто внутри зашифрованного JSON.
- Account шифрует пакет до получателя и передаёт Device непрозрачный payload.
- Device добавляет Device Envelope, выбирает Node и выполняет транспорт.
  Account peer association остаётся в Account Vault.
- Не возвращать AccountID в транспортный locator/KDF/Node mailbox.

Не было посторонних незакоммиченных изменений в исходном checkout. AGENTS.md
не найден. Исторический текст про оркестратора в ROUTING_UPDATE.md не был
использован как разрешение запускать агентов. Субагенты не запускались.

## Готово и проверено

### A — аудит и воспроизводимые проверки: IMPLEMENTED

Изучены код, README, текущие/исторические handoff, routing update, installer.
Зафиксированы прежние DMP-C v2, односторонний Node handshake, старый mailbox,
DNSS/EntryGrant/PoW, public/private routes, WebRTC и installer.
Добавлен `tools/test_all.py`: Node backend, Origin и каждый PWA `*.test.js`.
Он продолжает прогон после ошибки и выдаёт итог по всем наборам.

### B — secure transport: IMPLEMENTED, общая приёмка PARTIAL

- Общие Python/JS DMP-C v3 handshake и encrypted record primitives.
- Роли DEVICE/NODE явно включены в подписываемый transcript; capability
  surfaces разделены. NODE не получает DEVICE permissions.
- Свежий ephemeral X25519, SHA-256 transcript, HKDF, раздельные send/receive
  SecretBox keys. Nonce содержит sequence; replay/out-of-order closes session.
- Ed25519 взаимная аутентификация; роли, ключи, challenge и expiry проверяются.
- Формат IKM имеет domain/length framing для будущего combiner, но ML-KEM в
  этом handshake **не реализован**. Заявлений о PQ security нет.
- Python `SecureSocket` удерживает send lock на выделении sequence и await
  отправки. Закрытие очищает mutable key buffers; managed-runtime копии не
  гарантированно стираются.
- Node↔Node подключён к v3. Старого handshake fallback в peering нет.
- PWA NodeManager использует DeviceClientV3, а не plaintext v2 socket sends
  для новых соединений. Старые методы остаются для исторических тестов/кода;
  backend v3 runtime запрещает обход через прежние resource operations.
- Реальный loopback WebSocket тест запускает JS клиент и NodeManager против
  Python ASGI gateway: handshake, encrypted STATUS/PING, pin mismatch, cleanup.

Gateway: `/dmp-c/v3`, также `/dmash-client/v3` для proxy-facing пути.
WELCOME сообщает NodeID для derivation Device identity; доверие появляется
только после проверки того же NodeID в signed challenge. Настроенный pin
обязателен при наличии. WSS остаётся внешним транспортом.

Wire: WELCOME → HELLO → CHALLENGE → AUTH → encrypted AUTH_OK; затем SECURE
records. AUTH_OK сообщает роли, capability list и resource PoW difficulty.
Точные canonical bytes, domains, ограничения и key split — в TRANSPORT_V3.md.

**Не менять без миграции** существующий контекст Device transport key
derivation `DMP-C|2|NodeID`: он сохраняет прежнюю стабильную Device identity.
Версия wire уже 3; смена derivation context поменяет durable mailbox owner.

### C — DNSS и resource authority: IMPLEMENTED, lifecycle UI PARTIAL

- Device DNSS сохраняется в encrypted DeviceRoot material `dnss/v1/NodeID`.
  При reconnect новый socket повторно связывается с тем же DNSS.
- Node registration runtime-only; после restart клиент получает
  DNSS_NOT_REGISTERED, повторяет work для того же DNSS и регистрирует маршруты.
- Node↔Node имеет независимые local_dnss / remote_dnss и независимые PoW.
- PUBLIC: session + DNSS + Route proof + valid Node-bound EntryGrant,
  generation/expiry + work при новой/изменённой регистрации.
- PRIVATE: direction-derived signing capability и PRIVATE_ROUTE work;
  публичный EntryGrant не требуется. Pairing/root secret на Node не передаётся.
- Proof подписывает NodeID, session hash, DNSS, operation, request id,
  route, authority key, kind, generation, expiry. Replay/owner mismatch rejected.
- START_PROBE и UNREGISTER требуют authority существующей регистрации.
- Mailbox insertion повторно проверяет, что route authority ещё действует.

В UI удаления/деактивации исторических private routes ещё нужно закончить
миграцию к v3 UNREGISTER_ROUTE. Backend ownership gate уже реализован.

### D — durable DNSS mailbox: IMPLEMENTED, legacy migration PARTIAL

- Отдельная SQLite `mailbox_v3.db`: delivery_id, blind_dnss, ciphertext,
  timestamps/size/lease. Raw DNSS/RouteID в таблице отсутствуют.
- Durable alias — HMAC с отдельным domain, включает DNSS и authenticated Device
  transport key. Это не позволяет другому ключу забрать старую очередь после
  Node restart, заявив тот же DNSS.
- Несколько inbound routes связаны с одним DNSS mailbox.
- PULL не принимает locator/queue selector и отдаёт все текущие entries одним
  MAILBOX_DRAIN_RESULT в пределах quota.
- Lease → awaited send → delete ровно leased rows. Ошибка/cancel снимает lease,
  rows сохраняются. Crash после send до delete может дать повтор.
- 128 entries / 512 KiB per DNSS, 64 KiB ciphertext per packet, 64 MiB global.
- NODE_ACCEPTED отделён от Account DELIVERED; mailbox ACK не нужен.
- Старые offline_mailbox rows не удалены, но безопасная миграция/доступ к ним
  через новый client flow **не завершены**. Не выкатывать с потерей доступа.

### E — Device / Account boundary: IMPLEMENTED части, end-to-end PARTIAL

- DeviceEnvelopeV1: version, route_id, extensible type, random packet_id,
  device_metadata, opaque account_payload. Весь envelope шифруется ephemeral
  NaCl box для recipient Device/route key. Route/type не видны Mesh Node.
- DeviceInbox: HMAC aliases + AES-GCM at rest, отдельные HKDF domains,
  native IndexedDB, quota, Web Locks при поддержке, сериализация обработки.
- PULL сначала сохраняет opaque boxes в encrypted local staging. Ошибка
  одного decrypt/handler не удаляет необработанные boxes и не мешает остальным.
- После Device decrypt Account RouteID заменяется blind route_alias. Индекс
  Account routes хранит только alias → Account slot; public Device route имеет
  отдельную Device policy. Unknown routes остаются до восстановления policy.
- При A active входящий B пакет сохраняется без переключения Account и без
  DELIVERED. После B unlock Account handler проверяет sender signature,
  расшифровывает Account payload и сохраняет vault; только затем receipt.
- Normal-message Account handler подключён к Core. Shared Account key mutation
  согласована с текущими Inbox/route tasks при boot; новые Inbox операции
  при Account transition не начинают обработку старого Account.
- Device routes/box capabilities хранятся зашифрованно под DeviceRoot. Raw
  Account RouteID не сохранён в этих records; wire context вычисляется
  временно из capability. Peer identity lookup находится в Account Vault.
- Private route signing/box keys разделены по direction и generation; из двух
  random contributions, без AccountID. При reconnect Device может рекламировать
  сохранённые private routes независимо от текущего активного Account.
- Account отдаёт encrypted envelope + blind local route handle; Device
  оборачивает его и отправляет. Проверяется Account ownership outbound handle.
- Public contact senders перенесены на encrypted CONN_REQUEST Device Envelope.
  Public route grants хранятся encrypted; borrowed route keys стираются finally.
- Tombstone packet_id хранится 30 дней. Account handler должен оставаться
  идемпотентным при crash между своей записью и Inbox tombstone.

**Важные незавершённые места E:**

1. Старый Core.decrypt возвращает null и при успешном control packet, и при
   ошибке. Такие пакеты сохраняются pending, а не объявляются обработанными.
   Новый ratchet должен возвращать явный outcome.
2. Полный Request → network Accept → Account bootstrap → private route ещё
   не закончен. Исторический Accept в Core содержит local-only confirmation.
3. Private Device wrapper пока использует MSG и для части opaque Account
   control/receipt payloads; расширяемая schema поддерживает другие types,
   но все семантические producer paths ещё надо подключить.
4. Полная шкала SENT/NODE_ACCEPTED/DEVICE_FETCHED/DEVICE_STORED/DELIVERED/READ
   в UI и durable sender state ещё не доведена во всех путях.
5. Все-device/all-account advertisements работают в новом пути; исторические
   account-private lifecycle helpers и removal UX требуют завершения миграции.

## Что осталось по исходному плану

| Этап | Статус на checkpoint | Следующая работа |
|---|---|---|
| F hop labels / NCRH | PLANNED | Probe-installed разные labels на каждом hop, replacement DATA label, local NCRH mapping, runtime blind lookup/encrypted metadata |
| G batching 500 ms | PLANNED | Per-peer bounded queues, MESH_BATCH_V1, retry retention, quotas/dedupe/metrics, no cover/padding |
| H password Nodes | PLANNED | Argon2id verifier mode 600, transcript-bound HMAC proof, rate limits, fragment secret removal, encrypted saved credential, installer flags |
| I S-TURN/coturn | PLANNED | can_s_turn + aliases, descriptor, real coturn install/health, ephemeral signaling tickets and TURN credentials |
| J calls | PLANNED | Device-encrypted CallRequestV2, locked-account UI, ringtone/name limits, actual WSS SDP/ICE and relay acceptance |
| K files | PLANNED | DataChannel file session, encrypted chunks/integrity/limits/progress/cancel/resume foundation, actual UI path |
| L epoch ratchet | PLANNED | Loss/out-of-order/epoch state, repeated fresh-update capsules, FS/PCS tests and honest security limits |
| M acceptance/docs/deploy | PARTIAL | Full app/multi-node tests, secret review, production Chrome scenarios, final push and exact-hash deploy |

Сейчас Node data plane ещё имеет прежние raw route/back-route identifiers и
глобальный NCRH. Нельзя заявлять hop privacy. `TACT_INTERVAL` пока 1.5 sec;
старый TactEngine не заменён, transient failures/retry и cover behavior надо
исправить. NodeChannel уже шифрует packets и не отправляет старое padding поле,
но это не реализация требуемого batching. Старый DUMMY становится keepalive.

Нельзя заявлять завершённость S-TURN/calls/files/password/FS/PCS/PQ по текущему
состоянию. Node directory остаётся центральным; DHT не внедрять.

## Проверки и окружение

Последний полный прогон: **134 backend tests + 11 Origin tests + 31 PWA suites,
все PASS**. Новые regression tests проверяют secure-session interop, DNSS,
route authority, leased drain, Device crypto/Inbox, actual NodeManager socket,
private capabilities, Account dispatcher, blind Device storage и handoff.

Исторические тесты не удалены. Два изначально падавших WebAuthn tests перенесены
с obsolete release implementation на реально загружаемый runtime_fixes.
Проверка старой release-55 строки заменена проверкой совпадения текущего
release страницы и service worker; остальные исторические guards сохранены.

Рабочий Python: 3.12, venv `/tmp/dmash-v3-py312`.
Системный Python 3.13 не подходит к части pinned dependencies.
Использован bundled Python:
`/Users/afsvu/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3`.
Dependencies: `D-MASH/client/requirements.txt` и `httpx==0.27.0`.
Node.js: v24.19.0. Native Node WebSocket используется в interop test.

```sh
cd /Users/afsvu/Documents/Codex/D-MASH/D-MASH
/tmp/dmash-v3-py312/bin/python tools/test_all.py
git diff --check
```

Логи последних прогонов находятся в `/tmp/dmash-v3-*.log`, не в git.
Тестовые private keys генерируются во время тестов; production credentials
не добавлялись. Локальные HTTP test servers завершены.

### Настоящий Chrome: только локальная модульная проверка

`tests/device_inbox.browser.html` запускался в Google Chrome на отдельном
localhost origin. Пройдено: native IndexedDB encrypted storage, raw staging
после PULL и reopen, A/B dispatch, dedupe после reopen, Device event без Account
login. Тест удалил собственную DB, тестовая вкладка закрыта.

Chrome browser provider в CUA недоступен, но native app API работает:
`cua.getApp("com.google.Chrome")`. Для адресов надёжнее paste; typeText однажды
ввёл неполный путь при изменении состояния UI. Не использовать чужие вкладки.

**Ни один production acceptance scenario из исходного задания не заявлен
пройденным.** Не было развёртывания, звонка через TURN, больших файлов,
multi-node Chrome mesh trajectory, Node-restart recovery в production.

## Основные файлы

Backend: `secure_session.py`, `secure_socket.py`, `gateway_v3.py`,
`node_session.py`, `device_registration.py`, `dnss_mailbox.py`, `network.py`,
`transport.py`, `database.py`, `core.py`, `main.py`, `client_gateway.py`,
`resource_pow.py` в `D-MASH/client/backend/`.

PWA: `secure_session.js`, `device_client_v3.js`, `device_authority_v3.js`,
`device_envelope.js`, `device_inbox.js`, `private_routes_v3.js`,
`node_manager.js`, `device_routes.js`, `core_engine.js`, `runtime_fixes.js`,
`public_contact_runtime.js`, `acceptance_v50.js`, `resource_pow.js`,
`release.js`, `sw.js` в `D-MASH PWA/not_messenger/`.

Runtime loader по-прежнему включает historical repair modules. При изменении
public contact/Node flow проверить порядок overrides: acceptance_v50 ставит
окончательный public sender после ранних repair modules. Release и SW должны
меняться согласованно; текущий dev id `transport-v3-dev-20260908.1`.

## История до данного checkpoint

- `19a535d` — baseline/spec + complete test runner.
- `45fe92c` — Python/JS secure session + gateway foundation.
- `0ea45ae` — mutual v3 Node peering + directional DNSS work.
- `fdf8ddf` — migrate historical WebAuthn tests.
- `5d9cc0f` — Device route authority + durable DNSS drain.
- `0918c44` — Device Envelope/Inbox + real JS client interop.
- `984ec49` — Device authority client + live mailbox permission check.
- `d59a963` — actual NodeManager v3 + encrypted staging + public contact send.
- Текущий commit добавляет private/Account adapters, blind Device route
  clarification, regression tests и этот общий HANDOFF.

## Git / deployment при продолжении

Пользователь отдельно запросил push текущего состояния ветки transport-v3.
Не использовать force push. После push проверить remote HEAD против локального.
Никакого SSH/deployment на этом checkpoint не выполнялось.

Исходный **финальный** deployment после завершения всех работ и тестов:

```text
ssh ems-vps
su - jcode
cd D-MASH/tools/
test -x ./get_commit.sh
./get_commit.sh <FULL_FINAL_PUSHED_COMMIT_HASH>
```

`tools/get_commit.sh` отсутствует в локальном репозитории; наличие на сервере
ещё не проверено. Не выводить из этого отсутствие удалённого скрипта.
Если remote script отсутствует или fails — исследовать и сообщить, не
импровизировать иной production deploy. Проверить текущую reverse-proxy
конфигурацию и реальный PWA URL; не придумывать новый production URL.

Рекомендуемый следующий шаг: завершить network Contact Accept/Account
bootstrap и явные control outcomes, проверить полный local two-device flow,
затем F/G последовательно. До production также обязательны legacy mailbox
migration, v3 route revoke/expiry UX, все оставшиеся milestones и Chrome.
