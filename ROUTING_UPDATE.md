ТЫ — ГЛАВНЫЙ ОРКЕСТРАТОР РАЗРАБОТКИ D-MASH MESSENGER.

Твоя задача — самостоятельно довести следующий большой архитектурный этап
D-MASH Messenger от аудита текущего репозитория до полностью работающей,
протестированной и задокументированной реализации.

Ты НЕ являешься одним coding-agent, который правит пару файлов.

Ты — ОРКЕСТРАТОР.

Сам:
- исследуй текущий код;
- составь архитектурную карту;
- разбей работу на независимые области;
- создавай специализированных агентов;
- назначай file ownership;
- интегрируй изменения;
- исправляй regressions;
- запускай тесты;
- запускай browser acceptance;
- проверяй privacy properties;
- делай логические commits;
- продолжай работу до полного Definition of Done.

НЕ ОСТАНАВЛИВАЙСЯ после design document, unit tests или первой работающей
демонстрации.

======================================================================
0. СНАЧАЛА АУДИТ
======================================================================

Сначала прочитай текущий репозиторий.

Не переписывай архитектуру с нуля.
Не создавай второй routing stack, если текущий можно эволюционно расширить.

Изучи минимум:

PWA:
- D-MASH PWA/not_messenger/js/core_engine.js
- D-MASH PWA/not_messenger/js/node_manager.js
- D-MASH PWA/not_messenger/js/ui_logic.js
- D-MASH PWA/not_messenger/js/storage.js
- D-MASH PWA/not_messenger/js/device_root.js
- release.js
- sw.js
- nodes.json
- manifest
- текущую QR реализацию
- pairing
- Account registry
- calculator gate
- biometricLogin/lazyLogin
- settings
- message delivery
- receipts
- notifications
- Telegram beacon

Python Node:
- D-MASH/client/backend/transport.py
- D-MASH/client/backend/database.py
- D-MASH/client/backend/network.py
- D-MASH/client/backend/capabilities.py
- DMP-C gateway
- Device Auth
- Node identity
- peer transport
- routing
- mailbox
- PULL
- ACK
- notifications

Документацию и tests тоже прочитай.

В начале выдай самому себе:

CURRENT
TARGET
DELTA

и file ownership для агентов.

Не спрашивай пользователя о том, что можно определить чтением кода.

======================================================================
1. ОРКЕСТРАЦИЯ АГЕНТОВ
======================================================================

Создай минимум следующие направления.

AGENT A — CURRENT ARCHITECTURE AUDIT

Только читает существующий код и составляет карту:
- DeviceRoot;
- Account lifecycle;
- NodeManager;
- routing;
- QR;
- contacts;
- storage;
- settings;
- login/logout;
- biometric;
- notifications.

AGENT B — NODE / ROUTING

Отвечает за:
- DNSS;
- PoW;
- Route EntryGrant;
- Probe;
- NCRH;
- route candidates;
- route table;
- multi-node;
- ROUTE_STATUS;
- DATA forwarding;
- route expiry.

AGENT C — DEVICE SECURITY

Отвечает за:
- DeviceRoot;
- master calculator secret;
- Argon2id;
- WebAuthn;
- device biometric unlock;
- Route private key storage;
- DNSS storage;
- lock/unlock lifecycle;
- zeroization.

AGENT D — ROUTE / CONTACT UX

Отвечает за:
- Public Device Routes;
- RouteCertificate;
- route rotation;
- contact URI;
- QR;
- clipboard;
- [+];
- external deep links;
- incoming requests;
- contact accept/reject/read;
- Quick Name Registry.

AGENT E — GLOBAL SETTINGS / ACCOUNT LIFECYCLE

Отвечает за:
- новый Global Settings screen;
- перенос device-level settings;
- Account selector;
- Account logout;
- separation Device Unlock vs Account Login.

AGENT F — STORAGE / MIGRATION

Отвечает за:
- route storage;
- DNSS;
- Quick Names;
- global settings;
- pending contacts;
- account associations;
- migrations.

AGENT G — ACCEPTANCE / SECURITY TESTS

Отвечает за:
- Python tests;
- JS tests;
- multi-node;
- security negatives;
- Playwright;
- deep links;
- biometric mocks;
- account lifecycle;
- privacy inspection.

НЕ ПОЗВОЛЯЙ двум агентам хаотично редактировать core_engine.js,
ui_logic.js, storage.js или node_manager.js одновременно.

======================================================================
2. ГЛАВНАЯ МОДЕЛЬ СИСТЕМЫ
======================================================================

D-MASH теперь имеет четыре принципиально разные сущности.

ACCOUNT

Криптографическая личность пользователя.

Отвечает на вопрос:

"КТО Я?"

--------------------------------------------------

DEVICE

Конкретная установка D-MASH.

Имеет DeviceRoot.

Отвечает на вопрос:

"КАКАЯ ЭТО УСТАНОВКА?"

--------------------------------------------------

ROUTE

Расходный транспортный адрес.

Отвечает:

"КУДА ДОСТАВИТЬ OPAQUE DATA?"

Route не является Account identity.

--------------------------------------------------

DNSS

Device ↔ конкретная Node псевдоидентичность.

Отвечает:

"КАК ENTRY NODE УЗНАЁТ ЭТО УСТРОЙСТВО?"

--------------------------------------------------

NCRH

Идентификатор конкретной trajectory распространения Probe.

Отвечает:

"КАКАЯ ЭТО ТРАЕКТОРИЯ?"

NCRH НЕ ЯВЛЯЕТСЯ security proof.

======================================================================
3. DEVICE SESSION И ACCOUNT SESSION — РАЗНЫЕ УРОВНИ
======================================================================

Нужно ввести чёткое разделение:

DEVICE LOCKED
        ↓
calculator

DEVICE UNLOCKED
        ↓
DeviceRoot доступен
NodeManager работает
Public Device Routes работают
        ↓
Account selector

ACCOUNT LOGGED IN
        ↓
Account keys доступны
Private routes этого Account объявлены
Contacts/messages доступны

Это ТРИ РАЗНЫХ состояния.

======================================================================
4. DEVICE UNLOCK
======================================================================

Device unlock происходит:

A:
через calculator Master Secret

или

B:
через device-level biometric WebAuthn.

После успешного Device Unlock:

1. DeviceRoot доступен в RAM.

2. Загружаются device-level encrypted settings.

3. NodeManager подключается к configured Nodes.

4. Для КАЖДОЙ успешно подключённой Node:
   - Device Auth;
   - DNSS;
   - при необходимости DNSS registration / PoW.

5. Для ВСЕХ активных PUBLIC DEVICE ROUTES запускаются Probe.

6. Пользователь попадает НЕ в чат, а на:

ACCOUNT LOGIN / ACCOUNT SELECTOR.

======================================================================
5. НИКАКОГО PERIODIC ROUTE REFRESH
======================================================================

ВАЖНО.

НЕ ДЕЛАТЬ:

setInterval(() => refreshAllRoutes())

НЕ делать периодическую рассылку Probe только ради refresh.

Логика другая.

PROBE инициируется СОБЫТИЕМ.

Для Public Device Routes:

- Device Unlock;
- Node connection;
- Node reconnection;
- добавление новой Node;
- создание нового Route;
- reissue Route;
- explicit route activation.

При каждом успешном подключении к Node:

отправить Probe для ВСЕХ активных Public Device Routes устройства.

Если в этот момент Account уже активен:

также Probe для ВСЕХ Private Routes активного Account.

--------------------------------------------------

Для Private Routes:

при входе в конкретный Account:

отправить Probe для ВСЕХ Private Routes этого Account
через активные подходящие Nodes.

При reconnect Node во время активного Account:

также повторно объявить Private Routes этого Account.

--------------------------------------------------

НЕТ background periodic refresh timer.

Route entries всё равно имеют expires_at и естественно стареют.

Reconnect / новое открытие Messenger снова объявляет маршруты.

Выбери разумный route lifetime согласно этой event-driven модели.

Не добавляй периодический refresh в обход этого решения.

======================================================================
6. ACCOUNT LOGIN
======================================================================

Device уже разблокирован.

Пользователь выбирает Account.

После успешной Account authentication:

1. Account keys появляются в RAM.

2. Загружаются Account contacts/messages.

3. Для ВСЕХ Private Routes именно этого Account:

   START PROBE.

4. Public Device Routes уже существуют независимо от Account.

То есть:

DEVICE LOGIN
→ Public Device Routes

ACCOUNT LOGIN
→ дополнительно Private Routes Account

======================================================================
7. ACCOUNT LOGOUT != DEVICE LOCK
======================================================================

Кнопка:

[ ВЫЙТИ ]

на странице контактов больше НЕ должна возвращать пользователя в калькулятор.

Она означает:

LOGOUT ACCOUNT

а не:

LOCK DEVICE.

После нажатия:

1. best-effort zeroize Account private keys;
2. уничтожить Account session crypto;
3. закрыть Account chat state;
4. остановить Account-specific processes;
5. закрыть Account-specific media/WebRTC;
6. убрать Account UI;
7. вернуть на Account selector/login page.

НО:

DeviceRoot остаётся unlocked.

NodeManager остаётся подключён.

DNSS остаётся active.

Public Device Routes остаются active.

Global Settings доступны.

Quick Name Registry доступен.

--------------------------------------------------

Отдельная операция:

LOCK DEVICE

должна:

- zero DeviceRoot RAM;
- zero Account keys;
- disconnect NodeManager;
- clear session data;
- показать calculator.

Flip-Lock/Panic = DEVICE LOCK.

======================================================================
8. ИСПРАВИТЬ CALCULATOR BUG
======================================================================

Сейчас после правильного Master Code может оставаться текст вроде:

"ЗАГРУЗКА ЯДРА..."
или аналогичный status/history.

Из-за этого при Flip-Lock calculator может снова показаться с этим старым текстом.

Исправить.

После успешного Device Unlock и завершения загрузки:

calculator state должен быть очищен:

curr = "0"
hist = ""
op = null

Перед переходом в Account selector.

Также каждый:

DEVICE LOCK
FLIP LOCK
PANIC LOCK

должен явно возвращать калькулятор в нейтральное состояние:

0

без:
- "ЗАГРУЗКА ЯДРА";
- старого Master Secret;
- предыдущих вычислений;
- статуса unlock.

Добавить regression test.

======================================================================
9. GLOBAL SETTINGS
======================================================================

На ACCOUNT LOGIN / ACCOUNT SELECTOR page:

СВЕРХУ СПРАВА добавить:

[ ⚙️ ]

Это GLOBAL SETTINGS.

Он доступен после Device Unlock даже если ни один Account ещё не выбран.

--------------------------------------------------

Перенести в Global Settings:

1. PUBLIC ROUTES

2. QUICK NAME REGISTRY

3. NODE CONNECTIONS

4. ✈️ ТЕЛЕГРАМ-МАЯК

5. 🌐 ПОДКЛЮЧЕНИЕ К УЗЛУ

6. ЭКСТРЕННЫЙ ФЛИП-ЛОК

7. СМЕНА MASTER SECRET / MASTER-КОДА

8. DEVICE BIOMETRIC AUTH

--------------------------------------------------

ЭТИ ПУНКТЫ УБРАТЬ ИЗ ACCOUNT SETTINGS.

Account Settings должны содержать только Account-specific вещи.

Например:
- Account identity;
- Account crypto;
- per-account settings;
- contact/account-related options.

Никаких Device Nodes/Public Routes/Master Code в Account Settings.

======================================================================
10. PUBLIC DEVICE ROUTES
======================================================================

Public Routes создаются НА УРОВНЕ DEVICE.

НЕ ACCOUNT.

Device может иметь сколько угодно Routes.

Локально Route может иметь association:

Route A -> Account1
Route B -> Account2, Account3
Route C -> none

Эта association нужна только для UX/default choices.

NODE ЭТОГО НЕ ВИДИТ.

Route нельзя криптографически связывать с Account.

======================================================================
11. ROUTE KEY PAIR
======================================================================

Route key material генерируется случайно.

НЕ:

KDF(Account)
KDF(DeviceRoot)
hash(AccountID)

Нужно:

RouteSignKeyPair = CSPRNG()
RouteBoxKeyPair = CSPRNG()

Canonical:

RouteID = RouteSignPublic

RouteID — публичный verification key маршрута.

RouteSignPrivate:
подписывает EntryGrant / route metadata.

RouteBoxPublic:
нужен для шифрования первого contact request.

RouteBoxPrivate:
хранится device-side encrypted.

DeviceRoot используется только для encrypted-at-rest protection.

======================================================================
12. ROUTE CERTIFICATE
======================================================================

RouteCertificateV1:

{
    version,
    route_id,
    route_box_public,
    generation,
    created_at,
    optional valid_until,
    signature
}

signature =
Sign(
    RouteSignPrivate,
    canonical(
        "D-MASH|ROUTE_CERT|V1",
        fields
    )
)

Self-signed.

Получатель проверяет через:

RouteID == RouteSignPublic.

В RouteCertificate НЕТ:

- AccountID;
- Account public key;
- DeviceID;
- username;
- display name.

======================================================================
13. ROUTE ROTATION
======================================================================

Global Settings:

PUBLIC ROUTES

Для Route:

[ REISSUE ]

создаёт:

new RouteSignKeyPair
new RouteBoxKeyPair
new RouteCertificate
new RouteID
new generation
new random metric context

Account identity не меняется.

DeviceRoot не меняется.

Contacts не меняются.

E2EE sessions не меняются.

--------------------------------------------------

Поддержать bounded fallback:

CURRENT Route
PREVIOUS Route

Не бесконечную историю.

Established contacts могут получить новый RouteCertificate через E2EE:

ROUTE_UPDATE_V1 {
    new_route_certificate,
    generation,
    previous_valid_until
}

======================================================================
14. ОДИН ROUTING ENGINE ДЛЯ ВСЕХ ROUTES
======================================================================

Не создавать:

PublicRouter
PrivateRouter

Нужен один:

ROUTE ENGINE

Для Node любой RouteID просто opaque destination.

Node НЕ знает:

"это Public"
"это Private"

Одинаковые:

PROBE
BlindRouteAlias
candidate
NCRH
metric
expiry
DATA
mailbox
PULL
ACK

Разница только в bootstrap RouteID.

======================================================================
15. EXISTING PRIVATE ROUTES
======================================================================

Текущий bilateral/private mechanism НЕ УДАЛЯТЬ.

Оставить как optional extreme metadata privacy mode.

Private Route bootstrap может происходить:

A.
исконно offline:
QR/NFC/AirDrop/bilateral pairing.

B.
через уже established contact.

C.
опционально bootstrap route state поверх trajectory уже прошедшего DATA.

НО после получения private RouteID:

тот же обычный Probe.
тот же route engine.

При Account Login:

Probe ВСЕХ Private Routes этого Account.

======================================================================
16. ROUTE OWNERSHIP
======================================================================

Malicious Entry Node не должна иметь возможность объявить чужой RouteID.

Поскольку:

RouteID = RouteSignPublic

Device создаёт:

EntryGrantV1 {
    version,
    route_id,
    entry_node_id,
    generation,
    created_at,
    valid_until,
    signature
}

signature =
Sign(
    RouteSignPrivate,
    canonical(
        "D-MASH|ENTRY_GRANT|V1",
        route_id,
        entry_node_id,
        generation,
        valid_until
    )
)

Transit Node проверяет:

Verify(
    public_key = RouteID,
    EntryGrant.signature
)

Также:

entry_node_id == реальная origin Entry Node.

Никакого Account certificate.

Никакого AccountID.

======================================================================
17. DNSS
======================================================================

DNSS = Device Node Secret String.

Per:

DEVICE ↔ NODE

У одного Device:

DNSS_EMS != DNSS_FORGE != DNSS_NODE_X

DNSS = CSPRNG 128 bit.

На Device:

encrypted-at-rest под DeviceRoot protected domain.

На Node:

НЕ persist raw DNSS.

Persist:

BlindDNSS.

При reconnect:

Device предъявляет DNSS в authenticated DMP-C session.

Node:

Blind(DNSS)
→ находит registration.

DNSS никогда не выходит за Entry Node.

Transit Nodes DNSS не видят.

======================================================================
18. POW
======================================================================

PoW нужен при генерации/регистрации какой-либо новой сетевой сущности.

Минимально:

NEW DNSS
NEW ROUTE REGISTRATION / EntryGrant activation

Не делать PoW на:

DATA
ACK
PULL
receipts
обычный Probe при reconnect существующего Route
обычный route advertisement уже зарегистрированной сущности

если registration всё ещё считается валидной.

--------------------------------------------------

Difficulty:

5–6 hex digits эквивалентно примерно:

20–24 leading bits.

Использовать difficulty bits, а не конкретный символ.

Например:

difficulty = 22

PoW material domain-separated:

"D-MASH|POW|V1"
resource_type
NodeID
node-scoped Device transport public key
DNSS or RouteID
nonce

PoW обязательно NodeID-bound.

PoW для Node A нельзя переиспользовать Node B.

Сделать browser benchmark.

======================================================================
19. NCRH
======================================================================

NCRH = Now Current Route Hash.

Назначение ТОЛЬКО:

различать trajectories.

Не:
- ownership;
- identity;
- hop proof;
- trust proof;
- authentication.

======================================================================
20. INITIAL METRIC
======================================================================

Device для Route имеет random initial metric context.

Не начинать всегда с 0.

Нужно скрыть абсолютное число hops.

Например:

metric_base = random high-range integer.

Route Probe:

metric = metric_base

каждая Node:

metric += 1

Отдельно:

hop_limit = 15

Не путать metric с hop_limit.

======================================================================
21. ENTRY PROBE
======================================================================

Entry Node получает от Device:

RouteID
DNSS context
initial metric
hop_limit = 15
EntryGrant
probe metadata

Entry вычисляет:

BlindRouteAlias = Blind(RouteID)

NCRH0 =
H(
    "D-MASH|NCRH|V1"
    || RouteID
    || BlindRouteAlias
)

И отправляет:

ROUTE_PROBE_V2 {
    route_id,
    generation,
    origin_entry_node_id,
    entry_grant,

    probe_id,

    ncrh,
    metric,
    hop_limit,

    route_expiry_metadata,

    origin_signature
}

DNSS отсутствует.

======================================================================
22. TRANSIT PROBE
======================================================================

Transit Node N получает Probe от authenticated Peer P.

Candidate = P.

LocalBlind =
Blind_N(RouteID)

NewNCRH =
H(
    "D-MASH|NCRH|V1"
    || PreviousNCRH
    || LocalBlind
)

metric = incoming_metric + 1
hop_limit = incoming_hop_limit - 1

Если hop_limit <= 0:
не forward.

======================================================================
23. ROUTE TABLE
======================================================================

Logical:

BlindRouteAlias
    Candidate Peer A
        best_metric
        best_ncrh
        expires_at
        last_seen
        health
        alternate_path_tags bounded

    Candidate Peer B
        ...

    Candidate Peer C
        ...

Candidate = immediate authenticated Node peer.

DATA отправляется через candidate с лучшим route score.

V1:
metric primary.

Health может быть secondary.

======================================================================
24. PROBE RULES
======================================================================

CASE 1:

candidate ещё неизвестен:

SAVE
FORWARD

CASE 2:

new_metric < current candidate best:

UPDATE
FORWARD

CASE 3:

known NCRH + same route:

refresh local expires_at
DON'T duplicate

ВАЖНО:

это НЕ periodic refresh mechanism.

Это только обработка повторного Probe,
например при reconnect/login.

CASE 4:

unknown NCRH,
но new_metric >= candidate best:

можно сохранить как bounded alternate trajectory tag.

НЕ forward как improvement.

NCRH storage bounded.

======================================================================
25. LOOP PROTECTION
======================================================================

NCRH сам loop не предотвращает.

Использовать:

probe_id
hop_limit
short-lived seen Probe cache

A → B → C → A

не должно бесконечно flood'иться.

======================================================================
26. ROUTE EXPIRY
======================================================================

Route candidate имеет expires_at.

Но НЕТ periodic refresh timer.

Route re-advertisement происходит при событиях:

- Device Unlock;
- Node connect;
- Node reconnect;
- Account Login для private routes;
- Route creation;
- Route reissue.

Если устройство долго отсутствует:
маршруты естественно истекают.

Когда пользователь снова открывает Messenger:
всё объявляется заново.

======================================================================
27. ROUTE STATUS ПЕРЕД DATA
======================================================================

Перед DATA обязательно проверить наличие Route хотя бы на одной своей Node.

DMP-C:

ROUTE_STATUS / HAS_ROUTE

Request:
route_id

Response:

ROUTE_READY
или
ROUTE_UNKNOWN

Optional:

best_metric
candidate_count
expires_at

Не раскрывать topology.

Multi-node:

Node1 UNKNOWN
Node2 READY
Node3 READY

выбираем лучший healthy Node.

Если все UNKNOWN:

НЕ слать DATA вслепую.

======================================================================
28. PUBLIC CONTACT LINK
======================================================================

Public Route передаётся единым D-MASH Contact Link.

НЕ основной JSON UX.

Использовать:

https://messenger.d-mash.ru/not_messenger/#/c/<BASE64URL_DESCRIPTOR>

ВАЖНО:
fragment.

НЕ query string.

Contact descriptor не должен уходить HTTP server.

Descriptor содержит:

RouteCertificate
protocol version
public contact bootstrap fields

НЕ AccountID.

======================================================================
29. ОДИН CONTACT PARSER
======================================================================

Один canonical serializer/parser.

parseDmashContactUri()

используется:

- QR;
- COPY;
- [+];
- scanner;
- external browser link.

QR = просто QR этой ссылки.

COPY = буквально эта ссылка.

[+] = вставка этой ссылки.

External open = эта же ссылка.

Не 4 разных implementation.

======================================================================
30. NODE CONNECTION LINKS
======================================================================

Сделать ТО ЖЕ САМОЕ для подключения к Node.

Сейчас/где есть:

- QR Node descriptor;
- текстовый Node descriptor/manual connection;

добавить canonical Node Connection Link.

Например:

https://messenger.d-mash.ru/not_messenger/#/node/<BASE64URL_NODE_DESCRIPTOR>

Descriptor содержит только реально поддерживаемые параметры:

- protocol version;
- WSS endpoint;
- NodeID / expected Node identity;
- human label optional;
- capabilities hints optional.

Не передавать Account identity.

Не пихать unsupported fake password auth.

Если private-node password protocol реально не реализован:
не делать вид, что он работает.

--------------------------------------------------

Один parser:

parseDmashNodeUri()

Один import:

importDmashNodeDescriptor()

Используется:

- QR;
- текстовая вставка;
- COPY;
- external link;
- scanner.

======================================================================
31. EXTERNAL DEEP LINK
======================================================================

При:

#/c/...

или:

#/node/...

если Device locked:

1. сохранить pending deep-link безопасно;
2. показать calculator;
3. после Device Unlock продолжить import;
4. не создавать state до успешной валидации.

Использовать RAM/sessionStorage.

Не логировать descriptor.

======================================================================
32. QUICK NAME REGISTRY
======================================================================

Добавить device-level:

РЕЕСТР БЫСТРЫХ ИМЕН.

Он находится в GLOBAL SETTINGS.

Примеры:

Сергей
Серёга
Сергей Генералов
D-MASH
StreetSharks
Работа

Это НЕ Account identity.

Это локальные self-display labels.

Хранить encrypted-at-rest.

Поддержать:

- add;
- edit;
- delete;
- ordering;
- recent;
- default optional;
- dedup;
- validation.

======================================================================
33. OUTGOING CONTACT REQUEST
======================================================================

Когда пользователь пишет через Public Route:

модал:

КАКОЕ ИМЯ ПОКАЗАТЬ?

[input]

Quick Names:
[ Сергей ]
[ Серёга ]
[ D-MASH ]

--------------------------------------------------

Также:

ПЕРВОЕ СООБЩЕНИЕ

[ textarea ]

Цель:
одним сообщением объяснить, кто ты.

Например:

"Привет, это Вася с пары по физике."

======================================================================
34. TEMPORARY REPLY ROUTE
======================================================================

Sender создаёт temporary Reply Route.

Это такой же RouteID / route engine.

Reply Route descriptor находится ВНУТРИ encrypted Contact Request.

Получатель должен иметь возможность ответить до раскрытия Account identity.

======================================================================
35. CONTACT REQUEST
======================================================================

CONTACT_REQUEST_V1:

{
    version,
    request_id,

    sender_display_name,
    intro_message,

    reply_route_certificate,

    bootstrap_encryption_public,

    protocol_capabilities
}

Payload encrypt для RouteBoxPublic destination.

Node получает только:

RouteID
opaque ciphertext

======================================================================
36. INCOMING PENDING CONTACT
======================================================================

В списке контактов:

pending contact подсвечивается СИНИМ.

Например:

Вася с физики          [✅] [❌] [✉️]

Это ещё НЕ established contact.

======================================================================
37. [✉️]
======================================================================

Открывается modal:

ОТ:
Вася с физики

СООБЩЕНИЕ:
"Привет, это Вася с пары..."

[ ✅ ПРИНЯТЬ ]
[ ❌ ОТКЛОНИТЬ ]
[ ЗАКРЫТЬ ]

Закрыть:
pending остаётся.

======================================================================
38. [❌]
======================================================================

Reject:

- удалить pending;
- не раскрывать AccountID;
- не создавать контакт.

Можно bounded encrypted anti-spam tombstone.

======================================================================
39. [✅]
======================================================================

При ACCEPT спросить:

КАК НАЗВАТЬ СЕБЯ ПЕРЕД ЧЕЛОВЕКОМ?

[input]

Quick Name Registry buttons.

--------------------------------------------------

Также спросить:

С КАКИМ АККАУНТОМ СВЯЗАТЬ ЭТОГО ПОЛЬЗОВАТЕЛЯ?

Например:

[ Personal ]
[ D-MASH ]
[ Work ]

Только теперь Route связывается с выбранной Account relationship локально.

======================================================================
40. CONTACT ACCEPT
======================================================================

CONTACT_ACCEPT_V1:

{
    request_id,

    my_display_name,

    selected_account_public_key,

    account_handshake_material,

    established/private_route_bootstrap
}

Encrypt для sender bootstrap / Reply Route.

Account public key раскрывается ТОЛЬКО ДРУГОМУ CLIENT.

NODE его не видит.

После этого начинается Account↔Account handshake.

======================================================================
41. DEVICE ROUTE ≠ USER
======================================================================

КРИТИЧЕСКИЙ ИНВАРИАНТ:

RouteID может обслуживать разные Accounts.

RouteID не говорит:

"кто пользователь?"

Он говорит только:

"какое Device транспортно доступно?"

Один Route может локально иметь:

allowedAccounts = [...]

Но это чисто local metadata.

======================================================================
42. DEVICE ROOT
======================================================================

DeviceRoot:

random 256-bit CSPRNG.

Не Account key.
Не Route key.
Не DNSS.
Не password hash.

Он является encryption/wrapping root устройства.

======================================================================
43. DEVICE MATERIAL
======================================================================

Через domain-separated keys защищать:

- Route private keys;
- DNSS;
- Quick Names;
- Public Route state;
- global Node config;
- pending contacts;
- local route/account associations;
- device transport material;
- fallback route state.

Например separate domains:

dmash/device/routes/v2
dmash/device/dnss/v2
dmash/device/quick-names/v1
dmash/device/contact-bootstrap/v1
dmash/device/storage/v2

======================================================================
44. MASTER SECRET
======================================================================

УБРАТЬ текущий SHA-256 calculator PIN verifier.

Calculator Master Secret поддерживает:

0-9
+
-
*
/
%
(
)
=
.
и остальные безопасные calculator tokens.

Минимум:

8 tokens.

--------------------------------------------------

ВАЖНО:

73+18%(4)=

является literal password string.

НЕ вычислять выражение.

Canonical exact keystroke sequence.

======================================================================
45. ARGON2ID
======================================================================

KEK_password = Argon2id(MasterSecret, random install salt).

Параметры benchmark.

Baseline около:

memory 64 MiB
time ~3

но проверить browser/mobile constraints.

DeviceRoot:

AES-256-GCM encrypted.

Не хранить:

SHA256(masterSecret)

для проверки.

Wrong secret должен просто fail authenticated decrypt.

НЕ создавать новый DeviceRoot.

======================================================================
46. DEVICE-LEVEL BIOMETRIC AUTH
======================================================================

БИОМЕТРИЯ ТЕПЕРЬ НА УРОВНЕ DEVICE.

НЕ Account.

Она должна разблокировать:

DeviceRoot / Device Shell

после чего показать:

Account selector.

Она НЕ должна автоматически логинить конкретный Account.

--------------------------------------------------

Аудировать старый Account biometricLogin.

Если текущая account-level biometric схема небезопасная либо противоречит новой модели:

мигрировать/удалить её.

Не оставлять скрытый bypass.

======================================================================
47. BIOMETRIC SETUP
======================================================================

Global Settings:

DEVICE BIOMETRIC AUTH

Кнопка:

[ НАСТРОИТЬ ]

После нажатия:

показывается калькулятор в специальном setup mode.

Текст может быть минимальным/скрытым согласно UX.

Пользователь должен:

ЗАЖАТЬ ТУ КНОПКУ КАЛЬКУЛЯТОРА,
КОТОРУЮ ОН ХОЧЕТ ИСПОЛЬЗОВАТЬ
ДЛЯ ВЫЗОВА БИОМЕТРИИ.

Например пользователь зажимает:

3

на 3 секунды.

Тогда:

chosenBiometricTrigger = "3"

После этого запускается WebAuthn registration.

--------------------------------------------------

Можно выбрать другую calculator button.

Не hardcode "3".

3 — просто пример/default concept.

======================================================================
48. BIOMETRIC LOGIN
======================================================================

Когда Device locked:

обычное короткое нажатие chosen button работает как calculator.

Но если пользователь удерживает configured button примерно 3 секунды:

trigger WebAuthn platform authentication.

При успехе:

unlock DeviceRoot
connect Nodes
advertise Public Routes
show Account selector

При failure/cancel:

calculator остаётся calculator.

Никакой ошибки, раскрывающей наличие Messenger, по возможности.

======================================================================
49. WEBAUTHN
======================================================================

Использовать platform WebAuthn.

D-MASH НЕ получает fingerprint.

Палец/лицо только разрешает OS/hardware использовать credential.

Potential underlying implementation:

Android:
Keystore / StrongBox / OEM implementation

Samsung:
может быть Knox-backed, но web не должен обещать прямой Knox API

iOS:
Secure Enclave

macOS:
Touch ID / Secure Enclave

Windows:
Windows Hello / TPM

PWA использует WebAuthn abstraction.

======================================================================
50. BIOMETRIC WRAP
======================================================================

Если поддерживается безопасный WebAuthn PRF:

можно получить biometric-derived wrapping path.

DeviceRoot может иметь:

password_wrap
biometric_wrap

Оба раскрывают ОДИН DeviceRoot.

Если безопасный hardware/WebAuthn secret unavailable:

НЕ делать fallback:

localStorage AES key.

Biometric просто unavailable.

Master Secret остаётся рабочим.

======================================================================
51. GLOBAL NODE MANAGEMENT
======================================================================

Global Settings:

🌐 ПОДКЛЮЧЕНИЕ К УЗЛУ

Показать:

- configured Nodes;
- active state;
- authenticated state;
- latency;
- capabilities;
- notification flag если нужен;
- remove;
- add.

Добавление:

[ QR ]
[ ВСТАВИТЬ ]
[ ССЫЛКА ]

но все используют один canonical Node Descriptor parser.

======================================================================
52. TELEGRAM BEACON
======================================================================

✈️ ТЕЛЕГРАМ-МАЯК

Перенести UI/control в GLOBAL SETTINGS.

Он относится к Device/service layer, а не к конкретному открытом чату.

Аудировать существующую implementation.

Не сломать существующую signed enrollment security.

======================================================================
53. FLIP LOCK
======================================================================

ЭКСТРЕННЫЙ ФЛИП-ЛОК

теперь GLOBAL DEVICE SETTING.

Убрать из Account settings.

Flip Lock:

DEVICE LOCK

а не Account logout.

То есть:

zero DeviceRoot
zero Account keys
disconnect Nodes
return calculator

======================================================================
54. CHANGE MASTER SECRET
======================================================================

СМЕНА MASTER SECRET

GLOBAL SETTINGS.

Не Account Settings.

При смене:

старый Master Secret должен успешно unwrap DeviceRoot.

новый Master Secret:

Argon2id
→ new wrapping key
→ rewrap SAME DeviceRoot.

НЕ создавать новый DeviceRoot.

НЕ менять Device identity.

НЕ менять Routes.

НЕ менять DNSS.

======================================================================
55. NODE BLIND STORAGE
======================================================================

Не persist raw:

DNSS
AccountID
display names
intro messages
private keys

Raw RouteID допускается transiently в wire processing.

Persistent routing index:

BlindRouteAlias.

DNSS index:

BlindDNSS.

Разные blind domains.

======================================================================
56. MULTI-NODE
======================================================================

Device может одновременно подключаться:

EMS
Forge
Node X

Каждая Node:

свой DMP-C transport principal
свой DNSS
свой EntryGrant
свой route origin

При новом Node connection:

Probe ВСЕХ Public Device Routes.

Если Account активен:

Probe ВСЕХ Private Routes Account.

Это обязательный lifecycle hook.

======================================================================
57. PUBLIC ROUTES AFTER ACCOUNT LOGOUT
======================================================================

Поскольку Public Route принадлежит DEVICE:

при [ВЫЙТИ] из Account:

Public Route НЕ исчезает.

Node connections НЕ закрываются.

Incoming Public Contact Request всё ещё может попасть на Device.

Если для обработки нужен выбор Account:

он остаётся pending на device level.

Пользователь потом выбирает Account при Accept.

======================================================================
58. PRIVATE ROUTES AFTER ACCOUNT LOGOUT
======================================================================

Private Routes принадлежат Account relationship.

После Account Logout:

не нужно продолжать активно объявлять новые Private Routes этого Account.

Если есть локальная возможность unregister у Entry Nodes:

использовать её аккуратно.

Удалённые route records сами истекут по expires_at.

При следующем входе в Account:
Probe всех Private Routes снова.

======================================================================
59. LEGACY RELAY
======================================================================

Никакого silent fallback.

Mesh unavailable:

показать route unavailable / fallback transport state.

НЕ:

mesh fail
→ silently PHP relay.

Browser acceptance:
любой unexpected legacy relay call = FAIL.

======================================================================
60. STORAGE
======================================================================

Versioned schemas.

DeviceRoutes:
- route_id
- encrypted sign private
- encrypted box private
- certificate
- generation
- state
- metric material
- local allowedAccounts
- EntryGrants
- fallback status

DNSS:
- NodeID
- encrypted DNSS
- registration state
- PoW metadata

QuickNames:
- id
- encrypted value
- last_used
- optional default

GlobalSettings:
- node configurations
- biometric trigger button
- WebAuthn metadata
- flip-lock
- Telegram beacon state

PendingContactRequest:
- encrypted display name
- encrypted intro
- reply route
- bootstrap fields
- received Route
- status

======================================================================
61. PROTOCOL VERSIONING
======================================================================

Domain separated:

D-MASH|ROUTE_CERT|V1
D-MASH|ENTRY_GRANT|V1
D-MASH|DNSS|V1
D-MASH|POW|V1
D-MASH|ROUTE_PROBE|V2
D-MASH|NCRH|V1
D-MASH|CONTACT_REQUEST|V1
D-MASH|CONTACT_ACCEPT|V1
D-MASH|ROUTE_UPDATE|V1
D-MASH|NODE_DESCRIPTOR|V1
D-MASH|CONTACT_DESCRIPTOR|V1

Canonical serializer.

Не подписывать unordered JSON.stringify.

======================================================================
62. НЕ ДЕЛАТЬ СЕЙЧАС
======================================================================

Не переписывать:

T-Ratchet v2
ML-KEM redesign
DSP
DHT
blockchain
currency
full Byzantine routing
TURN architecture
DNS

Scope:

Routes
DNSS
NCRH
PoW
contact bootstrap
Quick Names
Global Settings
Device Security
Node links
Account lifecycle
browser acceptance

======================================================================
63. SECURITY TESTS
======================================================================

Обязательно:

1. RouteID == RouteSignPublic.

2. Чужой key не подписывает валидный EntryGrant.

3. EMS grant не работает Forge.

4. DNSS Node A != DNSS Node B.

5. Raw DNSS отсутствует Node DB.

6. Route private key encrypted.

7. AccountID отсутствует ROUTE_PROBE.

8. AccountID отсутствует RouteCertificate.

9. Quick Names encrypted.

10. Intro message Node не видит.

11. NCRH не считается ownership proof.

12. NCRH storage bounded.

13. Probe loop terminates.

14. Master SHA256 verifier удалён.

15. Wrong MasterSecret не регенерирует DeviceRoot.

16. Changing MasterSecret сохраняет DeviceRoot.

17. Route rotation не меняет Account identity.

18. Route rotation не меняет DeviceRoot.

19. Account logout не уничтожает DeviceRoot.

20. Account logout не disconnect NodeManager.

21. Device lock disconnect NodeManager.

22. Device biometric unlock не логинит Account автоматически.

======================================================================
64. ROUTING TESTS
======================================================================

A.
Device → Node1 → Device.

B.
Node1 → Node2.

C.
long path first,
short path later,
short wins.

D.
multiple candidates.

E.
new Node connection creates new Route candidate.

F.
Probe sent for ALL Public Routes at Node connection.

G.
Node reconnect sends ALL Public Routes again.

H.
Account Login sends ALL Private Routes of Account.

I.
Account B login does NOT advertise Account A private routes.

J.
No periodic Probe timer exists.

K.
hop_limit 15 works.

L.
random metric offset doesn't affect hop limit.

M.
ROUTE_STATUS required before DATA.

======================================================================
65. ACCOUNT LIFECYCLE TESTS
======================================================================

DEVICE LOCKED:
calculator.

Correct Master Secret:
→ Device Unlock
→ Nodes connect
→ Public Routes probe
→ Account selector.

Account Login:
→ private routes probe
→ contacts.

[ВЫЙТИ]:
→ account keys destroyed
→ Account selector
→ Node connections still OPEN
→ DeviceRoot still unlocked
→ Public Routes still functional.

Flip Lock:
→ Account gone
→ DeviceRoot locked
→ Nodes disconnected
→ calculator neutral.

======================================================================
66. GLOBAL SETTINGS TESTS
======================================================================

Account selector has top-right:

[⚙️]

Global Settings contains:

PUBLIC ROUTES
QUICK NAME REGISTRY
✈️ ТЕЛЕГРАМ-МАЯК
🌐 ПОДКЛЮЧЕНИЕ К УЗЛУ
ЭКСТРЕННЫЙ ФЛИП-ЛОК
СМЕНА MASTER SECRET
DEVICE BIOMETRIC AUTH

Verify these are removed from Account Settings.

======================================================================
67. NODE LINK TESTS
======================================================================

Canonical Node URI:

QR == COPY == pasted text == external link.

External link with:

#/node/...

opens same import flow.

HTTP request does NOT contain full descriptor.

Wrong NodeID / malformed descriptor rejected.

Unknown protocol version rejected.

======================================================================
68. BIOMETRIC TESTS
======================================================================

Global Settings:

setup biometric.

Calculator appears in setup mode.

Hold calculator key for ~3 sec:

chosen key stored.

Short press same key:
normal calculator.

Long press:
WebAuthn.

Success:
Device Unlock → Account selector.

Cancel:
neutral calculator.

Failure:
neutral calculator.

Biometric does NOT auto-login Account.

No fingerprint material in JS/storage.

======================================================================
69. CALCULATOR REGRESSION
======================================================================

После Device Unlock:

before leaving calculator state:

curr = "0"
hist = ""
op = null

При Flip Lock:

calculator показывает обычное нейтральное состояние.

НЕ:

ЗАГРУЗКА ЯДРА...

НЕ старый code.

НЕ status предыдущей session.

======================================================================
70. PUBLIC CONTACT PLAYWRIGHT ACCEPTANCE
======================================================================

Browser A:

Device Unlock.
Public Route active.

Copy Public Contact Link.

Browser B:

Device Unlock.
Import same link.

B:

Какое имя показать?
→ "Вася"

Intro:
→ "Привет, это Вася..."

Contact Request.

A receives blue pending:

Вася       ✅ ❌ ✉️

A presses ✉️.

Reads intro.

Close keeps pending.

A presses ✅.

Modal:

КАК НАЗВАТЬ СЕБЯ ПЕРЕД ЧЕЛОВЕКОМ?

Quick Names.

Then:

С КАКИМ АККАУНТОМ СВЯЗАТЬ?

A selects Account.

CONTACT_ACCEPT.

Only now Account identities exchanged client↔client.

Then established E2EE contact.

======================================================================
71. PRIVACY INSPECTION
======================================================================

После тестов специально inspect Node DB/logs.

НЕ должно быть:

AccountID
Account public keys
Quick Names
display names
intro plaintext
raw DNSS
Route private keys

Если есть:
FAIL.

======================================================================
72. OBSERVABILITY
======================================================================

Допустимый local debug:

DEVICE_UNLOCKED
ACCOUNT_LOGGED_IN
ACCOUNT_LOGGED_OUT
NODE_CONNECTED
DNSS_REGISTERED
ROUTE_PROBE_STARTED
ROUTE_FOUND
ROUTE_STATUS_READY
PUBLIC_CONTACT_REQUEST
CONTACT_ACCEPTED
ROUTE_REISSUED

Не server-log:

raw DNSS
Account ID
private keys
Quick Names
intro plaintext.

======================================================================
73. COMMIT ПЛАН
======================================================================

Примерно:

1.
docs: define device/account/route lifecycle

2.
feat: introduce device-scoped routes and encrypted storage

3.
feat: add DNSS and PoW registration

4.
feat: add EntryGrant and route ownership

5.
feat: implement NCRH multi-candidate routing

6.
feat: add connection-triggered route advertisement

7.
feat: add ROUTE_STATUS

8.
feat: add canonical contact and node deep links

9.
feat: add Quick Name Registry

10.
feat: add public contact request/accept flow

11.
feat: add global settings and separate account logout

12.
security: harden calculator master secret

13.
security: add device-level WebAuthn unlock

14.
fix: reset calculator state after device unlock

15.
test: add routing, security and browser acceptance

16.
docs: update verified architecture

======================================================================
74. DEFINITION OF DONE
======================================================================

Не заканчивать, пока:

[ ] Current architecture audited.

[ ] Device Unlock и Account Login разделены.

[ ] Account Logout и Device Lock разделены.

[ ] [ВЫЙТИ] возвращает Account selector, а не calculator.

[ ] Public Routes остаются active после Account Logout.

[ ] Node connections остаются active после Account Logout.

[ ] Flip Lock делает полный Device Lock.

[ ] Calculator stale "ЗАГРУЗКА ЯДРА" bug исправлен.

[ ] Global [⚙️] добавлен в Account selector.

[ ] Public Routes находятся в Global Settings.

[ ] Quick Names находятся в Global Settings.

[ ] Telegram Beacon находится в Global Settings.

[ ] Node Connections находятся в Global Settings.

[ ] Flip Lock находится в Global Settings.

[ ] Master Secret смена находится в Global Settings.

[ ] Device Biometric находится в Global Settings.

[ ] Эти пункты убраны из Account Settings.

[ ] RouteID device-scoped.

[ ] RouteID не зависит от Account.

[ ] Route private keys encrypted.

[ ] RouteCertificate implemented.

[ ] EntryGrant implemented.

[ ] DNSS per Device↔Node implemented.

[ ] DNSS raw не persist.

[ ] PoW implemented.

[ ] NCRH implemented.

[ ] Multi-candidate route table implemented.

[ ] hop_limit separate from metric.

[ ] НЕТ periodic Probe refresh.

[ ] Node connection инициирует Probe ВСЕХ Public Routes.

[ ] Node reconnect инициирует Probe ВСЕХ Public Routes.

[ ] Account login инициирует Probe ВСЕХ Private Routes этого Account.

[ ] Active Account private routes re-probe after Node reconnect.

[ ] ROUTE_STATUS before DATA.

[ ] Public/private используют один routing engine.

[ ] Contact deep-link implemented.

[ ] Node connection deep-link implemented.

[ ] QR/COPY/[+]/scanner/external share one Contact parser.

[ ] QR/text/link share one Node parser.

[ ] Quick Name Registry implemented.

[ ] "Какое имя показать?" implemented.

[ ] Intro message implemented.

[ ] temporary Reply Route implemented.

[ ] Blue pending contacts implemented.

[ ] ✅ ❌ ✉️ implemented.

[ ] Accept asks "Как назвать себя перед человеком?"

[ ] Accept asks which Account to bind.

[ ] Account public key exposed only after Accept client↔client.

[ ] Public Route rotation/fallback implemented.

[ ] Master Secret >= 8 calculator tokens.

[ ] operators participate literally.

[ ] SHA256 Master verifier removed.

[ ] Argon2id DeviceRoot wrapping verified.

[ ] Device biometric WebAuthn implemented.

[ ] biometric trigger calculator key configurable.

[ ] long hold ~3 sec works.

[ ] biometric unlock opens Account selector, not Account.

[ ] unsafe biometric fallback absent.

[ ] security tests PASS.

[ ] routing tests PASS.

[ ] account lifecycle tests PASS.

[ ] deep-link tests PASS.

[ ] Playwright two-browser contact flow PASS.

[ ] legacy relay silent fallback absent.

[ ] Node DB privacy inspection PASS.

======================================================================
75. FINAL REPORT
======================================================================

В конце дай:

1. Final commit SHA.

2. Architecture changes.

3. Device lifecycle:
   DEVICE LOCK
   DEVICE UNLOCK
   ACCOUNT LOGIN
   ACCOUNT LOGOUT.

4. Route architecture.

5. DNSS.

6. PoW.

7. NCRH.

8. Probe lifecycle.

Отдельно подтвердить:

NO PERIODIC ROUTE REFRESH EXISTS.

PUBLIC ROUTES ARE PROBED ON NODE CONNECTION/RECONNECTION.

PRIVATE ROUTES ARE PROBED WHEN THEIR ACCOUNT LOGS IN.

9. Route ownership.

10. Contact deep links.

11. Node connection deep links.

12. Quick Name Registry.

13. Public Contact Request flow.

14. Global Settings.

15. Device biometric authentication.

16. Master Secret storage/security.

17. Calculator stale-state bug fix.

18. Account Logout behaviour.

19. Test results.

20. Browser acceptance.

21. Node DB privacy inspection.

22. Remaining limitations.

23. git status.

И отдельно подтвердить:

ACCOUNT IDENTITY НЕ ПОПАДАЕТ В ROUTING PLANE.

ROUTE ID — DEVICE-SCOPED ROTATABLE TRANSPORT IDENTITY.

DNSS НЕ ПОКИДАЕТ ENTRY NODE.

NCRH — ТОЛЬКО TRAJECTORY IDENTIFIER.

PUBLIC И PRIVATE ROUTES ИСПОЛЬЗУЮТ ОДИН ROUTING ENGINE.

ACCOUNT LOGOUT НЕ LOCK'АЕТ DEVICE.

FLIP LOCK LOCK'АЕТ DEVICE ПОЛНОСТЬЮ.

LEGACY RELAY НЕ ЯВЛЯЕТСЯ SILENT FALLBACK.

======================================================================
76. АВТОНОМНОСТЬ
======================================================================

Не возвращайся ко мне после каждого шага.

Сам:
- исследуй;
- создавай агентов;
- распределяй файлы;
- интегрируй;
- тестируй;
- исправляй;
- перечитывай diff;
- запускай browser acceptance.

Спрашивай только если существует действительно неразрешимое продуктовое
решение, credential, deployment permission или необратимое действие.

Если тест падает:
исправляй код.

Не ослабляй тест только ради PASS.

Не заявляй VERIFIED, пока сценарий действительно не был выполнен.

НАЧНИ С CURRENT → TARGET → DELTA И FILE OWNERSHIP,
ПОСЛЕ ЧЕГО СРАЗУ ПЕРЕХОДИ К РЕАЛИЗАЦИИ.
