# Буферизация файлов: конкретный проект

20 октября 2026; audited source `9446c22f27309131456942870971d477f6f2358f`.
**Ниже отдельно факты кода и предложение. Новый blob/custody protocol НЕ реализован.**
См. [текущую реализацию](CURRENT_IMPLEMENTATION.md), [daemon](NETWORK_DAEMON_ARCHITECTURE.md), [настройки](SECURITY_CONTROLS.md).

## Что уже есть

- [FileRuntime](https://github.com/Seriy615/D-MASH/blob/9446c22f27309131456942870971d477f6f2358f/D-MASH%20PWA/not_messenger/js/file_runtime.js), строки 137–179: проверяет контакт, сохраняет attachment в Account-bound vault, создаёт history card. Строки 202–314: Account runtime читает vault, выбирает media service, создаёт signaling/session, заново готовит manifest и отправляет invitation. Это ещё не одноразовый handoff независимому daemon.
- [FileVault](https://github.com/Seriy615/D-MASH/blob/9446c22f27309131456942870971d477f6f2358f/D-MASH%20PWA/not_messenger/js/file_vault.js), строки 55–70, 280–306, 316–431: Account/session guards, encrypted local body с блоками 256 KiB, атомарная запись body/metadata/owner. Для чтения нужен действующий Account/storage context. Это не сетевой ciphertext spool, доступный daemon после logout.
- [FileChannel](https://github.com/Seriy615/D-MASH/blob/9446c22f27309131456942870971d477f6f2358f/D-MASH%20PWA/not_messenger/js/file_channel.js), строки 3–39, 65–149: предел 64 MiB, 32 KiB chunks, AES-GCM, окно 8, encrypted ACK, END, полная проверка SHA-256 и onCommit перед финальным ACK. Describe/hash и сборка результата используют полный файл в памяти; bounded in-flight window не означает bounded memory всего runtime.
- [FileSession](https://github.com/Seriy615/D-MASH/blob/9446c22f27309131456942870971d477f6f2358f/D-MASH%20PWA/not_messenger/js/file_session.js), строки 3–38: ordered reliable WebRTC DataChannel `dmash-file-v1`; по умолчанию remote ICE. [CallSession](https://github.com/Seriy615/D-MASH/blob/9446c22f27309131456942870971d477f6f2358f/D-MASH%20PWA/not_messenger/js/call_session.js): `iceTransportPolicy` relay при remote ICE и all в другом режиме. Это не доказательство phone↔phone NAT acceptance.
- Managed-v4 ветка FileRuntime использует confirmed Node media authority и N4 CONTROL; отсутствующий service не заменяется legacy staticShared. Есть локальная очередь, повторные попытки и durable outcomes. Invitation сейчас явно имеет `resumable:false` (строки 11–44): это не сетевой range-resume, provider storage или offline fetch без отправителя.

## Граница владения и цель

Account владеет plaintext, file key, authenticated manifest, E2EE invitation и проверенным receipt. Node daemon получает **только готовый encrypted packet и зависимости из ciphertext chunks**, затем сам выбирает путь/providers, соединяется, переподключается, буферизует и повторяет. Он не возвращается в Account за перепаковкой invitation при provider failover. Его transport keys не являются Account keys.

Direct phone↔phone link желателен как допустимый быстрый путь. Он необязателен: файл можно временно разместить на Nodes и получить позже. Отправитель может уйти offline после подтверждённого сохранения **и invitation, и chunks, и locator**. Custody не означает Account `DELIVERED`/`READ`. Browser без живого процесса не обещает непрерывного фонового исполнения; native/platform daemon и phone lifecycle требуют отдельной реализации.

## Предлагаемый формат и локальная транзакция — НЕ РЕАЛИЗОВАНО

Первая versioned реализация сохраняет верхний предел 64 MiB; пользователь может ставить меньший. Буферный формат `BUFFER_FILE_V1` использует 16 KiB plaintext chunks, чтобы ciphertext+tag+header помещались в отдельный bounded blob frame; это **не** file bytes внутри Mesh MSG/32-KiB route envelope. Изменение верхнего предела требует отдельного memory/protocol acceptance.

Account использует готовый AES-256-GCM port: случайные 32-byte key и 8-byte nonce prefix на новый объект; IV = prefix || uint32be(index), каждый index шифруется ровно один раз. AAD — канонически закодированный tuple `(domain=DMASH_BUFFER_FILE_V1, objectId, index, size, chunkBytes, count)`. В invitation внутри Account E2EE находятся file key, prefix, точные размеры/порядок, имя/MIME, SHA-256 plaintext и SHA-256 полного упорядоченного ciphertext потока. Manifest/invitation metadata ограничены 8 KiB: список тысяч chunk digests не помещается в Account control packet и туда не включается. Последний chunk имеет вычисляемую точную длину; count/size исключают усечение. Retry повторяет готовые bytes; изменение файла создаёт новый key/object. Проверки AEAD, длины, count и полного digest выполняет Account до render/receipt. Это новый формат поверх стандартного примитива, с обязательными test vectors и crypto review, не новый шифр.

Локальный API:

```text
beginOpaqueStage(ownerCapability, recipientRelation, policy)
    -> localJob, objectDescriptor
appendCipherChunk(localJob, index, ciphertext) -> durable staged chunk
submitPacked(localJob, sealedAccountPacket, ciphertextDigestList)
    -> LOCAL_DURABLE_ACCEPTED | incomplete/quota/conflict
```

`objectDescriptor = {version, objectId, locatorVerifyKey, deadline}` неизменен. ObjectId — случайный per-object handle, **не новый route ID**. Locator signing key — отдельный daemon transport secret; не file/Account key. Account включает descriptor в аутентифицированную invitation, но не видит список providers. Stage не делает network I/O: grant/anchor bootstrap может закончиться позже.

Daemon записывает immutable chunks в собственный durable spool с backpressure. После полного fsync/эквивалентного platform durability атомарно фиксирует index+digests+sealed packet+owner+policyGeneration+queue intent. Только затем отвечает ACCEPTED. Если bytes вне транзакционной БД, durable immutable files создаются до index commit; crash оставляет лишь удаляемые orphan files. GC никогда не удаляет referenced files. Exact повтор submit с тем же digest/dependencies возвращает прежний результат; другой packet/dependency list — конфликт. Недостаточная квота/прерванное staging не превращается в отправленную карточку. До submit logout оставляет только STAGED, после submit Account/UI не нужны scheduler.

## Предложенный bounded bootstrap — НЕ РЕАЛИЗОВАНО

Выбирается новый `durable-custody-v1` профиль, отдельно от текущего mailbox. При установлении разрешённого **направленного Node relationship** recipient daemon выдаёт sender daemon подписанный inbox grant: direction, relationship generation, случайный namespace, 1–3 custodian anchor endpoints и их auth pins, scoped writer public key, recipient scoped box key, byte/item limits и expiry. Recipient сам сохраняет эти anchors/namespace/read authority до выдачи grant. Anchor подтверждает резервирование квоты и правила доступа. Ни AccountID, ни постоянный device encryption public key в lookup не нужны. Node peer authentication остаётся отдельной сущностью; A→B не даёт grant для B→A/A→C.

Grant находится в transport context и проверяется daemon; Account получает только objectDescriptor. Без действующего cached grant job остаётся `WAITING_BOOTSTRAP`: daemon получает grant по уже разрешённому relationship при восстановлении связи. Это не callback в Account. До provisioning **обещания offline recipient availability нет**. Старый recipient может быть offline, если cached grant и резервирование ещё действуют; первый неизвестный recipient без прежнего bootstrap не получает магический inbox.

Для каждого принятого job фиксируется существующий набор anchors. Sender записывает туда bundle `{sealedAccountInvitation, encryptedSignedLocator}` по ключу `(namespace, objectId)`; recipient знает namespace/anchors из собственного grant и перечисляет свой inbox после reconnect. Таким образом первое местоположение locator не спрятано в неизвестном provider: оно находится в заранее согласованном recipient inbox. Это ограниченный каталог одного relationship с авторизованным list, не глобальный object/Account index. Scoped recipient route box secret сохраняется за local root до expiry всех выданных grants; rotation создаёт новое поколение для новых jobs, но не удаляет ключ старых accepted jobs до срока. Досрочная потеря ключа означает unavailable, не скрытую замену DeviceRoot.

Custodian принимает запись только от scoped writer по подписанному grant, с проверкой generation, срока, размера, owner и quota. Подписанный object signing key регистрируется неизменно в первой записи за авторизованным writer; invitation позднее аутентифицирует этот же key для Account. Замена key для существующего objectId запрещена. Bundle остаётся до expiry либо recipient durable ACK **точного digest/generation после local persist**. Recipient не ACK-ает только факт socket send. Sender фиксирует custody receipt bundle до удаления своей копии. Запись stale/conflicting generation отвергается; exact retry идемпотентен.

Это отдельное изменение reliability contract. **Сегодняшний mailbox остаётся PULL всех авторизованных rows в пределах квоты → lease → awaited send → delete только leased rows; failed send → release/retention, без обязательного client ACK.** В нём есть окно потери между server send и client persist. Нельзя выдавать такой mailbox за новое durable custody. Новый профиль согласуется явно; старый peer получает unsupported, не silent downgrade.

Anchors не меняются внутри принятого job: failover inbox возможен среди 1–3 уже согласованных anchors. Все anchors недоступны/утрачены — retrieval unavailable, даже при живых chunks. Для их замены нужен новый authenticated relationship grant и явная миграция при живых участниках; невозможность такой миграции не вынуждает Account перепаковать старую invitation. Этот bounded availability tradeoff отделён от свободной смены blob providers.

## Placement, provider failover, resume — НЕ РЕАЛИЗОВАНО

```text
schedule(job):
    enforce latest effective policy; stop at cancel/deadline
    obtain usable inbox grant or WAITING_BOOTSTRAP
    choose permitted blob providers; reserve bytes and retention
    persist each reservation before PUT
    upload missing immutable chunks, bounded concurrency/backoff
    provider durably commits each chunk before chunk ACK
    COMMIT ciphertext stream commitment, size/count and retention deadline
    verify/store provider custody receipt; publish locator generation
    persist invitation+locator at required inbox anchors
```

Предлагаемые bounds для первой реализации: 1–3 blob replicas, 1–3 anchors, TTL от 1 часа до 7 суток, не более 2 параллельных provider uploads/job и 8 in-flight chunks/provider. Локальные disk/rate/network quotas задаются отдельно, не бесконечны. Точные defaults проходят resource acceptance; это не текущие числа кода. Deadline = min(user TTL, grant expiry, provider admitted retention); уменьшение срока отображается до availability success.

У каждого provider независимый random reservation handle; authenticated directional resource grant связывает owner, object commitment, generation, byte cap и expiry. Read capability — отдельный случайный 256-bit bearer secret, только GET/STATUS exact reservation/ranges до expiry; он передаётся recipient только внутри encrypted locator. Write/commit/delete доступны scoped writer, а не любому обладателю read token. Никакой capability не является file key. Отдельная provider metadata служит только ciphertext inventory, без name/MIME/plaintext hash.

Reservation request имеет стабильный idempotency key: `HMAC-SHA256(localJobSecret, canonical("reservation-v1", providerAuthPin, attemptGeneration))`. Secret остаётся daemon; это не wire identity/KDF замена маршрутам. После reconnect owner запрашивает durable bitmap; повтор exact chunk не расходует квоту повторно, конфликтующие bytes отвергаются. COMMIT атомарно проверяет полноту, размер/порядок и SHA-256 ciphertext потока и фиксирует receipt до ответа. Локальный digest index может содержать тысячи записей, но wire COMMIT содержит только bounded commitment/count/size; массив не встраивается в Mesh/control packet. Expired/cancelled reservation имеет tombstone до своего абсолютного expiry плюс 24-часовое replay окно; старое полномочие не создаёт новый объект.

Provider failure → daemon берёт ciphertext из local spool, создаёт новую reservation, загружает и обновляет locator **без изменения Account packet**. Local spool по предлагаемому default сохраняется до verified recipient receipt либо TTL; удалять после k custody receipts — отдельная настройка с явно более слабой доступностью. Когда sender offline, никто не создаёт новые реплики автоматически: остаются ранее committed copies. Подпись provider — проверяемое обещание custody, не доказательство честного диска или независимости k copies.

## Locator и получение — НЕ РЕАЛИЗОВАНО

Locator содержит version/domain, direction+relationship generation, objectId, monotonic generation, issuedAt/expiresAt, state `WAITING|AVAILABLE|CANCELLED|EXPIRED`, максимум 3 `{provider locator, auth pin, reservation handle, read capability, ciphertext commitment, retention}`. Даemon подписывает canonical bytes per-object Ed25519 key, атомарно сохраняет generation+capsule+outbox, затем шифрует к scoped recipient route box key. Используется существующий seal/open-box crypto port из [recipient_payload_v4](https://github.com/Seriy615/D-MASH/blob/9446c22f27309131456942870971d477f6f2358f/D-MASH%20PWA/not_messenger/js/recipient_payload_v4.js) / [route_discovery_v4](https://github.com/Seriy615/D-MASH/blob/9446c22f27309131456942870971d477f6f2358f/D-MASH%20PWA/not_messenger/js/route_discovery_v4.js), с отдельным domain/type и cross-runtime vectors. Capsule не более 8 KiB plaintext, в пределах существующего 16-KiB discovery box bound. Подпись не заменяет шифрование; постоянный device pub не нужен.

Recipient daemon читает свой inbox, сохраняет opaque invitation/capsule, затем ACK exact durable records. До **первого Account unlock** он не доверяет attachment descriptor из sealed invitation и не начинает file retrieval. Account проверяет E2EE invitation, сохраняет file key/manifest у себя и один раз выдаёт daemon локальную retrieval capability с objectDescriptor. После этого daemon может догружать encrypted chunks при logout, сверяя ciphertext commitments; decrypt/preview/финальную file verification и `FILE_VERIFIED` делает только Account при следующем unlock.

Recipient проверяет pinned object key, domain/direction/generation/expiry и полный locator digest. Хранит highest accepted generation+digest долговечно; равное exact допустимо, равное конфликтующее или меньшее отвергается. При первой загрузке запрашивает **все доступные anchors**, выбирает наибольшее валидное поколение и проверяет provider commitments. После crash ledger и pending ACK восстанавливаются одной local transaction. Tombstone CANCELLED/EXPIRED и highest-generation ledger хранятся до absolute object expiry плюс 24 часа. Полная утрата recipient ledger снимает доказательство anti-rollback; восстановление не маркируется verified freshness.

Подписи, максимум среди ответивших anchors и сроки не доказывают отсутствие скрытой более новой capsule. Первый offline fetch может принять ещё действующий старый locator; если он указывает на прежнюю доступную immutable копию, Account проверит тот же файл. Для cancellation это означает bounded stale authority до expiry. Сговор/eclipsing всех доступных anchors вызывает rollback attempt или unavailable; строгая latest-state/мгновенная revocation guarantee **не заявлена**. Часы допускают максимум 5 минут skew; неизвестное/большее расхождение → wait/error, не бессрочное продление токена.

UI различает `STAGED`, `LOCAL_DURABLE_ACCEPTED`, `WAITING_BOOTSTRAP/POLICY/PROVIDER`, `STORED_UNTIL`, `OPAQUE_BYTES_READY`, `FILE_VERIFIED`, `EXPIRED`, `CANCELLED`, `FAILED`. `STORED_UNTIL` требует complete chunk custody нужного числа providers и invitation+locator custody нужного числа anchors. `FILE_VERIFIED` требует аутентифицированного Account receipt, а не upload ACK.

## TTL, квоты, отмена и проверка проекта

Transit queue, собственные attachments и чужой store имеют разные budgets. Provider reserve не принимает больше disk/time обязательств, чем разрешено. Обычный quota pressure не вытесняет accepted retained objects до обещанного срока. Если режим допускает early eviction, receipt явно `best_effort` и UI не обещает retention; потеря диска/процесса остаётся риском и для promised mode. Store disable запрещает новые grants и drain-ит принятые; аварийный revoke отдельно сообщает о нарушении доступности. TTL не гарантирует стирание чужих копий.

Cancel атомарно останавливает локальные retries, повышает locator generation до CANCELLED, ставит authenticated DELETE для своих reservations и tombstones. Delete повторяется bounded до deadline; отсутствие ответа показывается. Recipient read token не даёт delete. Уже скачанный файл/ключ или злонамеренные копии отозвать невозможно. Strict relay-only немедленно блокирует и queued retransmits через direct, не только новые uploads.

План миграции: versioned capability negotiation; старые vault/history/keys сохранить; незавершённые старые file jobs не превращать молча в новый формат. При Account unlock старый body проверяется, шифруется новым file key в spool, новый submit atomic; старый row отмечается migrated только после commit с mapping старый fileId→новый localJob. Crash/retry сохраняет одну карточку и прежние identity/history. Unsupported peer остаётся на явно указанном старом flow без новой гарантии; fallback запрещён вопреки effective policy.

Приёмка реализации: offline submit→Account logout→provider failover до/после COMMIT без callback; sender offline и ранее offline recipient через сохранённые invitation+locator+chunks; отсутствие первого unlock; restart каждого commit/ACK; disk-full/quota/expiry/cancel races; чужой direction/grant/read token, tamper/truncate/reorder/replay/fork/clock skew; потеря одного/всех anchors и providers; relay-only при уже queued direct retry; миграция без reset и duplicate cards. Отдельно browser clicks/real TURN и physical phone direct NAT, Doze/background/OS stop с измерением памяти/сети. **Этот документ проверен чтением source; новые UNIT/BROWSER/DEVICE прогоны и реализация не выполнялись.**
