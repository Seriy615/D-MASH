# Native host Android + Desktop: проверка выполнимости

20 октября 2026 UTC. Продуктовая база: `9446c22f27309131456942870971d477f6f2358f`. Scope: read-only анализ исходников и synthetic compilation в `/tmp`; production, SDK, пользовательские storage и живые adb/browser sessions не изменялись. Родительские network/security документы не переписывались.

## Решение

**Рекомендация: общий C++ headless host с embedded QuickJS 2026-06-04, существующим JS Node ядром, SQLite и явными native adapters; Android service и Desktop daemon развивать одновременно.** Для platform I/O использовать Qt 6 Core/Network/WebSockets/Sql: Desktop `QCoreApplication` daemon + отдельный Qt Widgets shell для выбранных Telegram Desktop rendering parts; Android отдельный `QtService` process/JNI entry с тем же host library и обычный Java/Kotlin Views frontend. Shell/Activity не владеют Node. Qt не исполняет Account E2EE внутри daemon и не требует WebView для сетевого runtime.

Это выбранный путь реализации spike, а не доказанная готовность всего приложения. По первичным документам Qt поддерживает C++ service entry в отдельном Android процессе; Qt WebSockets предоставляет клиентский WSS API, SQLite driver входит в Qt SQL. Собственная проверка пока покрыла только C/QuickJS execution, не Qt/Android linkage. Точная Qt kit/toolchain revision фиксируется build lock перед первым dual-target build; текущая публичная документация — Qt 6.12. Это не основание молча использовать случайные system Qt/NDK. [Qt Android services](https://doc.qt.io/qt-6/android-services.html), [QWebSocket](https://doc.qt.io/qt-6/qwebsocket.html), [Qt SQL drivers](https://doc.qt.io/qt-6/sql-driver.html).

QuickJS выбран, поскольку выполнен native source-load/crypto proof, C API встраивается в C++/JNI, доступны memory/stack/interrupt limits и явный pending-job pump. У движка нет браузерного окружения: WebCrypto, WebSocket, IndexedDB, Web Locks, WebAssembly не становятся доступными от одного `JS_NewContext`. Стандартный `os.Worker` не равен browser Worker. В production не экспортировать JS `std/os`, filesystem, subprocess/eval loader или произвольный native FFI; загрузка только из pinned application resource manifest. Bytecode не принимать от сети/пользователя. [QuickJS documentation](https://bellard.org/quickjs/quickjs.html), [официальный release/MIT](https://bellard.org/quickjs/).

Rust-порт всей route/ownership/bootstrap state machine сейчас отвергнут: он добавляет вторую реализацию протокола и миграции до закрытия существующих дефектов, а Android bindings/storage/crypto всё равно потребуются. Rust можно рассмотреть позднее для изолированного reviewed adapter; это не условие первого приложения. Python Node оставить реальным interop peer/fixture: его backend/FastAPI, PyNaCl, SQLite и routing не являются Account core и не дают готового Android host. Портирование CPython, numpy/scipy и backend HTTP stack на Android здесь не проверялось и не предлагается.

## Что действительно отделено в коде

[Node Worker](https://github.com/Seriy615/D-MASH/blob/9446c22f27309131456942870971d477f6f2358f/D-MASH%20PWA/not_messenger/js/node_runtime_worker_v4.js) прямо не загружает `core_engine`, DeviceRoot или UI. Сбор seed/storageKey/baseNcrh выполняет browser Host; worker получает уже разрешённые материалы, а затем управляет relationships, routing, Inbox, local ownership и private/public bootstrap. Эти transport secrets допускаются в daemon; Account private keys/plaintext — нет.

Worker import closure: **27 файлов**, включая conditional bootstrap/service modules и Argon2 WASM bundle. Для native proof загружено **25**: без самого browser Worker entry и без WASM Argon2 bundle. Core/route modules используют `globalThis`, typed arrays, Map/Set, BigInt, Promises, private class fields; обращения к document/window обычно guarded. Это не означает, что browser entry можно исполнить без adapters.

| Зависимость / фактические callers | Native port и обязательный контракт |
|---|---|
| `secure_session.js`: subtle SHA-256, raw HKDF import/deriveBits | OpenSSL EVP bridge, тот же domain/salt/info/output length и bytes; Promise completion на actor thread. XSalsa20-Poly1305/X25519/signatures оставить существующему TweetNaCl до отдельного vector-backed замещения. |
| `node_relationships_v4.js`, `node_inbox_v4.js`: HMAC-SHA256, AES-GCM, CSPRNG | Поддержать import/sign/verify/encrypt/decrypt, AAD, IV/tag layout, usage/extractability checks, reject tamper; не переименовывать иной algorithm WebCrypto-совместимым. Native key handles привязаны к root session и wipe/close. |
| `probe_primitives_v4.js`, routing/discovery/bootstrap: HMAC/digest/random | Тот же subset crypto bridge; синтетический native RAND proof уже есть, остальной bridge NOT RUN. |
| `node_identity.js`: Ed25519 generateKey/export raw+PKCS8 fast mining; BLAKE3 verification | Сохранить persisted seed; не майнить при каждом старте. Native bounded miner с теми же public-key work rules/seed encoding; JS fallback неизменён, performance ещё измерить. |
| `node_admission_v4.js`: nested Worker + Argon2id WASM | Native PHC Argon2id job, exact 64 MiB/T3/P1/32-byte profile, cancellation/deadline и одна mining/KDF lane. Не симулировать WASM поддержку QuickJS. |
| relationships: `indexedDB.open`, read/CAS/count/versionchange/transaction completion | Узкий SQLite-backed relationship store, CAS revision + owner generation + encrypted identity binding в одной tx; старое API `.open(...)` расширить явным store injection. Не писать общий IndexedDB emulator. |
| Inbox: records/bindings/usage, read/all/CAS/promote/reconcile | `NodeInboxV4.open(...,{store})` уже допускает injection. Реализовать SQLite store с atomic promotion и quota counters; complete Promise только после COMMIT, а не после выполнения statement. |
| `node_runtime_worker_v4.js`: navigator.locks, importScripts, postMessage, self.close/location | Новый headless entry вместо browser wrapper: exclusive process lock + durable generation/fencing; pinned module loader и bounded IPC dispatch; никакой зависимости от page/Worker lifetime. |
| `node_socket_v4.js`: browser WebSocket event handlers/OPEN/bufferedAmount | Qt QWebSocket shim/adapter: TLS hostname/CA checks, no ignoreSslErrors, bounded frame/queue bytes, cancel/close/read ordering. Socket send не считать recipient durable receipt. |
| timers, AbortController/EventTarget, TextEncoder/Decoder, atob/btoa, URL, performance.now | Небольшой reviewed compatibility layer; Qt monotonic timers + one event loop; UTF-8 strict decode, canonical base64, URL/endpoint policy. Synthetic UTF-8 shim из proof не production implementation. |
| nested identity/channel/admission Workers | Bounded native job executor; callbacks marshalled на единственный actor thread, cancellation generation checked до commit/send. Не делить JSValue/JSRuntime между threads. |

Sources: [relationships](https://github.com/Seriy615/D-MASH/blob/9446c22f27309131456942870971d477f6f2358f/D-MASH%20PWA/not_messenger/js/node_relationships_v4.js), [Inbox](https://github.com/Seriy615/D-MASH/blob/9446c22f27309131456942870971d477f6f2358f/D-MASH%20PWA/not_messenger/js/node_inbox_v4.js), [socket](https://github.com/Seriy615/D-MASH/blob/9446c22f27309131456942870971d477f6f2358f/D-MASH%20PWA/not_messenger/js/node_socket_v4.js), [admission](https://github.com/Seriy615/D-MASH/blob/9446c22f27309131456942870971d477f6f2358f/D-MASH%20PWA/not_messenger/js/node_admission_v4.js). Native crypto implementation references: [OpenSSL Android build](https://github.com/openssl/openssl/blob/master/NOTES-ANDROID.md), [PHC Argon2 C reference](https://github.com/P-H-C/phc-winner-argon2).

**KDF migration stop condition:** bundled Argon2 exports `ArgonType`, тогда как legacy Account/root callers передают `argon2.argon2id`. При отсутствии alias это undefined и vendor default Argon2d. Доказательство и vectors — [actual-argon2-results.json](actual-argon2-results.json). Native unlock обязан воспроизводить actual legacy Argon2d profile/params для сохранённых root/Account keys; новый Argon2id wrapping — отдельная versioned migration без смены identity. В Node password admission уже есть explicit `ArgonType?.Argon2id ?? 2`; не смешивать эти два случая. Нельзя «исправить» общий enum и потерять доступ к старым данным.

## Ограниченный native compile proof: PASS

Официальный `quickjs-2026-06-04.tar.xz` загружен с bellard.org и собран локально gcc/make; SHA-256 archive `b376e839b322978313d929fd20663b11ba58b75df5a46c126dd19ea2fa70ad2a`. C embedding process ограничен 128 MiB/2 MiB stack; native `RAND_bytes` заполняет Uint8Array с bounds check. Исходные JS модули прочитаны из exact audit checkout без изменений; shim и synthetic messages были созданы в `/tmp`; проверенные исходники и stdout теперь сохранены в [native-proof/](native-proof/README.md) без изменения байтов.

```text
PASS UTF8 synthetic adapter
PASS unchanged TweetNaCl Ed25519
PASS unchanged resource SHA256 vector
PASS unchanged BLAKE3 vector
PASS unchanged recipient payload seal/open
PASS routing and ownership loaded
Loaded 25 unchanged source modules; NO transport/storage/Android PASS
```

Последняя строка проверяет exports, не все route transitions. SHA-256 vector: `abc`; BLAKE3 vector: empty input; recipient V2 seal/open содержит Unicode и использует existing NaCl/route envelope. Proof C bridge предоставляет random, **не полный WebCrypto**. Вывод не доказывает network/privacy/durability/constant-time свойства, полный Account flow или отсутствие уязвимостей.

Первоначальные tested paths: `/tmp/dmash-native-feasibility-20261020/`. Portable audit copies `embed.c`, `source-load.js`, `proof-output.txt` находятся в [native-proof/](native-proof/README.md), с теми же SHA-256; compiled binary/archive в bundle не включены:

| Файл | SHA-256 |
|---|---|
| `embed.c` | `69ac81e5170bc0596008a3f321c5a26a2c090f456bfcbd3437672be6593b3ec9` |
| `source-load.js` (synthetic shim + 25 exact module bodies + checks) | `02a3d52e9a18f8c9f970a498e56c71e2723e40d5c4affa34fc8dd0e89c18c932` |
| `embed-proof` (Linux x86_64 executable) | `2deff4c82e3bfe379598a22f8039ae20e7df65c8fb812e3b3358f711cc517062` |
| `proof-output.txt` | `5208f16b72a55a8fcbc9d875b2ea0488e4cec429b9b9fe9c34c8c961577bd8a9` |

Повтор выполнения: `embed-proof source-load.js` из указанного artifact directory. C executable links `libquickjs.a -lcrypto -lm -lpthread -ldl`. Compile и запуск exit 0. Публикуемых ключей/пользовательских данных нет: signing seed только фиксированный synthetic test; recipient key случайный одноразовый в памяти. Архив/бинарники не добавлены в repository.

## Обнаруженные инструменты и пределы evidence

Есть `/usr/bin/java`, javac **17.0.20.1**, gcc/g++ **13.3.0**, make, curl, tar, OpenSSL **3.0.13** + headers/libcrypto. System `node` — **18.19.1**, не reference Node 24.19; дополнительно найден `/opt/forgeai-node-v22.21.0/bin/node`. Этот proof не запускал product test suite на другой версии Node.

В PATH нет gradle/adb/cmake/cargo/rustc/qmake; однако найдены:

- SDK `/tmp/shark-android-sdk`, `cmdline-tools/latest/bin/sdkmanager`, `platform-tools/adb`, `platforms/android-35/android.jar`, build-tools/system-images/licenses.
- Gradle `/home/jcode/.gradle/wrapper/dists/gradle-8.13-bin/5xuhj0ry160q40clulazy9h7d/gradle-8.13/bin/gradle`.
- `.android` содержит существующие emulator/adb artifacts; они не использовались и не очищались. Наличие этих файлов не является connected physical-device evidence.

В найденном SDK нет `ndk/` и `cmake/`; Qt kit не найден, SQLite runtime есть, headers не найдены. SDK inventory ограничен перечисленными paths, не доказывает глобальное отсутствие других installations. Build install выполняется в новом isolated prefix, существующий SDK/config не менять. Cross-compilation использует официальный NDK clang/sysroot, API/ABI задаются явно: [NDK build guidance](https://developer.android.com/ndk/guides/other_build_systems). Android APK/NDK/Qt build **NOT RUN**; физический Android, Desktop shell UI, WSS interop, SQLite crash tests, NAT/direct **NOT RUN**.

## Конкретные implementation tasks и файлы

Все пути ниже — **новые предлагаемые файлы/порты**, не существующая реализация. Начать Android и Desktop targets в одном checkpoint; CLI acceptance не заменяет оконное приложение.

1. `native/CMakeLists.txt`, `native/deps.lock`, `native/js/manifest.json`: pin QuickJS archive+hash, maintained Qt kit, OpenSSL, PHC Argon2 и SQLite revision/licenses; isolated toolchain lock для Linux x86_64 и Android arm64-v8a. Собирать `dmash-host`, `dmashctl`, `libdmash_service.so`, shell/APK в CI. Qt licensing/relink requirements проверить до упаковки: [Qt licensing](https://doc.qt.io/qt-6/licensing.html).
2. `native/core/JsActor.{h,cpp}`, `native/js/entry.js`, `native/ports/{Clock,Codec,Crypto,JobExecutor,Socket}.*`: memory/stack/interrupt caps, pending Promise jobs, JS actor confinement, cancellation/fencing и only-approved module loader. Сохранить те же crypto transcripts/route modules. На обеих ABI выполнить одинаковые vectors; SHA/HKDF/HMAC/AES-GCM negative tests до открытия любого migrated vault.
3. `native/store/{NodeStore,OwnerCoordinator,OpaqueJobLedger}.*`: SQLite tx/CAS/promote/quota schema, authenticated encrypted records, process lock + monotonic owner generation; SQLITE_FULL/IOERR/crash cleanup. `node_relationships_v4.js` получает store injection; Inbox использует уже существующий injection. Не эмулировать всю IndexedDB и не переписывать JS маршрутизацию. Commit semantics должны опираться на реальные SQLite sync settings, проверенные kill tests: [SQLite atomic commit](https://sqlite.org/atomiccommit.html).
4. `native/ipc/{Protocol,Server,Client}.*`, `native/desktop/{HostMain,ControlMain}.*`: OS-scoped local IPC с caller/destination capabilities; bounded requests/frames; submit ciphertext durable до reply, idempotency/digest conflict, events cursor, root-lock/admin policy. Unix-domain socket access/peer credentials; platform-specific equivalent при Windows/macOS target. Desktop service остаётся жив после закрытия окна.
5. `native/android/{AndroidManifest.xml,src/.../DmashNodeService.java,ServiceMain.cpp,INodeHost.aidl}`: неэкспортируемый separate `:node` service, JNI bridge в один actor, authenticated same-UID Binder API. В Binder переносить handles/ограниченные control messages; bulk ciphertext через bounded descriptor/stream, не unbounded Binder parcel. Android Keystore защищает wrap key, не делает произвольный JS root автоматически hardware resident: [Keystore](https://developer.android.com/privacy-and-security/keystore), [bound services](https://developer.android.com/develop/background-work/services/bound-services).
6. `native/ui/DesktopShell/`: обычный Qt Widgets frontend для выбранных Telegram Desktop rendering parts, без обязательного QML framework. `native/ui/AndroidShell/`: обычные Java/Kotlin Views, включая выбранные Telegram `TextSettingsCell`/`ChatMessageCell`, поверх `QtService` JNI/Binder IPC. Qt Quick Android допустим только как необязательный временный минимальный status spike; он не является drop-in путём переиспользования Java widgets и не заменяет финальный Android frontend. Локальный Account actor/vault отделён от daemon. Existing `core_engine.js` целиком DOM-bound; перенести protocol modules и storage/root interfaces, а не загружать его в Node actor. Для first app slice обязательны unlock/import без identity reset, Node connect/status, public/private contact, ciphertext send/receive/history; Account frontend crypto/KEM/WASM требует отдельного port proof. Окно/Activity не держит singleton network keys и не запускает network timers.
7. `native/tests/`: dual-ABI vectors, real Python NODE/WSS interop, forced transit без Account login, two-process ownership, durable submit/crash/restore и policy-off queued-retry capture. Physical Android lifecycle tests и Desktop visible flows идут параллельно; existing synthetic profiles не трогать.

Android background mode требует отдельного platform gate. Предлагается пользовательский opt-in foreground Node service с видимым уведомлением; для relay runtime кандидат `specialUse` с правдивым subtype, а не автоматическое присвоение messaging/systemExempted. При Play distribution такое описание подлежит review; не обещать принятие или вечную работу. Отказ OS/start restrictions → SUSPENDED/WAITING, сохранённая очередь, поздний allowed restart. `remoteMessaging` описывает continuity текстовых сообщений, не blanket разрешение чужого transit. Это design/application-policy решение, не Android evidence: [official foreground-service types](https://developer.android.com/develop/background-work/services/fgs/service-types).

## Abort criteria выбранного spike

- Byte-for-byte crypto/KDF vectors или retained identity отличаются — остановить migration, чинить adapter/profile. Не переписывать данные и не «починять» legacy Argon2 enum на месте.
- В Android/Qt service нельзя обеспечить единственного owner либо persisted submit зависит от Activity/WebView/Account callback — spike не принят; исправить lifecycle/IPC до расширения функций.
- QuickJS latency/mining/GC under quotas блокируют policy deny/lock/IPC deadlines на реальном arm64 — измерить native crypto/miner adapter; если неизменённые state modules всё ещё не укладываются, оформить отдельное engine replacement решение с теми же vectors. Не переходить незаметно к Rust protocol rewrite.
- WSS adapter не даёт hostname validation, bounded buffered bytes, cancellation или проверку current policy непосредственно перед write — network slice не принят.
- Android service работает только при открытом UI/неправдивом FGS type либо отдельный APK не собирается — Android gate FAIL; Desktop PASS не закрывает «оба приложения».
- Нет dual-target build + SQLite kill tests + Account-free transit + ordinary visible send/receive — нельзя называть результат готовым приложением или «все дыры закрыты».

## Ограничение credential ownership после дополнительного review

Общий сетевой QuickJS actor не получает DeviceRoot/PIN, Account vault key или общий `deviceMaterial(name)`. Credential/root broker вне network process открывает root и передаёт только scoped Node seed/storage key/BaseNCRH и разрешённые route keys, по шву существующего `NodeRuntimeHostV4.startMaterials`. Это существенно для legacy: полный root позволяет открыть installation Kyber secret, участвующий в Account bundle; считать его изолированным от root compromise нельзя. Managed-v4 Account KEM хранится отдельно под Account master key. Existing legacy KEM не удаляется/не ротируется без inventory сохранённых decrypt dependencies.

UI close может забыть root в broker и оставить разрешённый transport bundle в daemon; full D-MASH lock отзывает bundle и останавливает runtime. Reboot convenience требует отдельной OS-wrapped transport-only записи. Browser rootGuard/currentAccount helpers ещё предстоит заменить native owner/capability проверками. Эта архитектура не доказывает sandbox против произвольного same-UID/native-code/OS compromise; native broker/IPC acceptance **NOT RUN**.
