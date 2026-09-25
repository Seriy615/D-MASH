# D-MASH: план разработки для Codex — единая Node-модель

Дата: 25 сентября 2026 года. Репозиторий: https://github.com/Seriy615/D-MASH.

**Актуальное указание пользователя:** убрать понятие Device из сетевого взаимодействия. Клиент общается с другими узлами как полноценная Node, участвует в Mesh и пересылает чужие пакеты. Это указание заменяет прежнее разделение сетевых ROLE_DEVICE и ROLE_NODE. Сохранить остальные совместимые требования исходного задания.

**Дополнительное обязательное требование:** пользовательский runtime не должен выдавать себя как «устройство/клиент», а внешние Nodes не должны получать сведения о начале и конце пользовательского маршрута. Одинаковая роль NODE — только основа; нужна проверка всего control/data plane и наблюдаемого поведения. Границы этого требования уточнены в разделе 4.7; не объявлять абсолютную анонимность достигнутой простым переименованием ролей.

Этот документ — готовое задание для следующего сеанса разработки Codex. При его составлении код и серверы не менялись.

## 1. Цель и границы

Продолжить transport-v3 с текущего состояния, выполнить переход к единой Node-модели и устранить зависание «контакт добавляется, дальше ничего». Не начинать весь проект заново и не ограничиваться заменой названий Device на Node.

В целевой модели:

- Account владеет identity, E2EE, ratchet, контактами, содержимым, DELIVERED/READ.
- Локальный Node runtime владеет Node identity, соседями, DNSS, routing, transit, mailbox/inbox и передачей локальным Accounts.
- DMP-C/Mesh связывает равноправные Nodes независимо от среды выполнения: Python daemon, браузер/PWA, будущий native runtime.
- Network adapters предоставляют WSS/TCP и отдельные WebRTC/signaling/TURN пути.
- DeviceRoot может остаться локальным названием корня хранения/разблокировки. В сетевых ролях, handshake, resource authority, directory и адресации понятия Device больше нет.

Транзит обрабатывается локальной Node без Account login и без доступа к Account plaintext/ключам. Account получает только адресованный ему payload после local delivery; транзитные пакеты в Account Inbox не попадают.

## 2. Проверенная исходная точка

На момент проверки remote refs:

- main: `703a5dfc12167a31f181fc8e064f6cfef5d891fa`.
- transport-v3: `aa0ad8aac716570bf9b65b8901e4548c255251f3`, 44 коммита поверх main.
- PWA release: `transport-v3-hotfix-20260918.8`.
- Публичные release.js/core_engine.js совпали с этой веткой. SHA всего deploy и обновление SW у конкретных пользователей этим не доказаны.
- Самостоятельно пройдены 209 backend-тестов, 11 Origin-тестов, 48 PWA JS-наборов. Backend main: 98 тестов.
- Свежий CURRENT_HANDOFF описывает успешную двухбраузерную приёмку через EMS. В данном анализе она не повторялась. Это ещё не проверка транзита через браузерную Node.
- Дополнительные локальные fault-сценарии выявили дефекты из раздела 6. Они не исправлены. Первичный handshake проверялся с настоящими TweetNaCl/Kyber WASM и моделируемыми storage/network.

Уже есть основа для переиспользования: secure_session.py/js, node_session.py, hop_routes.py, hop_probes.py, tact.py, DNSS mailbox, local Inbox, public contact bootstrap, Account ratchet, signaling/call/file runtimes. Но браузер сейчас подключается через DeviceClientV3/ROLE_DEVICE; его нужно превратить в настоящий Node peer.

Перед работой fetch/status/log, перечитать актуальные CURRENT_HANDOFF.md и TRANSPORT_V3.md. Если HEAD изменился — сравнить delta с этим планом. Старый HANDOFF_TRANSPORT_V3.md не считать текущей ведомостью готовности.

## 3. Правила выполнения

1. База — актуальная origin/transport-v3. Не пересоздавать существующую ветку и не начинать с main. При необходимости отдельный worktree/рабочая ветка.
2. Не перезаписывать чужие изменения, не force-push, не очищать IndexedDB/историю ради прохождения тестов.
3. Сначала спецификация затронутого контракта и воспроизведение ошибки, затем небольшой связанный diff и regression tests. Не ослаблять auth, signatures, PoW и ownership ради PASS.
4. Новую логику помещать в модуль-владелец. Не добавлять ещё один acceptance_vNN поверх криптографических monkey patches. Порядок существующих загрузчиков учитывать.
5. Не переносить AccountID в transport KDF, mailbox key, NodeID или route metadata. NCRH не является полномочием.
6. Продолжать авторизованную работу автономно. Инфраструктурный блокер останавливает только зависимый этап, а не локальную разработку.
7. Использовать тестовые Accounts/Nodes. Не отправлять сообщения реальным контактам без отдельной авторизации. Не писать секреты, plaintext, полные пользовательские идентификаторы в диагностические артефакты.
8. Не выдавать наличие модуля, mock-теста, локального ICE или push за полную browser/production acceptance.
9. Приоритет требований: последнее явное указание пользователя → совместимые прежние указания → исходное задание → проектная документация. Отсутствующие ремарки не выдумывать.

## 4. Новый сетевой контракт: принять перед реализацией

### 4.1 Единая identity и permissions

Одна сетево́вая роль NODE. NodeID не зависит от выбранного Account и не меняется при Account logout. Ключи Node создаются/хранятся отдельно от Account keys, за локальным root. При миграции не переиспользовать Account signing key как Node identity.

Browser Node — описание среды выполнения, не новый ROLE_CLIENT/ROLE_DEVICE и не протокольный класс с особыми привилегиями. Capabilities, локальная политика и ресурсные квоты могут различаться у любых Nodes. «Полноценная Node» не означает неограниченное право на чужие routes/mailbox или обязательный coturn у каждого участника.

Сохраняются mutual auth, signed transcript, fresh ephemeral X25519, directional keys, sequence/replay checks и WSS. Портировать в JS существующую NODE authorization, а не просто заменить строку роли в DeviceClientV3. В текущем node_session.py NODE не имеет Device operations: нужные операции нужно формально включить в новый Node contract с самостоятельными grants.

Версионировать изменение отдельно от старой DEVICE/NODE семантики v3: новая protocol version или явно согласованный mandatory profile. Имя версии выбрать после аудита wire. Старый клиент должен получить понятную несовместимость/путь обновления, а не silent downgrade.

### 4.2 Node↔Node DNSS

Для каждой пары сохраняется направленность: DNSS_AB != DNSS_BA; отдельная авторизация каждого направления. DNSS не равен NodeID, AccountID или socket ID.

**Предлагаемая целевая политика для новой схемы:** сохранять каждый directional DNSS для данной пары Nodes при обычном reconnect; каждый новый socket получает fresh transcript/nonce и новую session binding. После потери runtime registration повторяются необходимые auth/PoW/probe. Это расширяет устойчивость прежнего клиентского DNSS на общую Node-модель.

Это проектное решение данного плана, а не уже реализованное свойство: текущий authorize_node создаёт DNSS заново на соединение. Зафиксировать изменение явно в спецификации. Если выбрана другая политика, durable mailbox owner обязан оставаться независимым от случайного socket DNSS и иметь проверяемую миграцию. BootID не вводить.

При устойчивом DNSS нельзя повторно использовать старый transcript-bound proof. Направленность, expiry, replay и стоимость повторной регистрации тестировать отдельно. Обе стороны проверяют peer Node identity/PoW без исключений «потому что это браузер».

### 4.3 Реальный браузерный transit

Браузер не обязан слушать входящий TCP/WSS port. Он устанавливает несколько исходящих WSS-соединений с Nodes. Уже открытые WebSocket двусторонние: receive от N1 → local routing → send к N2 обеспечивает полноценный transit.

Реализовать Node peer WSS endpoint с тем же протоколом и проверками, доступный браузеру через proxy. Не открывать старый privileged HTTP API как замену peering.

Browser Node должна:

- держать минимум два соседних соединения для сценария transit;
- принимать/проверять/распространять Probe, устанавливать hop-local bindings;
- разбирать MESH_BATCH, заменять входной label на outgoing label, агрегировать к next hop;
- доставлять локальные пакеты отдельно от пересылки;
- иметь quotas, queue/backpressure, hop/loop/duplicate/expiry guards и bounded retry;
- объявлять/отзывать пригодность маршрута при availability changes.

Сохранять first-arrival 500 ms aggregation windows актуального проекта. Не вводить padding/cover traffic и глобальный periodic Probe refresh.

При sleep/закрытии вкладки браузер не гарантирует transit. Service Worker не считать постоянно работающим Mesh daemon. Соседи должны перестраивать маршруты; UI не обещает relay после остановки runtime. Account logout оставляет Node работающей, пока локальный Node runtime разблокирован. Полная локальная блокировка закрывает sockets и доступ к Node keys. Фоновый always-on native daemon — отдельная будущая задача.

Транзит вынести в Worker/отдельный runtime там, где это поддерживается, чтобы нагрузка не блокировала UI. Сам Worker не считать защитой от полного same-origin JS compromise.

### 4.4 Public/private routes и конечная доставка

Route ownership остаётся отдельным от Node membership. Public route — signing authority/certificate/grant; private — pairing-derived directional capability. Один факт authenticated NODE не позволяет присвоить произвольный маршрут, захватить mailbox или выполнять чужой unregister.

Node, на которой находятся локальные Accounts, создаёт owned local delivery bindings внутри процесса. В сеть выходят только обычные route advertisements, не отмеченные как локальные/конечные: их wire semantics должны быть совместимы с рекламой доступного через Node транзитного направления. Account передаёт локальному Node runtime opaque payload через локальный API; для этого не нужен сетевой Device gateway. До реализации проверить, что signature chain, Probe root/origin tag и binding не превращают эту рекламу в доказательство endpoint.

Сохранить дополнительный encrypted recipient envelope, если он нужен для type/demultiplexing. Предлагаемое название — RecipientEnvelopeV2; это проектное имя, не готовый wire. Он скрывает local route/type/packet ID/opaque AccountPayload от промежуточных Nodes и открывается только delivery owner по recipient route/Node capability. Не заменять per-route box keys одной глобальной Node key без отдельного анализа связи маршрутов.

DeviceEnvelopeV1 мигрировать совместимо, но не сохранять под новым названием отдельную Device identity/auth plane. Внутри локального хранилища Account route index остаётся blind alias → Account slot; transit table и Local Inbox раздельны.

### 4.5 Store-and-forward без Device

Любая Node может предоставлять разрешённую mailbox/store capability соседней Node. Это не привилегия отдельного типа «клиент». Очередь служит и временно недоступному транзитному next hop: она не маркирует конечного получателя. Сосед знает, какому peer он обязан передать ciphertext, но не должен получать утверждение, что этот peer является конечным Account endpoint. Унифицировать store/drain для transit и локально адресованного трафика; выделенный endpoint-only PULL не оставлять побочным каналом.

Durable mailbox owner привязать к authenticated recipient Node и её подтверждённому directional relationship/grant. Alias — domain-separated keyed derivation с owner binding; сырой DNSS и AccountID в persistent lookup не хранить. NodeID сам по себе не раскрывает и не даёт чужую очередь. Offline recipient, reconnect, restart и key rotation должны иметь явный lifecycle.

Сохранить семантику исходного задания: один PULL возвращает ALL текущего авторизованного mailbox в пределах quota; lease → awaited send → delete ровно leased rows; failed send → release lease и retention. Обязательный клиентский ACK mailbox не добавлять скрыто.

Это даёт повтор при server crash между send/delete, но не гарантирует client persist после send. Надёжность Account/control packets обеспечивать durable retries/key confirmation/receipts выше mailbox. Окно потери документировать. Изменение на mandatory client ACK — отдельное изменение требования.

### 4.6 Privacy delta

Единая Node identity, peering и участие клиента в Probe/transit меняют модель наблюдаемости по сравнению с прежней pairwise Device transport identity. Соседи видят сетевого peer и его availability; нельзя обещать отсутствие связи его соединений или глобальную анонимность.

Account identity и plaintext должны оставаться скрыты. Составить threat model: malicious сосед, colluding Nodes, disk compromise, live runtime compromise, traffic correlation. Узел, пересылающий пакет, не получает terminal keys и не открывает recipient envelope.

### 4.7 Сокрытие пользовательского runtime и концов маршрута

Это отдельный архитектурный gate N0, а не обещание от наличия transit.

**Операционное толкование:** локальный runtime неизбежно знает о собственном Account send/delivery. Требование скрытия относится к внешним Nodes: сосед не получает protocol evidence, что текущий peer создал пользовательское сообщение или является его конечным получателем; промежуточный Node знает только необходимый локальный участок. Не переопределять это как гарантию скрыть сам факт собственного получения от локальной Node.

**Уровни проверки:**

1. Явные признаки: нет DEVICE/CLIENT role, browser/platform flags, специальной Account-facing gateway semantics, origin/end/terminal полей и endpoint-only receipts.
2. Локальный протокольный наблюдатель: видит свой peer, authenticated channel, свои grants/labels/queues. Не получает весь путь, абсолютную позицию на нём, глобальный RouteID, публичную цепочку NodeIDs или связь с Account. Сведения из Probe/NCRH не должны превращать числовую метрику в точный счётчик расстояния от пользовательского отправителя. Оптимизацию shortest-route согласовать с этим ограничением, а не просто удалить метрику.
3. Статистический/сговаривающийся наблюдатель: timing, length, traffic volume, соседние участки и topology могут раскрывать связи. Проверить и описать остаточные риски. При требовании гарантии против такого противника понадобится дополнительный design (mixing/padding/cover/transport camouflage); исходный запрет padding/cover нельзя отменять молча.

**Обязательные задачи:**

- Для каждого frame составить таблицу «какие данные видит peer / можно ли вывести origin или terminal». Включить handshake, password admission, DNSS, Probe, HOP_ROOT_NCRH, origin tags, labels, route status, grants, store/drain, errors, capabilities и reconnect.
- Account-originated packet вводится в ту же bounded queue/forwarding pipeline, что и transit. Внешняя Node не получает origin flag и отдельный SEND_FROM_ACCOUNT frame. Для локального завершения не отправлять terminal=true или открытый Account receipt.
- End-to-end handshake/DELIVERED/READ должны идти внутри непрозрачных payload обычного класса. Hop/store подтверждение означает только соседнюю передачу/хранение, не «здесь конечный пользователь». Удалить из новой wire-семантики DELIVERED_TO_DESTINATION_PWA_SESSION и аналогичные markers.
- Hop-local labels не устраняют корреляцию неизменного packet_id/ciphertext между colluding hops. Проанализировать существующий HOP_DATA id и envelope; при необходимости разработать per-hop transformation/onion construction с аутентификацией и независимой проверкой. Не изобретать криптосхему ради green test и не принимать session encryption за защиту от самих Nodes.
- Browser нельзя выдавать специальным path, advertised client capability или channel shape. При этом capability list должен оставаться правдивым: не рекламировать фиктивный listener/coturn ради маскировки. Нужны единый общий протокол и отсутствие искусственного browser class, а не ложные services.
- Проверить WSS handshake Origin/User-Agent/subprotocol, TLS/network fingerprint, IP/topology, sleep pattern и radio/network timing. JS не может произвольно скрыть все browser-controlled признаки от сервера. Если выбранный browser transport не удовлетворяет строгой неразличимости — это архитектурный blocker для этой гарантии, а не выполненный пункт. Рассмотреть native transport/адаптер и его собственные границы доверия; не добавлять центральный proxy как «магическое» исправление.
- Calls/files проверять отдельно: direct WebRTC и ICE раскрывают сетевые адреса участников peer/signaling, TURN знает подключившиеся сетевые endpoints. Force-relay помогает ограничить раскрытие адреса собеседнику, но не делает пользователя невидимым для relay. Указать границу применимости маршрутной приватности к Mesh и к media plane.

**Приёмка:** сопоставить протокольные traces peer-узла для local-origin и transit, а также local-delivery и onward-forwarding; искать конкретные различающие поля/ответы/операции. Отсутствие найденного различителя в тесте не считать доказательством глобальной неразличимости. Privacy gate не закрывать, пока runtime выдаётся явным протокольным признаком. Если остаётся fingerprint/timing различитель, честно указать его и не утверждать исполнение абсолютного требования.

## 5. Порядок milestones

| Этап | Результат | Критерий перехода |
|---|---|---|
| N0 | Новый контракт, endpoint-privacy threat model и план миграции; регрессии | Устранены неоднозначности roles/DNSS/mailbox/identity; проверены явные endpoint/runtime различители |
| N1 | JS полноценный Node peer ↔ Python Node | Mutual auth, directional authorization, no DEVICE wire, real interop |
| N2 | Transit через браузер и local delivery | Python N1 → браузер B → Python N2 действительно доставляет пакет |
| N3 | Accounts/contact/Inbox поверх локальной Node | Public/private contact, multi-account, offline mailbox через новую модель |
| N4 | Надёжный initial handshake и ratchet control flow | Collision/loss/restart/recovery проходят без ложного ESTABLISHED |
| N5 | Security hardening, storage migration, crypto requirements | Закрыты exposure/legacy/verifier риски; честные FS/PCS границы |
| N6 | Password Nodes, directory, installer | Одинаковая policy для допустимых Node peers; безопасный repeat install |
| N7 | Live S-TURN/calls/files, wake и UI | Реальный TURN relay и file integrity, понятные состояния |
| N8 | Сквозная приёмка, документация, exact-SHA release | Полная матрица evidence, проверенная миграция и deploy |

В N0 сразу оценить возможный BaseNCRH exposure и доступность legacy admin endpoints. Не откладывать проверку действующего риска до N5. Воспроизведения handshake сделать до переноса слоёв; исправления можно переносить вместе с Account integration. Не завершать старую Device-архитектуру отдельным большим проектом перед переходом.

## 6. N0: обязательные регрессии и диагностика

Зафиксировать для обоих клиентов page/SW/runtime release, Node capabilities и переход, на котором зависает контакт. Различать CONTACT_SAVED, BOOTSTRAP_READY, ROUTE_READY, KEY_PENDING, KEY_CONFIRMED/ESTABLISHED. Node connected не означает готовность маршрута и E2EE.

| ID | Подтверждённый локально дефект | Где | Что должен доказать regression test |
|---|---|---|---|
| H1 | Встречные initial 0x01 дают разные staticShared; оба 0x03 consumed | core_engine.js | Одна согласованная попытка и одинаковый подтверждённый ключ |
| H2 | Старый staticShared заставляет поглотить новый 0x01 без ответа | core_engine.js | Аутентифицированное восстановление одной потерявшей state стороны |
| H3 | pendingKyberFinal удаляется после Node submission, не peer confirmation | core_engine.js | Потерянный final можно повторить до завершения попытки |
| H4 | Emergency recovery теряет pid и идёт в activePeerId; throttle общий | core_engine.js | Явный адресат, отдельный retry/backoff каждого peer |
| R1 | Одновременные ratchet updates расходятся по roots/ACK state | account_ratchet*.js | Детерминированное разрешение столкновения |
| R2 | false от ACK-send игнорируется; ACK отправляется до persist | account_ratchet_runtime.js | Durable ACK/update, определённый crash-safe порядок |
| I1 | Ошибка одного pending record прерывает Inbox drain | device_inbox.js | Invalid-first не блокирует valid-next |

Не считать все эти дефекты установленной причиной конкретной пользовательской пары. Отдельно проверить импорт одного голого Account ID без pairing contribution, несовпадение версий/SW, PoW pending, route unavailable и неверную фазу public contact bootstrap.

## 7. N1–N3: задачи по коду и миграции

Backend foundation: secure_session.py, secure_socket.py, node_session.py, network.py, hop_probes.py, hop_routes.py, tact.py, transport.py, capabilities.py. Browser foundation: secure_session.js, node_manager.js, device_client_v3.js, device_authority_v3.js, device_inbox.js, device_routes.js, private_routes_v3.js, core_engine.js.

- Спроектировать JS NodeRuntime/NodePeerChannel с чёткими владельцами identity, sessions, route tables, queues, local delivery. Имена предварительные.
- Сделать общие wire fixtures/test vectors Python↔JS для handshake, NODE_REGISTER/authorization, Probe/bind/status/data/batch/control и новых mailbox grants.
- Разделить socket identity/auth и ресурсные permissions. can_route не равно accept-any-route. Password/resource gates не обходятся через общий NODE role.
- Перенести browser mining в Worker, сохранить difficulty и ограничить concurrency/handshake admission, чтобы атакующий не заставлял узел бесконечно майнить встречные регистрации.
- Обеспечить socket reconnect, duplicate peer connections, cancellation, epoch/expiry и shutdown очистку. Проверить долгоживущие caches auth/bind: старый cached success не должен навсегда блокировать re-registration.
- Реализовать local Node submit API для Account payload и отдельный transit API. Ни один transit callback не обращается к активному Account.
- Преобразовать DeviceRouteRegistry/Inbox в локальные Node delivery structures с прежней blind Account mapping. Public local event работает без Account login; чужой locked Account получает encrypted pending, без автоматического входа.
- Приватные разрешённые маршруты локальной Node не ограничивать выбранным Account. При полном lock Node прекращает рекламу/пересылку, соседи восстанавливают topology.
- Продумать mailbox grant для offline recipient, retention/expiry/quota, owner proof после reconnect/restart. Не смешивать disposable routing keys с durable mailbox lifecycle.
- Существующие Node identities, Account identities и историю не обнулять. Новый локальный Node identity material мигрирует за storage root; привязки старого mailbox переносить с доказательством прежнего владения.
- Старый DEVICE gateway допускается только как явно версионированный ограниченный migration path с сроком удаления. Он не остаётся скрытым рабочим обходом новой policy.
- Обновить descriptor/capabilities и админ-инструменты. can_accept_devices убрать из новой wire-модели; старые конфиги распознавать через migration adapter, не сохранять два расходящихся источника истины.

**Ключевой тест N2:** N1 и N2 соединены только через браузер B, прямой обход отключён. Два других конечных тестовых участника обмениваются реальными encrypted payload через N1→B→N2. У B нет их Account keys и нет активного Account; наблюдается замена hop label и реальный receive/forward. Затем B исчезает, альтернативный путь восстанавливает доставку либо честно сообщается unavailable. Нельзя засчитать путь, который незаметно обошёл B.

## 8. N4: initial handshake, ratchet reliability, Inbox

- Явная per-peer state machine с attempt/session ID, фазами, ролями, transcript binding, pending/established separation.
- Детерминированное разрешение одновременной инициации. Поздний финал проигравшей/старой попытки не перезаписывает выбранный секрет.
- Key confirmation обязателен для ESTABLISHED. Локальный staticShared и NODE_ACCEPTED не являются подтверждением.
- Durable повтор одинаковых init/final/update capsules до подтверждения/явного TTL. Повтор не порождает несовместимый новый секрет.
- Recovery после односторонней потери состояния аутентифицирован и защищён от replay. Нельзя просто заменить ключ по любому новому 0x01.
- Зафиксировать peer/Account generation до await. Передавать pid явно; смена чата/Account не перенаправляет операцию и не записывает state в другой vault.
- Для ratchet: collision policy, последовательное изменение state на peer, durable update/ACK и доказуемый persist/send порядок. ACK-send=false не считается доставленным подтверждением.
- Для Inbox: per-record error isolation, временный retry, quarantine недопустимых пакетов, quotas и bounded attempts. Crash после Account persist до tombstone не дублирует сообщение.
- Для outbox: стабильный logical operation/message ID, backoff, cancellation и завершение по нужному peer receipt. Повторы не зависят от открытия чата и не засоряют историю control-пакетами.
- Contact Request/Accept/Confirm получают тот же дисциплинированный retry; сбой одного контакта не останавливает resume остальных.
- Версионировать новые handshake frames, проверить mixed-version refusal/migration без silent downgrade.

**Приёмка:** один/два инициатора, repeated click, loss/duplicate/reorder каждой фазы, crash/reload каждого участника на каждом переходе, односторонний stale state, смена чата, logout/lock, disconnected recipient, corrupted first Inbox record и валидный следующий. Проверять реальную двустороннюю переписку после recovery.

## 9. N5: ИБ и криптографические требования

### Срочные риски

- Убрать SHA-256 Master verifier в sys_m и всех repair/emergency путях. Versioned KDF/wrap verification и миграция без смены local root/identity. Политику PIN брать из актуальных явных требований; короткий PIN остаётся слабым даже при дорогом KDF.
- Закрыть legacy HTTP login/logout/connect/debug/read API в публичном runtime; auth и отдельная admin boundary. Проверить nginx exposure. CORS не является авторизацией.
- Разобраться с tracked 32-byte node_identity.key.basencrh. Проверить реальное использование; удалить runtime sidecars из поставки, настроить ignore/secret checks. Если использовался — выполнить разрешённую ротацию с recovery plan. Не публиковать значение, не force-push историю.
- Контролируемо мигрировать legacy mailbox/storage с backup и проверкой доступа. Не удалять старые ciphertext до доказанного переноса.
- Inventory dependencies/vendor WASM, актуальные advisories, воспроизводимая среда, CI runner/interop/secret checks на рабочей ветке и PR.
- Ограничить вредоносный transit: frame/parser bounds, очереди на peer/route/global, CPU/PoW budget, backpressure, malformed batches, loops/replay, fairness. Account UI должен оставаться доступным под разрешённой нагрузкой.

### PFS/PCS/PQ

Стабилизация epoch state machine — отдельный результат от выполнения PFS/PCS.

- Указать threat model для epoch root, полного Account state, identity key, local root, backup и живого runtime.
- Retention старых roots ограничить временем/эпохами и согласовать с out-of-order window. Нельзя одновременно обещать немедленное стирание и чтение сколь угодно старого ciphertext.
- После согласованной миграции убрать бессрочную поддержку legacy decrypt через staticShared/PSK и ненужные snapshots/capsules. Сохранённая история — отдельная поверхность, не «стирается ratchet».
- Выполнить требование свежего X25519 agreement для PCS; random seed, переданный только под уже раскрытым root, не считать восстановлением секретности.
- Hybrid update: свежая classical и ML-KEM энтропия, domain-separated combiner, explicit suite, no silent downgrade. Проверить происхождение bundled Kyber, соответствие ML-KEM, vectors и сборку; длины ключей не доказывают соответствие стандарту.
- Self-contained повтор update после потери первых копий; bounded epoch jumps; компрометационные тесты с точным моментом раскрытия состояния.
- Не обещать восстановление при постоянном контроле атакующего над клиентом или автоматически при украденной identity key. Перед security release нужен отдельный crypto review.

## 10. N6: private/password Nodes и installer

Исходный DEVICE-only password gate заменяется общей политикой доступа к Node peering/resources. Новый браузер имеет NODE role: оставленный только на DEVICE password check станет обходом.

- Объявить операции до/после password authorization: peering/transit, route advertisement, mailbox/store. Явно определить доверенные исключения конфигурацией, а не типом клиента.
- Сохранить исходную модель Argon2id-derived proof: random salt, bounded versioned KDF params, HMAC domain + authenticated transcript + nonce. Fresh proof каждой session; raw password не передавать и не логировать.
- Stored Kpwd — password-equivalent credential, не PAKE. Указать offline guessing границы; rate limits, cooldown, expiry/revocation/password change.
- Password в Node link — только fragment, сразу history.replaceState; никакого query/plaintext localStorage. Optional saved credential за локальным root.
- CLI --password, --password-file, --can-s-turn и ENV equivalents; безопасный ввод/file предпочтителен. Mode 600/minimal service permissions, no secret stdout.
- Installer idempotent, noninteractive, immutable revision pin, корректные systemd/nginx/firewall. Старый режим/config migration сохранить.
- Единый NodeDescriptor/versioned capabilities для Python/PWA/native, central directory пока остаётся. DHT не реализовывать.

**Приёмка:** wrong/missing/replayed password не даёт закрытых ресурсов независимо от реализации peer; correct работает; повторный install и смена credential корректны.

## 11. N7: S-TURN, calls/files, уведомления и статусы

Переиспользовать готовые runtimes. Переделать discovery/admission/invitations под Node-модель; Account identity в signaling не добавлять.

- can_s_turn канонический, can_be_turn — compatibility alias. Capability рекламируется только при рабочем signaling и реальной TURN allocation/relay health, не только открытом порте.
- Реальный coturn install/config/systemd/firewall только при capability; short-lived credentials, одноразовые scoped tickets, bounded queues/expiry/cleanup/rate limits.
- Call invitation идёт в encrypted recipient envelope; SDP/ICE через отдельный WSS, не Mesh MSG. Direct ICE и forced TURN relay проверить отдельно по RTC stats.
- Доделать custom ringtone/caller display из исходного задания: MIME/size/duration limits, decode/autoplay failures, consent и cleanup.
- Для locked Account нейтральный вызов без раскрытия имени — безопасная текущая политика. Более ранние требования показа caller_display_name после terminal decrypt и запрета раскрытия имени до Account login конфликтуют: зафиксировать выбранную privacy policy явно, не скрывать её изменением UI.
- File: consent, encrypted chunks/manifest/completion, integrity, cancel/progress, memory limits, resumable foundation; без file bytes в Mesh MSG fallback.
- Согласовать реальные размеры: текущий PWA limit 64 MiB и schema ceiling 50 GiB не равны поддержке 50 GiB. Большие файлы требуют streaming и отдельной приёмки.
- Opaque notification/wake: запускается local Node runtime → reconnect peers/auth → mailbox pull → local dispatch. Origin/Telegram не узнаёт Account semantics и не становится обязательным транспортом.
- Статусы UI/local API: SENT, NODE_ACCEPTED, LOCAL_NODE_FETCHED, LOCAL_NODE_STORED, DELIVERED, READ либо согласованные имена. В новую Mesh wire-модель не переносить endpoint semantics: NODE_ACCEPTED извне подтверждает лишь оговорённое хранение/приём соседней Node. Старое требование открытого destination-node подтверждения конфликтует с новым сокрытием endpoint; конечные гарантии передавать только end-to-end encrypted receipts и документировать эту смену семантики.
- Отправитель знает удалённый статус только по аутентифицированному подтверждению. Transit через браузер не означает доставку его Account. Locked Account не DELIVERED до decrypt/verify/persist.

**Приёмка:** реальный relay call, файл через TURN с hash, отмена/expiry/locked Account, degraded capability при падении coturn. Local direct-ICE fixture не засчитывать вместо relay acceptance.

## 12. Дополнительный E6-трек

Saved Messages и password-protected local history сохранить. Более поздний E6 milestone из handoff вести отдельно после устойчивого основного обмена.

Сначала зафиксировать точную модель компрометации и что скрывается: content, topology, keys. Versioned Argon2id descriptor, opaque handles, Worker/WASM и storage migration выполнять по согласованным требованиям. Worker сам по себе не защищает от полного same-origin runtime compromise. Local history protection не менять на transport encryption. Вложения Saved Messages — отдельный backlog, не придумывать как обязательное требование.

## 13. N8: обязательная приёмка

| Область | Обязательные сценарии |
|---|---|
| Unified protocol | Python↔Python, JS↔Python, при доступном адаптере JS↔JS; единая роль NODE, shared vectors, явная несовместимость старой версии |
| Реальный transit | N1→Browser B→N2 без обхода; B без Account login; label replacement/batching; B не читает payload |
| Отказ транзита | Sleep/close B, альтернативный путь, честный unavailable, recovery без global refresh |
| Local delivery | Account A active/B receives, B unlock, public event без Account, transit отделён от local Inbox |
| Contacts/handshake | Private/public flow, два инициатора, missing contribution, loss/reorder/duplicate, stale peer recovery |
| Ratchet | Concurrent update, lost ACK/capsule, N lost/N+1 received, epochs/retention, crash/persist |
| DNSS/resource auth | Directional lifecycle, reconnect/restart, wrong owner/session/proof, expiry, revocation |
| Mailbox | ALL/lease/send/delete, failed send, concurrent arrivals, client crash, верхнеуровневый retry |
| Mesh | Multi-path/fork, shorter path, limits/loops/dedupe, first-arrival 500 ms, queue fairness |
| Password | Нельзя обойти Node policy через implementation/role/operation; fragment/credential storage |
| Media | Real TURN allocation/call/file, expired tickets, consent/cancel, ringtone/file bounds |
| Migration | Existing Accounts/root/history/old mailbox; mixed-version; SW update; rollback storage compatibility |
| Security | Legacy API deny, secret scan, hostile transit, Node DB/log privacy, explicit compromise tests |
| Endpoint privacy | Origin/transit и termination/forwarding traces, Probe/metric/NCRH, одинаковый общий wire, packet correlation и browser/media fingerprint limits |

Полный `python tools/test_all.py` и новые suites запускать в зафиксированной среде; в предыдущей проверке использован Python 3.12. Test dependencies, включая httpx, должны быть воспроизводимы. Browser tests проверяют криптографию и transport без подмены; fault injection только воспроизводит потери/задержки/сбои. Не запускать WebAuthn-приёмку через неподдерживающий её браузер и не засчитывать mocks как real-device evidence.

Документация: актуальные README, CURRENT_HANDOFF, TRANSPORT_V3/новая версия spec, ROUTING_UPDATE, .env.example, installer docs. Одна текущая таблица статусов и SHA; старую Device-схему пометить исторической. Различать IMPLEMENTED/PARTIAL/PLANNED и UNIT/INTEGRATION/BROWSER/DEPLOYED evidence.

Перед release: full tests, review, secret scan, migration/backup/rollback, ordinary commit/push без force. Не сливать main только из-за green unit tests.

Deployment — в рамках действующей авторизации execution-сеанса. Сохранить исходный путь: `ssh ems-vps` → `su - jcode` → `cd D-MASH/tools/` → `test -x ./get_commit.sh` → `./get_commit.sh <FULL_PUSHED_SHA>`. Если отсутствует/fails — исследовать и сообщить, не импровизировать замену production deployment. Проверить фактический SHA Node/PWA/SW и повторить browser acceptance после deploy. Наличие опубликованных отдельных файлов не равно проверке полного развёртывания.

## 14. Связь с исходным заданием и итоговый отчёт

| Прежняя группа | Что сохраняется | Что меняется |
|---|---|---|
| A/B: foundation/DMP-C | Secure channel, vectors, auth/replay guards | Убрать разделение DEVICE/NODE, реализовать JS NODE peer |
| C/D: DNSS/mailbox | Directional auth, ownership, quotas, ALL drain | Node↔Node lifecycle и universal mailbox grants |
| E: Device envelope/dispatch | Терминальная encryption и multi-account isolation | Local Node delivery/Inbox; отдельного сетевого Device нет |
| F/G: labels/NCRH/batching | Hop privacy, bounds, first-arrival aggregation | Browser участвует в тех же алгоритмах transit |
| H: password Node | Argon2id/HMAC, fragment, encrypted credentials | Gate применим к NODE peers/resources; DEVICE-only удалён |
| I/J/K: S-TURN/calls/files | Отдельный signaling, TURN, file crypto, ringtone | Discovery/invitations/admission через новую Node-модель |
| L: E2EE ratchet | Account ownership, loss/reorder, целевые PFS/PCS | Исправить state machine и закончить криптографический delta |
| M: acceptance/deploy | Exact SHA, реальные сценарии, честные ограничения | Обязателен доказанный транзит через браузер |

Первый reviewable результат: **N0–N2**, то есть новая спецификация, failing regressions и реальный JS Node transit без Account login. Следующий: **N3–N4**, рабочие контакты/переписка и recovery через новую модель. Не распыляться на DHT, UI redesign и новые возможности до этих двух результатов.

После этапа сообщать diff/решение/tests/SHA/остаток. Итог: статус N0–N8 и исходных A–M/E6; protocol/migration changes; реальные PASS/FAIL/NOT RUN; privacy delta; pushed/deployed SHA; результат get_commit.sh; backlog. Не заявлять новый Mesh реализованным, если клиент лишь назван Node, но не пересылает чужие пакеты.
