# Алгоритмы самостоятельного Node daemon

20 октября 2026. **Проект алгоритмов, не новый PASS.** База `9446c22f27309131456942870971d477f6f2358f`. Границы ключей, факты QR и вопросы Q1–Q5 — [NETWORK_DAEMON_ARCHITECTURE.md](NETWORK_DAEMON_ARCHITECTURE.md). Файловый custody профиль — [BUFFERED_FILES.md](BUFFERED_FILES.md). Ни один алгоритм после handoff не вызывает Account, не открывает его vault и не создаёт Account receipt.

## 1. Состояния и инварианты

| Объект | Состояния / устойчивое содержимое |
|---|---|
| Host | LOCKED → STARTING → RUNNING; SUSPENDED, STOPPING, RECOVERY_REQUIRED. Root/owner generation, encrypted journal. Account logout не равен LOCKED. |
| Peer | CANDIDATE → DIALING → AUTHENTICATING → AUTHORIZED; BACKOFF, REVOKED. Pinned trust, auth generation, fresh session epoch, admission/grants отдельно. |
| Route | MATERIAL_PENDING → INSTALLED → DISCOVERING → READY; STALE, REVOKED. Directional locator/authority, route generation, local destination capability. |
| Job | LOCAL_DURABLE → WAITING_BOOTSTRAP/WAITING_PATH → IN_FLIGHT → TRANSPORT_COMPLETE; EXPIRED, CANCELLED, FAILED_POLICY. Custody profile уточняет completion как CUSTODY_CONFIRMED. |
| Inbox | COMMITTED → OFFERED → CONSUMED; QUARANTINED, EXPIRED по разрешённой policy. COMMITTED не означает decrypt/DELIVERED. |

Node identity, route ID, route authority, DNSS/grant, hop label, local job ID и session epoch — разные поля и разные lifetimes. Отдельный stable Node HELLO public key в нынешнем коде не следует отождествлять с Device encryption public key пользовательской концепции. Не менять Node identity ради AB/BA/AC. Reconnect меняет session binding; обычная route rotation — route generation; wrapping rotation — шифрование storage. Ни одно не пересоздаёт Account identity/history.

Схема ledger: `jobs`, `attempts`, `inbox`, `dedupe`, `routes`, `grants`, `policy`, `owner_generation`. Encrypted records включают проверяемые owner/direction/generation/schema/digest. Индексы — локальные blind aliases; AccountID не переносится в route KDF, mailbox alias или wire. Транзакции сериализованы одним owner и CAS generation; непрозрачность индекса не заменяет проверку полномочий.

**Предлагаемый стартовый bounded profile**, подлежащий нагрузочной приёмке: 8 активных соседей, 32 кандидата, 4 introductions/ответ, 2 concurrent dials, 1 identity/resource mining worker, 1 scheduler train; candidate TTL ≤10 min, dial deadline 30 s; retry full jitter `U(0,min(60s,1s·2^k))`. Peer/session/route expiries и существующая protocol difficulty не ослабляются. Bytes/jobs/retention quotas задаются обязательной конечной конфигурацией до запуска; profile без них невалиден. Network failure retries прекращаются по deadline/TTL/cancel, не по Account login.

## 2. Единственный owner и локальный handoff

```text
startHost(scopedTransportBundle, brokerUnlockGrant):
  validate broker grant, bundle purpose/generation; never receive full root or Account keys
  acquire OS exclusive lock; if busy: attach IPC to current owner
  tx: verify storage schema/root binding; increment durable ownerGeneration
  construct adapters fenced by ownerGeneration; recover committed jobs/leases
  start ONE scheduler; advertise only currently authorized routes

submit(callerCap, destination, callerOp, ciphertext):
  authorize callerCap/destination; validate size and current quota/policy
  tx under current ownerGeneration:
    key = (callerScope, destination.localId, callerOp)
    if exists: require identical digest; return existing JobHandle
    persist own ciphertext copy + destinationRef + TTL + LOCAL_DURABLE
  after commit: signal scheduler; return durable acceptance
```

Crash до commit → submit не принят; после commit до IPC reply → тот же callerOp возвращает прежний JobHandle. Stale owner не пишет ledger и не отправляет новые frames. Последняя проверка generation/policy выполняется в adapter непосредственно перед I/O, а не только при постановке в очередь. Full root lock отзывает broker grant/transport bundle и закрывает sockets/keys; pending operations получают local reason без удаления bytes. UI restart не запускает второго daemon. В текущем browser Host запрет второго owner ограничен root session в JS realm: [node_runtime_host_v4.js](https://github.com/Seriy615/D-MASH/blob/9446c22f27309131456942870971d477f6f2358f/D-MASH%20PWA/not_messenger/js/node_runtime_host_v4.js), `8+`; новый OS fencing ещё предстоит реализовать.

Account commit plaintext и Inbox consumption не объединяются фиктивной cross-process транзакцией. Приложение устойчиво коммитит operation ID, затем `commitConsumption`; crash между ними приводит к повторному чтению и идемпотентному application commit. После handoff transport не ждёт этого marker.

## 3. Bootstrap, peering, reconnect

```text
onNeedPeers(now):
  budget = min(8-readyPeers, 2-dialsInFlight)
  candidates = fairSelect(persistedPinnedPeers, configuredSeeds, unexpiredIntroductions)
  for candidate in candidates.take(budget):
    require policyAllowedEndpoint(candidate) and diversity/source/rate budgets
    dial until deadline; authenticate current DMP-C NODE profile and pinned trust
    require fresh transcript/replay state + Node admission/password policy
    install sessionEpoch; separately authorize directional resource grants
    if success: READY; reset backoff; rebind valid routes; wake affected jobs
    else: retain jobs; schedule bounded jitter; quarantine repeated invalid auth
```

Introduction не считается pin/route grant. Не публиковать полную neighbor map; короткоживущие предложения не включают Account contacts/DeviceRoot fingerprint. DNS resolution/redirect и final endpoint повторно проверяются перед dial; private/link-local/admin targets запрещены, кроме явно разрешённых локальных peers. Неизвестный origin не получает дорогое mining по каждому запросу. Circuit breaker одного peer не останавливает остальных.

Duplicate socket: один coordinator выбирает current session по согласованному profile/connection attempt, старую epoch fences. Session sequence/replay windows сбрасываются только новым authenticated handshake. Исчезновение peer делает его bindings stale и запускает affected-route recovery, не global refresh. BACKOFF прерывается явным network-change event с rate limit, не циклом polling. Смена IP не меняет identity или logical jobs.

## 4. Направленные маршруты и discovery

Текущий PRIVATE v3 выводится из кода, без нового route-ID minting:

```text
pair(ownContribution, peerContribution, generation):
  validate 32-byte contributions; reject equality; require generation >= 1
  root = HKDF(sorted(contributions), domain=ROUTING_ROOT_V1)
  for direction in [A_TO_B, B_TO_A]:
    signSeed = HKDF(root, PRIVATE_ROUTE_AUTHORITY_V3|direction|generation)
    boxSeed  = HKDF(root, PRIVATE_ROUTE_DEVICE_BOX_V3|direction|generation)
    signing, box = existing NaCl key derivations(signSeed, boxSeed)
    routeId = SHA256(PRIVATE_LOCATOR_V3 || signing.publicKey)
  assign inbound/outbound by contribution ordering; wipe temporary secrets
```

Это конспект [private_routes_v3.js](https://github.com/Seriy615/D-MASH/blob/9446c22f27309131456942870971d477f6f2358f/D-MASH%20PWA/not_messenger/js/private_routes_v3.js), `7–37`, а не новая криптосхема. Обе стороны выводят обе directions и secrets; credential доказывает владение route authority, **не sender Account identity**. V1 fallback использует другой locator domain: [core_engine.js](https://github.com/Seriy615/D-MASH/blob/9446c22f27309131456942870971d477f6f2358f/D-MASH%20PWA/not_messenger/js/core_engine.js), `473–537`. Не смешивать версии/alias в migration. Bundle/certificate verification и Account E2EE authentication остаются раздельны.

```text
installDestination(authorizedLocalOwner, profile, material):
  verify profile/owner/material/generation and encrypted storage binding
  tx install inbound route secrets + outbound route box public + local handle
  no Account lookup on future transport operations
  advertise registered inbound route via existing START_PROBE semantics

onProbe(authenticatedPeer, packet):
  validate exact schema/size/hop-limit/trace/lifetime + resource authority
  answer NCRH knowledge in route context; bounded pending state if material absent
  reject loops/replay/stale bindings; install bounded alternate paths
  prefer shorter valid metric; stable tie policy; NCRH is never auth or tie ID
  propagate only within remaining hop/random-limit and byte/CPU budget
  on local material import: reconcile relevant pending route, not global restart
```

[hop_probes.py](https://github.com/Seriy615/D-MASH/blob/9446c22f27309131456942870971d477f6f2358f/D-MASH/client/backend/hop_probes.py), `350+`: Probe рекламирует путь назад к зарегистрированному инициатору, а не ищет recipient. `receive_probe` ограничивает metric/trace и remaining hops; `UNKNOWN` recovery существует. Нынешний root начинается с общего `derive_ncrh_root`; целевой route-bound NCRH и random hop-limit contract требуют отдельного Q2 delta/interop vectors. Не выдавать целевое свойство за готовое. Нельзя без анализа удалять метрику или менять discovery на blind DATA flood.

Binding key включает peer/session epoch/direction/route generation и локальный label. Угаданный route ID, NCRH или скопированный label не дают register/read/delete. При forwarding incoming label заменяется outgoing label; local Inbox и onward используют общий разрешённый класс frames, без terminal/origin flags. Остаточная корреляция ciphertext/timing/metric/trace проверяется отдельно.

## 5. Scheduler, retries, dedupe и backpressure

```text
schedulerTick():
  assert currentOwner and not alreadyRunning
  select bounded ready jobs by fair per-peer/per-route budgets
  for job:
    reload effective policy/generation; check TTL/cancel/revoke
    if no grant/bootstrap: persist WAITING_BOOTSTRAP; continue
    if no allowed current path: persist WAITING_PATH; trigger scoped discovery; continue
    tx: persist attempt(peerScope, direction, routeGeneration, bytesDigest, nextAt)
    enqueue ciphertext in same bounded batching pipeline as foreign transit
  reschedule ONE earliest deadline; finally release running token

adapterSend(frame):
  check current owner/session/route/grant/policy immediately before each write
  if denied: retain permitted durable bytes; return blocked; never flush forbidden queue
  send under authenticated outer channel; use profile-specific completion condition
```

`IN_FLIGHT` и socket send success не равны удалённой durability. В baseline успешная отправка помечает лишь согласованный transport result; нет доказанного durable receipt — нет CUSTODY_CONFIRMED. Ожидание Account receipt не является network timer; Account может позднее создать новый opaque control job.

Сохранить [tact.py](https://github.com/Seriy615/D-MASH/blob/9446c22f27309131456942870971d477f6f2358f/D-MASH/client/backend/tact.py), `13–56`: первое поступление в IDLE ставит **один deadline +500 ms**, следующие его не сдвигают; snapshot swaps до route/socket awaits, пустой IDLE без periodic timer. Per-peer FIFO senders и quotas отделяют медленного peer. Retry не создаёт параллельные timer trains. Full disk/queue отклоняет новое acceptance, не обнуляет старое состояние. Dedupe scoped к authenticated route/peer/direction/generation и bounded horizon; те же bytes/attempt идемпотентны, другой digest — reject. End-to-end operation dedupe у Account отдельно: бессрочное exactly-once сеть не обещает.

## 6. Authenticated direct/NAT и policy transition

```text
tryPath(job, relationship):
  if currentPolicy.direct == off: return allowedRelayOrWait()
  request short-lived rendezvous over existing authenticated route
  verify expected peer/route+auth generation/attempt/expiry/replay quota
  gather only policy-allowed host/reflexive/relay candidates
  send encrypted candidate capsule only to that peer
  bounded ICE checks; on viable pair perform existing Node mutual auth/admission
  require carrier transcript binding to rendezvous attempt
  direct deadline -> allowed relay; absent relay -> WAITING_PATH

applyPolicy(adminCap, newPolicy):
  tx commit validated policyVersion + transition tasks
  fence adapters against all forbidden sends, including old queued retransmits
  cancel forbidden ICE checks; erase forbidden candidates; close forbidden carrier
  start allowed alternate path without Account callback
```

Policy update linearizes at committed version; writes already issued to OS before deny нельзя «отозвать», но после commit ни один новый forbidden adapter write не допускается. Candidate capsule не допускает сканирование arbitrary addresses/ports; fresh ICE credentials не заменяют D-MASH peer auth. Relay-only не собирает/не отправляет запрещённые host/reflexive candidates, не делает скрытых direct probes. При mobility/sleep/expired consent помечать path stale, делать bounded ICE restart/auth и сохранять те же jobs; keepalive не гарантирует NAT доступность. Normative mechanics: [RFC 8445](https://www.rfc-editor.org/rfc/rfc8445.html), [RFC 8489](https://www.rfc-editor.org/rfc/rfc8489.html), [RFC 8656](https://www.rfc-editor.org/rfc/rfc8656.html), [RFC 7675](https://www.rfc-editor.org/rfc/rfc7675.html). Новый native carrier ещё не выбран и не проверен.

## 7. Mailbox baseline и отдельный durable-custody-v1 proposal

**Существующее поведение сохраняется явно:** remote ALL snapshot → lease → awaited send → delete; failed send снимает lease. [node_mailbox_v4.py](https://github.com/Seriy615/D-MASH/blob/9446c22f27309131456942870971d477f6f2358f/D-MASH/client/backend/node_mailbox_v4.py), `186–247`. Client crash после успешного send/server delete до durable Inbox commit теряет пакет. Это не закрывается повтором PULL. Обязательный клиентский ACK к старому PULL не добавляется.

**Предлагаемый negotiated `durable-custody-v1`** из [BUFFERED_FILES.md](BUFFERED_FILES.md): отдельный профиль с cached directional recipient-inbox grant (opaque namespace, scoped write/read, route generation, expiry/quota, recipient route box key); 1..3 fixed anchors на job. До provision — WAITING_BOOTSTRAP; daemon может provision позднее из уже авторизованного relationship без Account callback. Отсутствие всех anchors означает unavailable, не глобальный lookup. Sealed invitation и encrypted signed locator capsule сохраняются как durable bundle; mutable blob providers и location state принадлежат daemon. Сетевой receipt не является Account receipt.

```text
acceptCustody(session, transfer):
  require negotiated profile and live directional write grant
  validate exact bytes/digest/expiry/quota/route generation
  key = (grant.namespace, direction, generation, peerScope, transferId)
  tx under current owner:
    if key exists: require same locally-computed digest; return prior decision
    persist encrypted bytes + retention contract + dedupe/receipt record
  after commit: send authenticated scoped persist receipt

receiveCustodyReceipt(receipt):
  verify expected custodian/transfer/digest/direction/generation/retention
  tx mark exact attempt CUSTODY_CONFIRMED
  retire sender copy only if accepted contract permits
```

В новом профиле PULL/read **не удаляет** remote records; authenticated persist ACK удаляет только exact records после durable receiving daemon commit. Lost ACK → bounded replay того же transfer/digest; crash до commit → retry; после commit до ACK → прежний receipt без второй записи. Expired grant не даёт новых writes; replay прежнего receipt допускается только по заранее специфицированному узкому owner/digest/retry-horizon contract. Ledger retention ≥ retry horizon; после его окончания нет слепого обещания exactly-once. Chunk custody аналогично подтверждается после durable provider commit. Злонамеренный custodian может лгать/исчезнуть: receipt не доказывает будущую доступность. Снижение quota не стирает принятые contracts. Negotiation с legacy peer честно оставляет baseline loss window, без silent downgrade сохранности.

## 8. Generations, revocation и миграция

Reconnect: fresh channel epoch, те же identity/route material, reauthorization и новый session-bound proof. Route rotate: staged route generation+1, bounded overlap, подтверждённый rebind/grant migration, durable anti-rollback floor. Не выводить новые identity keys на каждую пару. Root wrapping меняется отдельно. Потеря state/старый backup → RECOVERY_REQUIRED; не генерировать новые contributions/identity молча. При shared authority односторонний отзыв второго обладателя route secrets не доказан: Q2 решает re-pair/revocation trust, а не косметическую смену alias.

Миграция: инвентаризация profile/owner/schema → protected backup → authenticated read/ownership proof → transactional versioned copy → verify identities/history/route bindings/queue digests → switch единственного writer → retained rollback compatibility. Legacy mailbox не удалять до доказанного переноса доступных ciphertext. Legacy send-delete loss window не превращается задним числом в durable guarantee. Не мигрировать чужую очередь по знанию alias. Mixed-version incompatibility показывается явно; старый gateway только ограниченный migration profile.

## 9. Acceptance gates и attacks/failures

Все строки ниже **NOT RUN для предлагаемого native daemon**. Каждый gate фиксирует exact SHA, platform/OS, scenario, captured evidence и ограничения; mocks доказывают только локальный механизм. Решения Q1–Q5 из соседнего документа принимаются независимо.

| Gate | Проверка и критерий |
|---|---|
| G1 identity/routes/QR (Q1/Q2) | Retained root/Account/Node keys; actual PRIVATE/PUBLIC v1 и managed-v4 UI import/export; AB≠BA≠AC, reconnect сохраняет direction; wrong generation/owner/session/label не даёт resource rights. Contribution holder не получает ложное Account sender-auth. |
| G2 owner/handoff (Q3) | Два native процесса; kill до/после каждого tx/IPC reply; retry submit даёт один job; stale owner не пишет/не sends; disk full отказ до acceptance; backup restore не снижает floor. |
| G3 Account-free progress | Submit → logout/close UI; sender retry/route change/recipient encrypted Inbox/foreign transit работают без Account keys/callback. Account unlock позже даёт один verified application commit; DELIVERED отсутствует до Account receipt. Full root lock честно останавливает runtime. |
| G4 discovery/batching (Q2) | Реальный N1→B→N2 с отключённым bypass и без Account у B; наблюдаем label replacement. Probe-before-contribution, UNKNOWN NCRH, loops, shorter alternate, loss B/reconnect. Fake clock: first-arrival 500 ms, no idle timer; real transport подтверждает порядок/fairness. |
| G5 host lifecycle (Q3) | Desktop service restart; физический Android screen-off/sleep/background denial/reboot/roaming; UI отображает реальную suspension/unavailable, identity/queue сохраняются. Browser Worker fixture не заменяет native gate. |
| G6 NAT/policy (Q4) | Два независимых реальных NAT: direct подтверждён capture/carrier stats; forced TURN relay отдельно. Candidate tamper/replay/wrong peer/endpoint SSRF reject; Wi-Fi→mobile recovery. Direct-off при queued retry: после policy commit нет новых direct writes/probes/candidates; relay outage оставляет wait. |
| G7 custody (Q5) | Baseline loss window воспроизведён и обозначен. Новый профиль: drops/duplicates/reorder, lost ACK, crash перед/после persist/read/delete, grant expiry/revoke, all anchors lost, chunk/provider move, recipient offline. Bytes не потеряны в пределах принятого retention; mixed-version не обещает durability. |
| G8 hostile load/privacy | Oversize frames/batches, Sybil introductions, PoW storms, replay/flood, slow peer/full disk bounded; остальные peers и UI продолжают progress. Сравнить local-origin/transit/local-Inbox/onward traces; stable Node key/metric/trace/media/timing/ciphertext correlation записаны как limits. |
| G9 migration/release | Existing encrypted history/routes/mailbox retained без reset; wrong-owner migration reject; rollback/restore на тестовых profiles; full UNIT + real browser flows + native/interop gates по exact SHA. DEPLOYED считается отдельно, не по наличию файлов. |
