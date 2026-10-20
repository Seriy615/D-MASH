# Независимая исполняемая проверка плана — 20 октября 2026

Product source: `9446c22f27309131456942870971d477f6f2358f`.
Изменены только audit artifacts. Это UNIT actual-source crypto и SPEC MODEL;
новой browser/native/deployed приёмки здесь нет. Исторические browser PASS
сохраняют свой исходный scope и не означают «все кнопки проверены».

## Запуск

Из repository root, Node.js 24 и Python 3:

```sh
node docs/audits/2026-10-20/verification/check_actual_crypto.cjs
node docs/audits/2026-10-20/verification/check_actual_argon2.cjs
node docs/audits/2026-10-20/verification/check_master_secret_repro.cjs
python3 docs/audits/2026-10-20/verification/spec_fault_model.py
node 'D-MASH PWA/not_messenger/tests/private_routes_v3.test.js'
node 'D-MASH PWA/not_messenger/tests/device_envelope.test.js'
```

Все данные synthetic, keys/contributions не печатаются. Проверка actual JS
загружает repository modules, включая bundled NaCl и actual HKDF; функции не
копируются и crypto не mock-ается. Результаты JSON содержат source SHA,
хеши загруженных crypto source или модели, версию runtime и limits. Набор
состояний модели ограничен depth 12 и двумя копиями пакета; запуск занимает
секунды, не требует сети, сторонних Python packages или changes storage.

Фактический свежий запуск: Node `v24.19.0` из official nodejs.org archive;
SHA256 archive `14b342e71204f811bde6153be8e04b62aef63c236fef92b55f9c83154b409647`,
сверен с official `SHASUMS256.txt`. Указанный ранее temporary Node path отсутствовал;
использован `/tmp/dmash-plan-verification-node/node-v24.19.0-linux-x64/bin/node`.
Две существующие suites выше также PASS. Full test suite заново не запускался:
его прежний результат принадлежит основной аудиторской сводке, не этому gate.

## Actual Argon2 dispatch: подтверждённый compatibility дефект

`check_actual_argon2.cjs` загружает **actual vendor JS и repository WASM** в
browser-like VM. Top-level `argon2.argon2id` отсутствует; enum находится в
`argon2.ArgonType.Argon2id=2`. Вызов с undefined type (как DeviceRoot/Core)
даёт тот же результат, что explicit Argon2d, и другой, чем explicit Argon2id;
encoded result также сообщает `$argon2d$`. Non-minified product JS alias
assignment не найден. JSON содержит exact hashes vendor JS/WASM и callers.
Это synthetic public vector с уменьшенными memory/time, проверка actual type
dispatch; не реальный Account unlock или browser loader gate. Node admission
использует правильный enum отдельно — нельзя обобщать дефект на все вызовы.

Исправление не может молча менять enum у существующих Accounts: это изменит
детерминированные Account keys и root wrapping key. Нужны explicit legacy
profile, retained-key fixed vectors, versioned wrap и rewrap **того же root**;
Account migration имеет отдельную совместимость. Label `argon2id` и test stub
с `argon2id:2` не доказывают actual type. Это не доказательство взлома Argon2d;
быстрый SHA-256 PIN verifier остаётся отдельной проблемой.

## Grounded crypto facts

- `D-MASH PWA/not_messenger/js/private_routes_v3.js:23–42`: pair принимает
  две 32-byte hex contributions и generation. Сортированный concat → actual
  HKDF (`secure_session.js:52`) routing root → разные HKDF domains для
  directional Ed25519 signing seed и X25519 recipient secret; locator —
  SHA256 domain + directional signing public key (`private_routes_v3.js:7–21`).
  Проверены A.out = B.in, B.out = A.in по locator, signing secret и box secret;
  направления и третий peer различаются. Account ID не входит в этот KDF.
  Runtime Account-independent helper не доказывает независимость всего transit.
- Generation имеет actual validation safe integer ≥1; проверены invalid inputs,
  max safe integer и отличающиеся generation keys. `pair` не хранит monotonic
  generation floor, не проверяет freshness и не реализует antirollback сам.
- Contributions — **секретные capabilities относительно наблюдателя**, даже
  если пользователь публикует QR. V1 QR/copy payload содержит Account ID и
  contribution (`core_engine.js:3483–3486`, `runtime_fixes.js:436–442`,
  `acceptance_fixes.js:60–69`). Обе captured contributions достаточны для
  восстановления **обоих** route authority signing secrets и recipient box
  secrets; actual-source test это воспроизводит. Этот KDF не DH agreement.
  Это не утверждение о взломе Account E2EE, не общий вывод обо всех V4 bundles,
  и не доказательство, что конкретная текущая UI ветка показывает именно V1 QR.
  Поэтому public exchange/QR требует отдельной модели угроз; нельзя обещать
  route secrecy против наблюдателя, собравшего обе contributions.
- `device_envelope.js:31–75`: ephemeral NaCl box к route recipient public key;
  wire имеет только `c,e,n,v`, без static recipient field. Actual roundtrip,
  wrong-peer и wrong-generation rejection PASS; semantic fields скрыты.
  Любой знающий recipient public key может создать валидный outer box — это
  **не Account sender authentication**. Последняя принадлежит проверяемому
  внутреннему Account протоколу. Отсутствие поля не доказывает anonymity,
  endpoint indistinguishability или защиту от traffic analysis.

## Исполняемая SPEC MODEL

`spec_fault_model.py` — отдельная конечная модель предложения о stronger custody,
не implementation существующего mailbox. BFS реально перебирает interleavings:
lease/send/retry, packet loss/duplicate, receive, atomic persist, crash/restart,
lease expiry, receipt loss/verify, remote delete, Account offline/online,
policy revoke, address mobility, transit и Account delivery. Stable message ID
задаётся моделью; unique local job — atomic upsert по нему. Custody receipt
здесь символически authenticated/message-bound; crypto/key lifecycle не доказаны.

Invariants: после удаления remote не теряется последняя custody copy; ≤1 local
job для stable ID; DELIVERED только после Account decrypt/verify/persist. Новые
send/receive запрещены после policy revocation; уже durable данные остаются
локально доступны. Forward action имеет witness именно **после Account offline**;
address change не меняет stable ID/durable state; delivered witness проходит
mobility. Это safety в пределах модели; бесконечная потеря пакетов/вечный offline
не имеют обещания eventual delivery. Policy change semantics — явно выбранное
предложение для этой модели, не описание всех production flows.

Отдельный BFS local handoff (depth 9) перебирает IPC reply loss, повтор того же
caller/destination-scoped operation ID, atomic persist, crash/restart и удаление
application transport intent. Safe вариант не теряет последнюю копию и возвращает
один daemon job. Negative controls: return-before-persist → caller удаляет intent
→ crash теряет volatile request; non-unique persist → repeated submit создаёт
два jobs. Проверка конфликтующего digest символическая; IPC auth не реализован.

Negative controls должны находить контрпримеры, иначе runner FAIL:

| Вариант | Ожидаемый counterexample |
|---|---|
| send→delete без durable custody | lease → send → loss → delete: copy lost |
| ACK после volatile receive | receive → ACK → crash → ACK verify → delete: copy lost |
| нет atomic dedupe | два receive/persist: два local jobs |
| нет authenticated receipt gate | forged receipt → delete: copy lost |
| custody назван DELIVERED | local custody без Account commit: false DELIVERED |

`durable_authenticated` не имеет counterexample в bounded exploration; JSON
содержит точные counts, event coverage и witnesses. Это не формальная проверка
production storage, browser process crash, OS fsync, native transport или NAT.
Два одинаковых network экземпляра симметричны: их порядок принятия и потери
перебирается как количество 0–2; multiple-message ordering не моделируется.

## Существующий mailbox contract

`D-MASH/client/backend/dnss_mailbox.py:129–142` делает reserve/lease → await send
→ delete leased snapshot; failure освобождает lease. Новые arrivals не входят
в snapshot. `node_mailbox_v4.py:217–246` дополнительно проверяет authority/rebind,
expiry, guard до/после send и `False` return, затем удаляет. Ни один из этих
фрагментов не требует durable authenticated custody ACK от получателя.

Send completion не является доказанным remote durable persist. Контрпример
модели показывает границу более сильной гарантии, **не нарушение согласованного
пользовательского ALL/lease/send/delete contract**. Если нужна передача custody,
необходимо отдельно согласовать versioned receipt, stable IDs, persist-before-ACK,
ACK retry/dedupe, receipt authentication и retention. NODE_ACCEPTED/custody и
Account DELIVERED/READ должны иметь разные основания; без Account receipt
нельзя ставить отправителю DELIVERED.


## Дополнительные review artifacts

[MASTER_SECRET_FIX_DESIGN.md](MASTER_SECRET_FIX_DESIGN.md) и
[MASTER_SECRET_REPRO.json](MASTER_SECRET_REPRO.json) содержат source/loader
inventory, actual full-cost Argon2/WASM + root-wrap synthetic checks и проект
безопасной миграции. Cross-store failure ordering использует rewrap spy;
это mechanism repro, не реальный persistence crash. Runner сохранён как
[check_master_secret_repro.cjs](check_master_secret_repro.cjs); он печатает только
synthetic public vectors/results и поддерживает `--repo` для запуска из зеркала.
Actual Argon2 dispatch дополнительно воспроизводится `check_actual_argon2.cjs`.

[NATIVE_HOST_FEASIBILITY.md](NATIVE_HOST_FEASIBILITY.md) фиксирует отдельный
Linux C/QuickJS compile/source-load proof. Независимый повтор executable также
exit 0: UTF-8 shim, NaCl Ed25519, resource SHA-256, BLAKE3, recipient seal/open,
exports routing/ownership; загружены 25 unchanged modules. Четыре исходных artifact hashes
совпали с note; исходники/вывод сохранены в [native-proof](native-proof/README.md)
с portable build recipe и manifest 25 embedded original modules. Это не Android/Qt build, WSS/SQLite runtime, full WebCrypto port
или NAT acceptance; выбор engine остаётся кандидатом до dual-target gates.
