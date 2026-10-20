# Browser QA — baseline до исправления runtime readiness

20 октября 2026 UTC. **Исторический FAIL; общий gate не закрыт.** Результаты ниже восстановлены из сохранённых в разговоре tool outputs после reboot хоста. Исходный browser profile, raw CLI logs, screenshots, temporary checkout и owning storage exports из `/tmp` утрачены. Это не новый прогон, не восстановление backup и не post-update retest. Native Windows/Linux/Android acceptance не выполнялась этим проходом.

Исходная страница: `http://127.0.0.1:9179/`, Chromium, mobile viewport 430×932, release `transport-v3-node-preparation-20261020.38`, default `legacy-migration`, SW blocked/uncontrolled. Product baseline при открытии — `9446c22f27309131456942870971d477f6f2358f`. Все nonlocal HTTP и все WebSockets блокировались browser routes: positive network delivery не проверена, production connections не выполнены. Браузером владел `files_policy_correction` после передачи root; проверки выполнялись UI clicks/input, без вызова Core handlers из console. Read-only metadata дополняли видимый результат.

Позднее на диске того же serving checkout началось написание candidate readiness fix; исходный page **не перезагружался**, его отсутствующие handlers сохранялись. Поэтому поздние наблюдения относятся к уже загруженному старому page; byte-exact совпадение всех поздних fetched responses с одним disk tree не заявлено. После reboot root восстановил durable checkout `/home/jcode/D-MASH`; новый candidate требует отдельного exact-source gate.

[Восстановленные наблюдения](BROWSER_QA_RESULTS.json), [late runtime markers/hashes](runtime-delayed-boot.json), [матрица control classes](BROWSER_QA_MATRIX.md). Матрица отделяет PASS конкретного пройденного сценария от непройденных дополнительных cases; она не означает all-controls PASS. Source inventory восстанавливается отдельно; stable IDs сохранены, 133 из 178 исходных labels восстановлены точно из tool output, остальные 45 восстановлены из фактического source в [инвентаре](UI_CONTROL_INVENTORY.md); это новые labels, не восстановленные байты исходного JSON; первоначальные counts — 178 stable classes, 304 binding/widget source lines, 86 source hashes.

## Ошибки, владелец и retest

| ID | Приоритет / владелец | Реальные шаги и результат | Статус |
|---|---|---|---|
| UI-BOOT-CONVERGENCE-01 | P1 функциональный blocker; root + plan_verification, security/runtime readiness | Fresh setup заняла больше 120 s до lazy Core. Скрипты runtime/acceptance загружены, но Core имел только V51 markers. Настройки остались stock. `[+]` → синтетический contact → `ОБМЕНЯТЬСЯ КЛЮЧАМИ` вызывает `TypeError: Core.beginKeyExchange is not a function`, UI не объясняет ошибку. Global Public Routes → copy вызывает `TypeError: Core.copyPublicContactLink is not a function` | **FAIL**, audit bugfix назначен; candidate и browser retest после reboot ещё не подтверждены этим документом |
| UI-BOOT-CONVERGENCE-01 / logout child | P2; тот же owner | Actual Account logout оставил DeviceRoot unlocked и Account keys cleared. Затем global Quick Names потребовал «СНАЧАЛА РАЗБЛОКИРУЙТЕ УСТРОЙСТВО». Отсутствующая синхронизация Core.deviceState не позволяет выполнить global operation без повторного master unlock | **FAIL**; проверить после readiness fix на retained fresh test profile |
| UI-BIO-CANCEL-01 | P2; security/local credential UX owner | Manager → ADD KEY → реальное удержание `7` 1.3 s → headless PRF enrollment отказ. OK оставляет calculator mode 6 без Back/Cancel. Ввод master возвращает gate, но mode 6 остаётся; Account logout позже вернул mode 0 | **FAIL** удобного выхода; успешная OS biometric enrollment/unlock **NOT RUN** |
| UI-GLOBAL-FLIP-REFRESH-01 | P2; readiness/UI owner | Global flip toggle вызывает stock account settings modal; underlying global label остаётся OFF при stored policy ON. Через UI policy восстановлена OFF. Вероятный descendant незавершённой wrapper chain; отдельный retest обязателен | **FAIL** в late profile; не засчитывать изменение localStorage как правильный UI refresh |

Root независимо проверил другой fresh early profile: actual master unlock около 52,413.7 ms от page start; Core имел V51, functional repair, public-contact, V50 reload/hooks, V50 и node-account markers. Early Contact Link copy сработал. Это поддерживает timing diagnosis; его raw profile и временный evidence также не считаются восстановленными после reboot. Не подменять этим retest позднего профиля.

## Реально выполненные сценарии

PASS здесь всегда ограничен указанным действием/состоянием; доставка, OS и conditional alternatives отдельно остаются NOT RUN.

| Case | Действие и видимый результат | Результат |
|---|---|---|
| ROOT-CALC | Root до передачи: все фактические 19 calculator buttons использованы в операциях `9+1`, `8−3`, `7×6`, `4÷2`, `100%`, sign и decimal. Упоминание «20 keys» относилось к шагам; поздний DOM count = **19 buttons** | PASS basic clicks; bounds/repeated-input matrix NOT RUN |
| ROOT-SETUP | Слишком короткий master rejected; master/wipe setup; настоящий master unlock; empty Account list back; intentional empty Account login error; save checkbox; создание/вход synthetic Account | PASS в root-owned baseline до передачи |
| ROOT-SAVED | Saved Messages: empty SEND, затем один `Retained synthetic history before security migration 20261020` видимый row | PASS локальный текст; transport не участвовал |
| HISTORY-PASS | Saved rename pencil → Cancel; chat-lock prompt → новый пароль → повтор; wrong password показывает «Неверный пароль или повреждённая защита»; правильный пароль снова показывает исходный row | PASS; password removal/recovery NOT RUN |
| HISTORY-DELETE-CANCEL | Message × → «Стереть маляву?» → НЕТ; исходный row count = 1 | PASS отмена; исходное сообщение не удалялось |
| HISTORY-FILE | Paperclip открыл реальный chooser; upload синтетического text fixture в Saved показывает честное «Локальное сохранение файлов пока недоступно» | PASS unsupported-state UX; chooser cancel и реальная file delivery NOT RUN |
| MIC-DENIED | Saved 🎤 → «МИКРОФОН / ОТКАЗАНО» → OK | PASS реальный browser denial/error; запись/воспроизведение NOT RUN |
| CAMERA-DENIED | Saved ⭕ → «КАМЕРА / Не удалось запустить камеру» → OK | PASS real error; camera chooser/success recording NOT RUN |
| QR-SCAN | `[ QR ]` → scanner → browser camera denial → «Глаз не открывается. Проверь разрешения» → OK | PASS denial; реальный scan NOT RUN |
| CONTACT-INVALID | `[+]` → Cancel; повтор → malformed ID → «Получено 4 знаков, а надо ровно 64» | PASS input/cancel/validation |
| CONTACT-OFFLINE | Ручной synthethic `a…a` 64-char ID + alias `Audit offline peer` → contact row и «КВАНТОВЫЙ КАНАЛ НЕ НАСТРОЕН» | PASS local creation; это не authenticated contact |
| CONTACT-EXCHANGE | В offline contact нажата «ОБМЕНЯТЬСЯ КЛЮЧАМИ» | FAIL missing handler; дальнейшие chat/call/file positive controls BLOCKED |
| CONTACT-DELETE | Новосозданный пустой synthetic contact: delete → НЕТ сохраняет row; повтор → ДА удаляет только этот test contact и показывает «Хата, ключи и Mesh locator зачищены» | PASS local test-contact cleanup; реальный peer/grant revoke NOT RUN |
| SETTINGS | Actual account gear показывает stock settings; retired passwordless button показывает «Беспарольный вход аккаунта недоступен» | PASS deny; FAIL convergence/obsolete exposed label |
| FLIP | Account settings toggle ON/OFF обновляет label; исходное значение OFF восстановлено | PASS сохранение simple policy; реальный device lock NOT RUN |
| QUICK | Account Quick Names empty list; Add prompt → Cancel; Back | PASS empty/cancel only; add/remove nonempty registry NOT RUN |
| PENDING | Account Pending Contacts показывает «ЗАПРОСОВ НЕТ», Back работает | PASS empty UI; accept/reject/refresh real request NOT RUN |
| NODE-INPUT | Invalid `http://not-a-node.invalid` → native alert WSS/WS validation; локальный test `ws://127.0.0.1:9180/dmp-c/v3` добавлен | PASS validation/local storage; не подключение |
| NODE-QR | Test Node без NodeID → QR → ясная ошибка «Для QR нужен канонический D-MASH #/node URI с NodeID» | PASS missing-authority error; positive Node QR import/share NOT RUN |
| NODE-CONNECT | ON у localhost test Node → blocked WSS/reconnecting; settings gear открыт; active auto-connect checkbox disabled | PASS loading/error/disabled UI; authenticated connection OFF/resume NOT RUN |
| NODE-NOTIFY | Notifications enable без beacon → native alert «Сначала привяжите Телеграм-маяк» | PASS prerequisite denial; notification delivery NOT RUN |
| NODE-DELETE | Native confirmation dismissed, затем повтор accepted; test endpoint удалён и list empty | PASS synthetic endpoint deletion/cancel |
| NODE-SCAN | Add Node QR → camera unavailable native alert; после dismiss scanner Cancel возвращает list | PASS denied/cancel; real camera import NOT RUN |
| NODE-REQUEST | Request empty list использовал local catalog и добавил EMS staging public endpoint; WSS route закрыл соединение. Этот локальный entry затем удалён через UI | PASS selection/error/cleanup; HTTP/WS production delivery не выполнена |
| PRIVATE-SHARE | My-ID card → stock Pairing V1; после async render имеются image+canvas. COPY через Clipboard API даёт type `DMASH_PAIRING_V1`, AccountID/contribution present; сам contribution не опубликован | PASS actual QR/copy; cross-Account pairing NOT RUN |
| MASTER-CHANGE | До смены protected owning export. Calculator UI: старый master → новый → wipe. Последний `=` превысил harness 5 s, не перезапускался. Последующая проверка показывает new verifier=true, old=false и тот же DeviceID; затем old master не открывает gate, new master открывает прежний account list | PASS eventual completion + реальный reopen; original harness timeout сохраняется как ограничение |
| MASTER-HISTORY | После смены вновь войти в тот же Account, открыть Saved и ввести chat password → исходное сообщение, те же DeviceID и Account signing-ID SHA-256 | PASS на старом загруженном page; reload/candidate migration NOT RUN |
| PUBLIC-ROUTE | Global gear → Public Routes empty → Create. Видно local created/PoW when connected. Deactivate/Activate и Reissue изменяют соответствующие состояния, current/previous rows видимы | PASS local lifecycle; реальная EntryGrant/PoW/Probe регистрация NOT RUN |
| PUBLIC-COPY | Global route copy нажата | FAIL missing Core.copyPublicContactLink; clipboard success в late profile не заявлен |
| BIO-MANAGER | Global Manager empty state → Add Key → calculator «УДЕРЖИВАЙТЕ ЛЮБУЮ КНОПКУ 1 СЕК.» → trusted mouse hold → headless enrollment failure; trigger unset/root unchanged | PASS negative enrollment; mode/cancel defect выше |
| WIPE-CANCEL | Full Wipe: первый confirm dismissed; второй запуск: confirm accepted, phrase prompt **dismissed**. Root record/unlocked/configured сохранены | PASS двух отмен; correct wipe retained profile не выполнялся |
| LOGOUT | Account exit → selector; read-only rootUnlocked=true, accountUnlocked=false, activeIdentity=null, mode=0 | PASS Account/root separation; transit без Account NOT RUN |
| GLOBAL-QUICK-AFTER-LOGOUT | Root unlocked, global Quick Names → ошибочный «СНАЧАЛА РАЗБЛОКИРУЙТЕ УСТРОЙСТВО» | FAIL; readiness descendant |
| SENSOR-ATTEMPT | CDP orientation: сначала invalid Euler 180 fixture error; исправлено на 179. Первый event beta=null, повтор с фильтром numeric beta за 4 s результата не дал. Root не закрывался | **NOT RUN** root-lock behavior; не product FAIL и не physical PASS |

Употребление `a…a` в test contact — только legacy UI parser fixture, не валидированный Ed25519 peer. Ни одна его операция не доказала handshake/trust.

## Сохранность synthetic identity/history и утрата временных артефактов

До и после реального master rewrap/повторного Account login были одинаковы:

- DeviceID SHA-256 `07c514e1244744f68c2ca05528784bd815d991733ae51cc1f28900a59f07d4a7`;
- Account signing ID SHA-256 `242b1111a0ee3e02e4ae8890c376d165d933d2553438050703a8500b297d8806`;
- исходное Saved сообщение — один visible row.

До reboot owning exports существовали в `/tmp/dmash-security-baseline-owned-20261020.json` и `/tmp/dmash-security-baseline-before-master-change-20261020.json`, второй был chmod 600. Это были storageState+IndexedDB snapshots, **restore не проверялся**. Оба утрачены; восстановление прежнего профиля сейчас недоказуемо. Новый fresh baseline→candidate тест обязан получить новые synthetic identities и сохранить именно их, не заявлять продолжение утраченного профиля.

CLI session `dmash-security-baseline` и server session 96380 больше не доступны после reboot. В `/tmp/dmash-ui-baseline/` оставались commands log и 47+ decoded result records; последние не были byte-verified durable mirror. Сейчас [JSON](BROWSER_QA_RESULTS.json) восстанавливает semantic observations из tool outputs и честно помечает provenance. Raw console errors: missing beginKeyExchange около page 1,880,158 ms; missing copyPublicContactLink около 2,187,632 ms. Старые 1 expected empty-login console error + SW blocked warning не были новыми product defects.

## Что осталось и как продолжить

**Конечный baseline зафиксирован; это не full acceptance.** Непосредственные gates: readiness candidate source/unit + independent early/late browser; новый persistent baseline→candidate identity/history proof. Затем S01/S02 credential implementation может продолжаться по решению root. Отложенные network/hardware cases — конкретный acceptance backlog, а не причина бесконечно повторять старые клики или останавливать все native features. Затем новый persistent synthetic baseline profile → owning export → candidate без reset → повтор master/Account/history/public/private flows. Временные profiles/exports больше не держать только в `/tmp`: browser profile directory 0700 и snapshots 0600 вне Git в durable recovery workspace; хранение export не считать backup restore PASS.

NOT RUN: safe correct wipe в отдельном disposable profile; wrong emergency `0010`/`1020` на fresh mode 0; retained reload после candidate; actual root lock на physical phone; setup cancel/back; nonempty Quick Names; registry/Account biometrics; PUBLIC/PRIVATE repaired share tabs; multi-Account/contact acceptance; managed-v4 opt-in controls; isolated authenticated Nodes and mailbox/transit; calls/real TURN; resumable/network files; device power/background/permissions. Export/import backup/recovery UI в baseline не был найден; не выдавать обычный contact/Node link copy за export backup.

Root owns integration, exact-source gate и назначение фиксов; `files_policy_correction` owns browser QA evidence. Native feature readiness и security release не следуют из этого отчёта.
