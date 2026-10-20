# Baseline control matrix — historical reconstruction

178 stable IDs: 133 original labels recovered from context and 45 regenerated from actual source in UI_CONTROL_INVENTORY.json. PASS is scoped to the observed member/scenario; untested alternatives remain NOT RUN. No raw-byte equality or new execution claim.

| ID | Control | Status | Observed scope / remaining fixture |
|---|---|---|---|
| CALC-01 | 0,1,2,3,4,5,6,7,8,9 | PASS | Root clicked all ten digits; input-length bounds NOT RUN |
| CALC-02 | decimal point | PASS | Root decimal 1.2; repeated decimal/secret decimal NOT RUN |
| CALC-03 | AC | PASS | AC used in arithmetic and credential flow; in-flight cancel NOT RUN |
| CALC-04 | ± | PASS | Root 5±=-5; repeat toggle NOT RUN |
| CALC-05 | % | PASS | Root 100%=1 |
| CALC-06 | ÷,×,−,+ | PASS | Root all four operators observed |
| CALC-07 | = | PASS | Actual arithmetic and master unlock; repeat-submit matrix NOT RUN |
| CALC-08 | long-hold configured key / pointer release | PASS | Trusted 1.3s hold enrollment denial only; configured unlock NOT RUN |
| CALC-09 | fresh master setup | PASS | Root short master reject and valid setup |
| CALC-10 | fresh wipe-code setup | PASS | Root valid wipe setup; collisions NOT RUN |
| CALC-11 | master unlock / loading | PASS | Old PIN refused gate/new PIN opened same account list |
| CALC-12 | master + wipe reconfiguration | PASS | Actual rewrap completed after 5s harness timeout; same device/account hashes and history reopened |
| CALC-13 | wipe PIN + equals | NOT RUN | Correct destructive path requires disposable profile; wrong emergency sequence deferred; historical retained profile lost before candidate |
| CALC-14 | 0010<master>= emergency | NOT RUN | Correct destructive path requires disposable profile; wrong emergency sequence deferred; historical retained profile lost before candidate |
| CALC-15 | 1020<master>= compatibility emergency | NOT RUN | Correct destructive path requires disposable profile; wrong emergency sequence deferred; historical retained profile lost before candidate |
| GATE-01 | identity / access-key fields | PASS | Real synthetic Account credentials filled |
| GATE-02 | ВОЙТИ В СИСТЕМУ / Enter | PASS | Empty login error and real login; Enter alternative NOT RUN |
| GATE-03 | saved-account row | PASS | Saved main account row selected |
| GATE-04 | + НОВЫЙ ВХОД | NOT RUN | Fresh new-login alternative not independently clicked after setup |
| GATE-05 | К СПИСКУ / НАЗАД К АККАУНТАМ | PASS | Root empty-list return and later Back-to-Accounts |
| GATE-06 | save-in-registry checkbox | PASS | Root save-in-registry checked |
| GATE-07 | Account BIOMETRY row | NOT RUN | No account biometric credential; conditional row absent |
| GATE-08 | global settings gear | PASS | Global gear opened |
| GLOBAL-01 | PUBLIC ROUTES | PASS | Global Public Routes reached/local controls exercised |
| GLOBAL-02 | УЗЛЫ | NOT RUN | Distinct global entry/conditional control not clicked; related stock account controls do not substitute |
| GLOBAL-03 | БЫСТРЫЕ ИМЕНА | FAIL | After logout global Quick Names demands master despite root unlocked; UI-BOOT-CONVERGENCE-01 child |
| GLOBAL-04 | РЕЕСТР АККАУНТОВ | NOT RUN | Registry control absent from observed delayed global settings; requires repaired chain |
| GLOBAL-05 | ЗАПРОСЫ В КОНТАКТЫ | NOT RUN | Distinct global entry/conditional control not clicked; related stock account controls do not substitute |
| GLOBAL-06 | ТЕЛЕГРАМ-МАЯК | NOT RUN | Distinct global entry/conditional control not clicked; related stock account controls do not substitute |
| GLOBAL-07 | ЭКСТРЕННЫЙ ФЛИП-ЛОК toggle | FAIL | Global toggle stale label and wrong stock modal; policy later restored OFF |
| GLOBAL-08 | СМЕНИТЬ MASTER-КОД | PASS | Master change entry clicked |
| GLOBAL-09 | БИОМЕТРИЯ УСТРОЙСТВА | NOT RUN | Distinct global entry/conditional control not clicked; related stock account controls do not substitute |
| GLOBAL-10 | УПРАВЛЕНИЕ БИОМЕТРИЕЙ | PASS | Empty biometric manager opened |
| GLOBAL-11 | ПОЛНОЕ УДАЛЕНИЕ ДАННЫХ | PASS | Both confirmation stages CANCELLED; success destructive path NOT RUN |
| GLOBAL-12 | КОНТАКТЫ NODE | NOT RUN | Distinct global entry/conditional control not clicked; related stock account controls do not substitute |
| QUICK-01 | ДОБАВИТЬ БЫСТРОЕ ИМЯ | PASS | Account add prompt Cancel only; persisted add NOT RUN |
| QUICK-02 | УДАЛИТЬ row | NOT RUN | No nonempty quick-name entry created; deletion not rendered |
| QUICK-03 | НАЗАД | PASS | Account Quick Names Back |
| ROUTE-01 | CREATE / СОЗДАТЬ PUBLIC ROUTE | PASS | Local create; no connected Node registration |
| ROUTE-02 | ACTIVATE / DEACTIVATE | PASS | Both activate/deactivate states; remote revoke NOT RUN |
| ROUTE-03 | REISSUE current | PASS | Local current reissue and previous/current states |
| ROUTE-04 | CONTACT LINK / copy | FAIL | Click raises missing Core.copyPublicContactLink; UI-BOOT-CONVERGENCE-01 |
| ROUTE-05 | НАЗАД | PASS | Back to global settings |
| GNODE-01 | ДОБАВИТЬ NODE | NOT RUN | Distinct global Node control not independently exercised; stock Node panel cases do not substitute |
| GNODE-02 | ПОДКЛЮЧИТЬ / ОТКЛЮЧИТЬ Node | NOT RUN | Distinct global Node control not independently exercised; stock Node panel cases do not substitute |
| GNODE-03 | СДЕЛАТЬ ОСНОВНЫМ / ОСНОВНОЙ | NOT RUN | Distinct global Node control not independently exercised; stock Node panel cases do not substitute |
| GNODE-04 | УДАЛИТЬ Node | NOT RUN | Distinct global Node control not independently exercised; stock Node panel cases do not substitute |
| GNODE-05 | Node address input / OK / Cancel | NOT RUN | Distinct global Node control not independently exercised; stock Node panel cases do not substitute |
| GNODE-06 | НАЗАД к global settings | NOT RUN | Distinct global Node control not independently exercised; stock Node panel cases do not substitute |
| BIO-01 | НАЧАТЬ ПРИВЯЗКУ | NOT RUN | Separate BEGIN entry not clicked; manager ADD KEY observed separately |
| BIO-02 | ДОБАВИТЬ КЛЮЧ | PASS | Add Key -> calculator -> actual headless enrollment denial; successful PRF NOT RUN |
| BIO-03 | УДАЛИТЬ КЛЮЧ | NOT RUN | No enrolled device credential; delete not rendered |
| BIO-04 | НАЗАД / ОТМЕНА | NOT RUN | Manager Back/Cancel not independently clicked; separate mode6 missing-cancel defect UI-BIO-CANCEL-01 is in bug backlog |
| BIO-05 | stock Account settings БИОМЕТРИЯ УСТРОЙСТВА | NOT RUN | Stock direct enrollment button distinct from manager hold flow; not separately clicked |
| ACCOUNT-01 | settings gear | PASS | Actual delayed stock account settings shown |
| ACCOUNT-02 | КОПИРОВАТЬ ID АККАУНТА | NOT RUN | Required repaired/conditional account or registry/biometric UI not reached in delayed wrapper profile; retest after readiness candidate |
| ACCOUNT-03 | БИОМЕТРИЯ АККАУНТА | NOT RUN | Required repaired/conditional account or registry/biometric UI not reached in delayed wrapper profile; retest after readiness candidate |
| ACCOUNT-04 | ПРОВЕРИТЬ КЛЮЧ | NOT RUN | Required repaired/conditional account or registry/biometric UI not reached in delayed wrapper profile; retest after readiness candidate |
| ACCOUNT-05 | ПРИВЯЗАТЬ БИОМЕТРИЮ | NOT RUN | Required repaired/conditional account or registry/biometric UI not reached in delayed wrapper profile; retest after readiness candidate |
| ACCOUNT-06 | БЕСПАРОЛЬНЫЙ ВХОД | PASS | Retired passwordless option denied |
| ACCOUNT-07 | Account registry remove biometric | NOT RUN | Required repaired/conditional account or registry/biometric UI not reached in delayed wrapper profile; retest after readiness candidate |
| ACCOUNT-08 | inactive Account УДАЛИТЬ | NOT RUN | Required repaired/conditional account or registry/biometric UI not reached in delayed wrapper profile; retest after readiness candidate |
| ACCOUNT-09 | ЗАКРЫТЬ / НАЗАД | PASS | Account settings close/back |
| WORK-01 | my-ID card | PASS | My-ID card opened stock Pairing V1 QR |
| WORK-02 | network card | NOT RUN | Dedicated network-card click not executed; related stock Node panel menu does not substitute |
| WORK-03 | [ QR ] scanner | PASS | Contact scanner camera denial |
| WORK-04 | [ + ] add contact | PASS | Add contact cancel/invalid ID/manual synthetic peer |
| WORK-05 | [ ВЫХОД ] | PASS | Actual logout root=true/account=false |
| WORK-06 | peer/Saved Messages row; Enter/Space | PASS | Saved and synthetic peer clicked; keyboard alternative NOT RUN |
| WORK-07 | chat delete × | PASS | New empty synthetic peer delete cancelled then confirmed; retained peer/history untouched |
| WORK-08 | contact progress row | NOT RUN | Requires contact progress/confirmation fixture; unavailable after missing bootstrap handler |
| WORK-09 | progress sync/refresh | NOT RUN | Requires contact progress/confirmation fixture; unavailable after missing bootstrap handler |
| SHARE-01 | PRIVATE / PUBLIC tabs | NOT RUN | Repaired PRIVATE/PUBLIC UI unavailable in delayed Core; stock Pairing V1 copy is separate scope |
| SHARE-02 | public route dropdown | NOT RUN | Repaired PRIVATE/PUBLIC UI unavailable in delayed Core; stock Pairing V1 copy is separate scope |
| SHARE-03 | copy current payload | NOT RUN | Repaired PRIVATE/PUBLIC UI unavailable in delayed Core; stock Pairing V1 copy is separate scope |
| SHARE-04 | СОЗДАТЬ PUBLIC ROUTE empty state | NOT RUN | Repaired PRIVATE/PUBLIC UI unavailable in delayed Core; stock Pairing V1 copy is separate scope |
| SHARE-05 | stock QR КОПИРОВАТЬ / ЗАКРЫТЬ | PASS | Async QR image/canvas then copy Pairing V1 verified by clipboard shape; no contribution published |
| SCAN-01 | contact scanner ОТМЕНА | NOT RUN | Historical context reconstruction; not new execution |
| CONTACT-01 | manual input OK / alias OK | PASS | Invalid ID and local synthetic ID+alias accepted |
| CONTACT-02 | name chooser quick-name row | NOT RUN | Requires confirmed contact/requests/route fixture; delayed key-exchange handler missing, so descendant blocked |
| CONTACT-03 | ВВЕСТИ ДРУГОЕ ИМЯ | NOT RUN | Requires confirmed contact/requests/route fixture; delayed key-exchange handler missing, so descendant blocked |
| CONTACT-04 | preparation ОТМЕНА | NOT RUN | Requires confirmed contact/requests/route fixture; delayed key-exchange handler missing, so descendant blocked |
| CONTACT-05 | pending request card | NOT RUN | Requires confirmed contact/requests/route fixture; delayed key-exchange handler missing, so descendant blocked |
| CONTACT-06 | ПРИНЯТЬ / продолжить accept | NOT RUN | Requires confirmed contact/requests/route fixture; delayed key-exchange handler missing, so descendant blocked |
| CONTACT-07 | ВЫЙТИ И ВЫБРАТЬ АККАУНТ | NOT RUN | Requires confirmed contact/requests/route fixture; delayed key-exchange handler missing, so descendant blocked |
| CONTACT-08 | ОТКЛОНИТЬ | NOT RUN | Requires confirmed contact/requests/route fixture; delayed key-exchange handler missing, so descendant blocked |
| CONTACT-09 | quick-name accept list / new quick-name | NOT RUN | Requires confirmed contact/requests/route fixture; delayed key-exchange handler missing, so descendant blocked |
| CONTACT-10 | ЗАКРЫТЬ / НАЗАД | PASS | Empty pending contacts Back only |
| CONTACT-11 | НАЧАТЬ ОБМЕН КЛЮЧАМИ | FAIL | Click raises missing Core.beginKeyExchange; UI-BOOT-CONVERGENCE-01 |
| CONTACT-12 | explicit Legacy Relay fallback ДА / НЕТ | NOT RUN | Requires confirmed contact/requests/route fixture; delayed key-exchange handler missing, so descendant blocked |
| CHAT-01 | back arrow + browser/mobile Back | PASS | Actual arrow Back; browser/system Back NOT RUN |
| CHAT-02 | header peer ID click | NOT RUN | Contact header ID copy not separately clicked |
| CHAT-03 | rename pencil | PASS | Pencil -> cancel only |
| CHAT-04 | chat password lock | PASS | Set and confirm local history password |
| CHAT-05 | locked-history password OK / cancel | PASS | Wrong pass error then correct original history reopen; removal NOT RUN |
| CHAT-06 | composer text field | PASS | Root local text entered |
| CHAT-07 | SEND / Enter / Shift+Enter | PASS | Root empty SEND then one Saved row; Enter/Shift+Enter NOT RUN |
| CHAT-08 | message delete × | PASS | Original row delete cancelled; success deletion NOT RUN |
| NODE-01 | ДОБАВИТЬ УЗЕЛ | PASS | Invalid scheme error and localhost test endpoint added |
| NODE-02 | ДОБАВИТЬ ПО QR | PASS | Actual Node camera denial |
| NODE-03 | ЗАПРОСИТЬ УЗЕЛ empty list | PASS | Local catalog requested then endpoint removed; egress blocked |
| NODE-04 | row ON / OFF | PASS | ON produced blocked reconnect; authenticated OFF/resume NOT RUN |
| NODE-05 | row QR | PASS | No-NodeID QR error only; positive canonical QR NOT RUN |
| NODE-06 | row gear | PASS | Endpoint settings opened |
| NODE-07 | АВТОПОДКЛЮЧЕНИЕ checkbox | PASS | Active auto-connect disabled state observed; toggle NOT RUN |
| NODE-08 | РАЗРЕШИТЬ / ВЫКЛЮЧИТЬ УВЕДОМЛЕНИЯ | PASS | Enable without beacon denied; disable/delivery NOT RUN |
| NODE-09 | СДЕЛАТЬ ОСНОВНЫМ | NOT RUN | Only one primary test Node present; nonprimary selection not rendered |
| NODE-10 | УДАЛИТЬ УЗЕЛ | PASS | Native cancel then delete only synthetic endpoint |
| NODE-11 | КОПИРОВАТЬ ССЫЛКУ / НАЗАД | NOT RUN | Positive canonical Node sharing unavailable for missing NodeID test entry |
| NODE-12 | ОТМЕНА | PASS | Node scanner Cancel after camera denial |
| NODE-13 | НАЗАД | PASS | Back from Node panel |
| MANAGED-01 | Подключить Node | NOT RUN | Requires explicit managed-v4 opt-in and isolated authenticated Node/contact fixture; not selected in historical legacy profile |
| MANAGED-02 | Публичный адрес Node field | NOT RUN | Requires explicit managed-v4 opt-in and isolated authenticated Node/contact fixture; not selected in historical legacy profile |
| MANAGED-03 | Ваше имя для запроса field | NOT RUN | Requires explicit managed-v4 opt-in and isolated authenticated Node/contact fixture; not selected in historical legacy profile |
| MANAGED-04 | Сообщение для знакомства field | NOT RUN | Requires explicit managed-v4 opt-in and isolated authenticated Node/contact fixture; not selected in historical legacy profile |
| MANAGED-05 | Создать / показать публичный адрес | NOT RUN | Requires explicit managed-v4 opt-in and isolated authenticated Node/contact fixture; not selected in historical legacy profile |
| MANAGED-06 | Копировать публичный адрес | NOT RUN | Requires explicit managed-v4 opt-in and isolated authenticated Node/contact fixture; not selected in historical legacy profile |
| MANAGED-07 | Отправить запрос | NOT RUN | Requires explicit managed-v4 opt-in and isolated authenticated Node/contact fixture; not selected in historical legacy profile |
| MANAGED-08 | Обновить запросы | NOT RUN | Requires explicit managed-v4 opt-in and isolated authenticated Node/contact fixture; not selected in historical legacy profile |
| MANAGED-09 | Выбрать аккаунт для принятия | NOT RUN | Requires explicit managed-v4 opt-in and isolated authenticated Node/contact fixture; not selected in historical legacy profile |
| MANAGED-10 | Принять в текущий аккаунт | NOT RUN | Requires explicit managed-v4 opt-in and isolated authenticated Node/contact fixture; not selected in historical legacy profile |
| MANAGED-11 | Подтвердить собеседника | NOT RUN | Requires explicit managed-v4 opt-in and isolated authenticated Node/contact fixture; not selected in historical legacy profile |
| MANAGED-12 | Завершить обмен ключами | NOT RUN | Requires explicit managed-v4 opt-in and isolated authenticated Node/contact fixture; not selected in historical legacy profile |
| MANAGED-13 | Повторить запрос | NOT RUN | Requires explicit managed-v4 opt-in and isolated authenticated Node/contact fixture; not selected in historical legacy profile |
| MANAGED-14 | Отклонить запрос / ДА, ОТКЛОНИТЬ / НЕТ | NOT RUN | Requires explicit managed-v4 opt-in and isolated authenticated Node/contact fixture; not selected in historical legacy profile |
| MANAGED-15 | PRIVATE адрес Node field / Проверенный ID собеседника field | NOT RUN | Requires explicit managed-v4 opt-in and isolated authenticated Node/contact fixture; not selected in historical legacy profile |
| MANAGED-16 | Создать PRIVATE QR | NOT RUN | Requires explicit managed-v4 opt-in and isolated authenticated Node/contact fixture; not selected in historical legacy profile |
| MANAGED-17 | Копировать PRIVATE адрес | NOT RUN | Requires explicit managed-v4 opt-in and isolated authenticated Node/contact fixture; not selected in historical legacy profile |
| MANAGED-18 | Проверить PRIVATE адрес | NOT RUN | Requires explicit managed-v4 opt-in and isolated authenticated Node/contact fixture; not selected in historical legacy profile |
| MANAGED-19 | Отправить PRIVATE запрос | NOT RUN | Requires explicit managed-v4 opt-in and isolated authenticated Node/contact fixture; not selected in historical legacy profile |
| MANAGED-20 | Обновить PRIVATE запросы | NOT RUN | Requires explicit managed-v4 opt-in and isolated authenticated Node/contact fixture; not selected in historical legacy profile |
| MANAGED-21 | Показать PRIVATE QR / Повторить PRIVATE запрос / Подтвердить PRIVATE контакт / Отклонить PRIVATE запрос | NOT RUN | Requires explicit managed-v4 opt-in and isolated authenticated Node/contact fixture; not selected in historical legacy profile |
| MANAGED-22 | Перевести существующий контакт на Node / confirm / cancel | NOT RUN | Requires explicit managed-v4 opt-in and isolated authenticated Node/contact fixture; not selected in historical legacy profile |
| MANAGED-23 | ЗАКРЫТЬ managed panel | NOT RUN | Requires explicit managed-v4 opt-in and isolated authenticated Node/contact fixture; not selected in historical legacy profile |
| MEDIA-01 | paperclip + hidden file input | PASS | Actual chooser and Saved unsupported-file alert; OS chooser cancel/network transfer NOT RUN |
| MEDIA-02 | file card ОТКРЫТЬ ФАЙЛ | NOT RUN | Positive recording/file/playback control requires media device or confirmed contact + isolated real TURN/file fixture; not rendered in tested denial/local-only states |
| MEDIA-03 | ОТМЕНИТЬ ОТПРАВКУ stored card | NOT RUN | Positive recording/file/playback control requires media device or confirmed contact + isolated real TURN/file fixture; not rendered in tested denial/local-only states |
| MEDIA-04 | incoming automatic receive status + cancel (NO separate YES/NO file consent) | NOT RUN | Positive recording/file/playback control requires media device or confirmed contact + isolated real TURN/file fixture; not rendered in tested denial/local-only states |
| MEDIA-05 | progress Отмена / Закрыть | NOT RUN | Positive recording/file/playback control requires media device or confirmed contact + isolated real TURN/file fixture; not rendered in tested denial/local-only states |
| MEDIA-06 | Сохранить файл link | NOT RUN | Positive recording/file/playback control requires media device or confirmed contact + isolated real TURN/file fixture; not rendered in tested denial/local-only states |
| MEDIA-07 | microphone start | PASS | Actual microphone denial/error UI only |
| MEDIA-08 | circle video start | PASS | Actual circle capture camera failure only |
| MEDIA-09 | camera-choice row / ОТМЕНА | NOT RUN | Positive recording/file/playback control requires media device or confirmed contact + isolated real TURN/file fixture; not rendered in tested denial/local-only states |
| MEDIA-10 | recording × cancel (voice/circle) | NOT RUN | Positive recording/file/playback control requires media device or confirmed contact + isolated real TURN/file fixture; not rendered in tested denial/local-only states |
| MEDIA-11 | SEND recording | NOT RUN | Positive recording/file/playback control requires media device or confirmed contact + isolated real TURN/file fixture; not rendered in tested denial/local-only states |
| MEDIA-12 | cancel outbound / retry cancelled | NOT RUN | Positive recording/file/playback control requires media device or confirmed contact + isolated real TURN/file fixture; not rendered in tested denial/local-only states |
| MEDIA-13 | incoming Принять / Отклонить | NOT RUN | Positive recording/file/playback control requires media device or confirmed contact + isolated real TURN/file fixture; not rendered in tested denial/local-only states |
| MEDIA-14 | РАСШИФРОВАТЬ / КРУЖОК | NOT RUN | Positive recording/file/playback control requires media device or confirmed contact + isolated real TURN/file fixture; not rendered in tested denial/local-only states |
| MEDIA-15 | ПОВТОРИТЬ decrypt | NOT RUN | Positive recording/file/playback control requires media device or confirmed contact + isolated real TURN/file fixture; not rendered in tested denial/local-only states |
| MEDIA-16 | native audio/video playback controls | NOT RUN | Positive recording/file/playback control requires media device or confirmed contact + isolated real TURN/file fixture; not rendered in tested denial/local-only states |
| MEDIA-17 | circle tap play/pause | NOT RUN | Positive recording/file/playback control requires media device or confirmed contact + isolated real TURN/file fixture; not rendered in tested denial/local-only states |
| MEDIA-18 | image open / download link | NOT RUN | Positive recording/file/playback control requires media device or confirmed contact + isolated real TURN/file fixture; not rendered in tested denial/local-only states |
| CALL-01 | VoIP call button / outbound cancel | NOT RUN | Requires two confirmed contacts, isolated signaling/TURN and permitted media; blocked legacy bootstrap/no hardware |
| CALL-02 | incoming call accept / decline | NOT RUN | Requires two confirmed contacts, isolated signaling/TURN and permitted media; blocked legacy bootstrap/no hardware |
| CALL-03 | microphone mute / unmute | NOT RUN | Requires two confirmed contacts, isolated signaling/TURN and permitted media; blocked legacy bootstrap/no hardware |
| CALL-04 | camera enable / disable | NOT RUN | Requires two confirmed contacts, isolated signaling/TURN and permitted media; blocked legacy bootstrap/no hardware |
| CALL-05 | switch camera | NOT RUN | Requires two confirmed contacts, isolated signaling/TURN and permitted media; blocked legacy bootstrap/no hardware |
| CALL-06 | share screen | NOT RUN | Requires two confirmed contacts, isolated signaling/TURN and permitted media; blocked legacy bootstrap/no hardware |
| CALL-07 | speaker toggle | NOT RUN | Requires two confirmed contacts, isolated signaling/TURN and permitted media; blocked legacy bootstrap/no hardware |
| CALL-08 | end call | NOT RUN | Requires two confirmed contacts, isolated signaling/TURN and permitted media; blocked legacy bootstrap/no hardware |
| NOTIFY-01 | ОТКРЫТЬ БОТА external link | NOT RUN | No Telegram account/bot messaging authorized; no external link navigation/beacon delivery tested |
| NOTIFY-02 | ОТКЛЮЧИТЬ МАЯК | NOT RUN | No Telegram account/bot messaging authorized; no external link navigation/beacon delivery tested |
| MODAL-01 | alert OK / modal close/back | PASS | Actual alerts OK and modal close/back |
| MODAL-02 | prompt field / OK / Enter | PASS | Actual prompt fields+OK; Enter NOT RUN |
| MODAL-03 | prompt ОТМЕНА | PASS | Actual prompt Cancel |
| MODAL-04 | confirm ДА / НЕТ | PASS | Synthetic peer yes/no and retained message no |
| MODAL-05 | native confirm/prompt | PASS | Node native confirm, wipe confirm and phrase cancellations only |
| MODAL-06 | backdrop / sidebar / chat-main click | NOT RUN | Backdrop/mobile sidebar empty-space dismiss contract not independently exercised |
| LOCK-01 | flipper orientation gesture | NOT RUN | CDP emulation produced no numeric beta; no physical phone sensor/root-lock acceptance |
| LOCK-02 | reload/window close/reopen | NOT RUN | Original page deliberately not reloaded before candidate; host reboot destroyed profile; retained-update proof unavailable |
| ABSENT-01 | Full installation backup / export / import UI | NOT RUN | Not exposed in current UI per source-backed inventory; no runtime execution claim |
| ABSENT-02 | Public Route DELETE UI | NOT RUN | Not exposed in current UI per source-backed inventory; no runtime execution claim |
| ABSENT-03 | Generic Node password UI | NOT RUN | Not exposed in current UI per source-backed inventory; no runtime execution claim |
| ABSENT-04 | Personal Telegram bot configuration UI (unloaded app_shell only) | NOT RUN | Not exposed in current UI per source-backed inventory; no runtime execution claim |
| ABSENT-05 | Custom ringtone UI | NOT RUN | Not exposed in current UI per source-backed inventory; no runtime execution claim |
| ABSENT-06 | Diagnostics launcher UI | NOT RUN | Not exposed in current UI per source-backed inventory; no runtime execution claim |
| ABSENT-07 | Per-file affirmative YES / NO consent UI (trusted files auto-receive) | NOT RUN | Not exposed in current UI per source-backed inventory; no runtime execution claim |
| ABSENT-08 | Master reconfiguration explicit Back / Cancel control | NOT RUN | Not exposed in current UI per source-backed inventory; no runtime execution claim |
