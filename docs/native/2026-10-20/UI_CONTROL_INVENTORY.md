# UI control inventory — 20 October 2026

This finite inventory covers **178 stable control classes**. Every enabled member still requires actual UI actions; one class is not one click, and a successful error/cancel case does not establish its positive path. Per-message/contact/Node repetition belongs to the same class. [Browser QA](BROWSER_QA.md) and its matrix own execution statuses. [Machine-readable inventory](UI_CONTROL_INVENTORY.json) includes baseline source SHA256 and the actual source binding lines.

Host reboot destroyed the original temporary inventory and browser profiles. The stable IDs and 133 labels were recovered from conversation; 45 missing labels were regenerated from source and marked individually. The original 304-line/86-file counts are historical metadata, not claimed for this regenerated extraction. Current extraction counts are recorded in JSON. No historical browser logs or retained-profile continuity are fabricated.

Baseline source is `9446c22f27309131456942870971d477f6f2358f`. Default `legacy-migration` and explicit `managed-v4` are separate branches. `release.js` loads v50/v51/v52/v54/v55; v53, stability_fixes and app_shell are not current entry dependencies. Actual baseline early/late UI differs because installer deadlines can expire before lazy Core. Candidate readiness correction requires its own exact-source browser result.

All rows start NOT RUN here. Required cases include every enabled member, input/validation, loading/repeated clicks, disabled/unavailable, cancellation and back navigation. DeviceRoot setup/unlock is distinct from Account login. Peer-positive/contact/call/file actions require isolated genuine peer fixtures; blocking external HTTP/WSS only proves the offline/error branch. Destructive cases require synthetic owned profiles. Managed controls require explicit opt-in; opening a panel does not prove transport delivery.

Concrete gaps: trusted incoming files automatically receive in `file_runtime.js`; a file progress cancel is not affirmative consent. Full backup/import/export, route deletion, generic Node passwords, personal bot setup, custom ringtone and diagnostics launcher are not current reachable controls. Master reconfiguration has no explicit Cancel/Back; AC clears the current entry. Generic modal prompt Enter prevents form submission and is not equivalent to OK. Calculator has 19 actual buttons. Core.copyMyId has baseline stock/repair payload differences; test both loaded branches rather than asserting one converged UI.

| ID | Control family / members | Source files | Required execution |
|---|---|---|---|
| CALC-01 | 0,1,2,3,4,5,6,7,8,9 | index.html, js/ui_logic.js, js/acceptance_v51.js, js/acceptance_v54.js, js/acceptance_v55.js | NOT RUN; enabled/error/loading/disabled/cancel |
| CALC-02 | decimal point | index.html, js/ui_logic.js, js/acceptance_v51.js, js/acceptance_v54.js, js/acceptance_v55.js | NOT RUN; enabled/error/loading/disabled/cancel |
| CALC-03 | AC | index.html, js/ui_logic.js, js/acceptance_v51.js, js/acceptance_v54.js, js/acceptance_v55.js | NOT RUN; enabled/error/loading/disabled/cancel |
| CALC-04 | ± | index.html, js/ui_logic.js, js/acceptance_v51.js, js/acceptance_v54.js, js/acceptance_v55.js | NOT RUN; enabled/error/loading/disabled/cancel |
| CALC-05 | % | index.html, js/ui_logic.js, js/acceptance_v51.js, js/acceptance_v54.js, js/acceptance_v55.js | NOT RUN; enabled/error/loading/disabled/cancel |
| CALC-06 | ÷,×,−,+ | index.html, js/ui_logic.js, js/acceptance_v51.js, js/acceptance_v54.js, js/acceptance_v55.js | NOT RUN; enabled/error/loading/disabled/cancel |
| CALC-07 | = | index.html, js/ui_logic.js, js/acceptance_v51.js, js/acceptance_v54.js, js/acceptance_v55.js | NOT RUN; enabled/error/loading/disabled/cancel |
| CALC-08 | long-hold configured key / pointer release | index.html, js/ui_logic.js, js/acceptance_v51.js, js/acceptance_v54.js, js/acceptance_v55.js | NOT RUN; enabled/error/loading/disabled/cancel |
| CALC-09 | fresh master setup | index.html, js/ui_logic.js, js/acceptance_v51.js, js/acceptance_v54.js, js/acceptance_v55.js | NOT RUN; enabled/error/loading/disabled/cancel |
| CALC-10 | fresh wipe-code setup | index.html, js/ui_logic.js, js/acceptance_v51.js, js/acceptance_v54.js, js/acceptance_v55.js | NOT RUN; enabled/error/loading/disabled/cancel |
| CALC-11 | master unlock / loading | index.html, js/ui_logic.js, js/acceptance_v51.js, js/acceptance_v54.js, js/acceptance_v55.js | NOT RUN; enabled/error/loading/disabled/cancel |
| CALC-12 | master + wipe reconfiguration | index.html, js/ui_logic.js, js/acceptance_v51.js, js/acceptance_v54.js, js/acceptance_v55.js | NOT RUN; enabled/error/loading/disabled/cancel |
| CALC-13 | wipe PIN + equals | index.html, js/ui_logic.js, js/acceptance_v51.js, js/acceptance_v54.js, js/acceptance_v55.js | NOT RUN; enabled/error/loading/disabled/cancel |
| CALC-14 | 0010<master>= emergency | index.html, js/ui_logic.js, js/acceptance_v51.js, js/acceptance_v54.js, js/acceptance_v55.js | NOT RUN; enabled/error/loading/disabled/cancel |
| CALC-15 | 1020<master>= compatibility emergency | index.html, js/ui_logic.js, js/acceptance_v51.js, js/acceptance_v54.js, js/acceptance_v55.js | NOT RUN; enabled/error/loading/disabled/cancel |
| GATE-01 | identity / access-key fields | js/ui_logic.js, js/acceptance_v50.js, js/acceptance_v52.js | NOT RUN; enabled/error/loading/disabled/cancel |
| GATE-02 | ВОЙТИ В СИСТЕМУ / Enter | js/ui_logic.js, js/acceptance_v50.js, js/acceptance_v52.js | NOT RUN; enabled/error/loading/disabled/cancel |
| GATE-03 | saved-account row | js/ui_logic.js, js/acceptance_v50.js, js/acceptance_v52.js | NOT RUN; enabled/error/loading/disabled/cancel |
| GATE-04 | + НОВЫЙ ВХОД | js/ui_logic.js, js/acceptance_v50.js, js/acceptance_v52.js | NOT RUN; enabled/error/loading/disabled/cancel |
| GATE-05 | К СПИСКУ / НАЗАД К АККАУНТАМ | js/ui_logic.js, js/acceptance_v50.js, js/acceptance_v52.js | NOT RUN; enabled/error/loading/disabled/cancel |
| GATE-06 | save-in-registry checkbox | js/ui_logic.js, js/acceptance_v50.js, js/acceptance_v52.js | NOT RUN; enabled/error/loading/disabled/cancel |
| GATE-07 | Account BIOMETRY row | js/ui_logic.js, js/acceptance_v50.js, js/acceptance_v52.js | NOT RUN; enabled/error/loading/disabled/cancel |
| GATE-08 | global settings gear | js/ui_logic.js, js/acceptance_v50.js, js/acceptance_v52.js | NOT RUN; enabled/error/loading/disabled/cancel |
| GLOBAL-01 | PUBLIC ROUTES | js/acceptance_fixes.js, js/acceptance_v51.js, js/node_account_ui_v4.js | NOT RUN; enabled/error/loading/disabled/cancel |
| GLOBAL-02 | УЗЛЫ | js/acceptance_fixes.js, js/acceptance_v51.js, js/node_account_ui_v4.js | NOT RUN; enabled/error/loading/disabled/cancel |
| GLOBAL-03 | БЫСТРЫЕ ИМЕНА | js/acceptance_fixes.js, js/acceptance_v51.js, js/node_account_ui_v4.js | NOT RUN; enabled/error/loading/disabled/cancel |
| GLOBAL-04 | РЕЕСТР АККАУНТОВ | js/acceptance_fixes.js, js/acceptance_v51.js, js/node_account_ui_v4.js | NOT RUN; enabled/error/loading/disabled/cancel |
| GLOBAL-05 | ЗАПРОСЫ В КОНТАКТЫ | js/acceptance_fixes.js, js/acceptance_v51.js, js/node_account_ui_v4.js | NOT RUN; enabled/error/loading/disabled/cancel |
| GLOBAL-06 | ТЕЛЕГРАМ-МАЯК | js/acceptance_fixes.js, js/acceptance_v51.js, js/node_account_ui_v4.js | NOT RUN; enabled/error/loading/disabled/cancel |
| GLOBAL-07 | ЭКСТРЕННЫЙ ФЛИП-ЛОК toggle | js/acceptance_fixes.js, js/acceptance_v51.js, js/node_account_ui_v4.js | NOT RUN; enabled/error/loading/disabled/cancel |
| GLOBAL-08 | СМЕНИТЬ MASTER-КОД | js/acceptance_fixes.js, js/acceptance_v51.js, js/node_account_ui_v4.js | NOT RUN; enabled/error/loading/disabled/cancel |
| GLOBAL-09 | БИОМЕТРИЯ УСТРОЙСТВА | js/acceptance_fixes.js, js/acceptance_v51.js, js/node_account_ui_v4.js | NOT RUN; enabled/error/loading/disabled/cancel |
| GLOBAL-10 | УПРАВЛЕНИЕ БИОМЕТРИЕЙ | js/acceptance_fixes.js, js/acceptance_v51.js, js/node_account_ui_v4.js | NOT RUN; enabled/error/loading/disabled/cancel |
| GLOBAL-11 | ПОЛНОЕ УДАЛЕНИЕ ДАННЫХ | js/acceptance_fixes.js, js/acceptance_v51.js, js/node_account_ui_v4.js | NOT RUN; enabled/error/loading/disabled/cancel |
| GLOBAL-12 | КОНТАКТЫ NODE | js/acceptance_fixes.js, js/acceptance_v51.js, js/node_account_ui_v4.js | NOT RUN; enabled/error/loading/disabled/cancel |
| QUICK-01 | ДОБАВИТЬ БЫСТРОЕ ИМЯ | js/core_engine.js, js/acceptance_fixes.js | NOT RUN; enabled/error/loading/disabled/cancel |
| QUICK-02 | УДАЛИТЬ row | js/core_engine.js, js/acceptance_fixes.js | NOT RUN; enabled/error/loading/disabled/cancel |
| QUICK-03 | НАЗАД | js/core_engine.js, js/acceptance_fixes.js | NOT RUN; enabled/error/loading/disabled/cancel |
| ROUTE-01 | CREATE / СОЗДАТЬ PUBLIC ROUTE | js/runtime_fixes.js, js/acceptance_fixes.js | NOT RUN; enabled/error/loading/disabled/cancel |
| ROUTE-02 | ACTIVATE / DEACTIVATE | js/runtime_fixes.js, js/acceptance_fixes.js | NOT RUN; enabled/error/loading/disabled/cancel |
| ROUTE-03 | REISSUE current | js/runtime_fixes.js, js/acceptance_fixes.js | NOT RUN; enabled/error/loading/disabled/cancel |
| ROUTE-04 | CONTACT LINK / copy | js/runtime_fixes.js, js/acceptance_fixes.js | NOT RUN; enabled/error/loading/disabled/cancel |
| ROUTE-05 | НАЗАД | js/runtime_fixes.js, js/acceptance_fixes.js | NOT RUN; enabled/error/loading/disabled/cancel |
| GNODE-01 | ДОБАВИТЬ NODE | js/acceptance_fixes.js | NOT RUN; enabled/error/loading/disabled/cancel |
| GNODE-02 | ПОДКЛЮЧИТЬ / ОТКЛЮЧИТЬ Node | js/acceptance_fixes.js | NOT RUN; enabled/error/loading/disabled/cancel |
| GNODE-03 | СДЕЛАТЬ ОСНОВНЫМ / ОСНОВНОЙ | js/acceptance_fixes.js | NOT RUN; enabled/error/loading/disabled/cancel |
| GNODE-04 | УДАЛИТЬ Node | js/acceptance_fixes.js | NOT RUN; enabled/error/loading/disabled/cancel |
| GNODE-05 | Node address input / OK / Cancel | js/acceptance_fixes.js | NOT RUN; enabled/error/loading/disabled/cancel |
| GNODE-06 | НАЗАД к global settings | js/acceptance_fixes.js | NOT RUN; enabled/error/loading/disabled/cancel |
| BIO-01 | НАЧАТЬ ПРИВЯЗКУ | js/ui_logic.js, js/acceptance_fixes.js, js/acceptance_v51.js | NOT RUN; enabled/error/loading/disabled/cancel |
| BIO-02 | ДОБАВИТЬ КЛЮЧ | js/ui_logic.js, js/acceptance_fixes.js, js/acceptance_v51.js | NOT RUN; enabled/error/loading/disabled/cancel |
| BIO-03 | УДАЛИТЬ КЛЮЧ | js/ui_logic.js, js/acceptance_fixes.js, js/acceptance_v51.js | NOT RUN; enabled/error/loading/disabled/cancel |
| BIO-04 | НАЗАД / ОТМЕНА | js/ui_logic.js, js/acceptance_fixes.js, js/acceptance_v51.js | NOT RUN; enabled/error/loading/disabled/cancel |
| BIO-05 | stock Account settings БИОМЕТРИЯ УСТРОЙСТВА | js/ui_logic.js, js/acceptance_fixes.js, js/acceptance_v51.js | NOT RUN; enabled/error/loading/disabled/cancel |
| ACCOUNT-01 | settings gear | js/core_engine.js, js/acceptance_v50.js | NOT RUN; enabled/error/loading/disabled/cancel |
| ACCOUNT-02 | КОПИРОВАТЬ ID АККАУНТА | js/core_engine.js, js/acceptance_v50.js | NOT RUN; enabled/error/loading/disabled/cancel |
| ACCOUNT-03 | БИОМЕТРИЯ АККАУНТА | js/core_engine.js, js/acceptance_v50.js | NOT RUN; enabled/error/loading/disabled/cancel |
| ACCOUNT-04 | ПРОВЕРИТЬ КЛЮЧ | js/core_engine.js, js/acceptance_v50.js | NOT RUN; enabled/error/loading/disabled/cancel |
| ACCOUNT-05 | ПРИВЯЗАТЬ БИОМЕТРИЮ | js/core_engine.js, js/acceptance_v50.js | NOT RUN; enabled/error/loading/disabled/cancel |
| ACCOUNT-06 | БЕСПАРОЛЬНЫЙ ВХОД | js/core_engine.js, js/acceptance_v50.js | NOT RUN; enabled/error/loading/disabled/cancel |
| ACCOUNT-07 | Account registry remove biometric | js/core_engine.js, js/acceptance_v50.js | NOT RUN; enabled/error/loading/disabled/cancel |
| ACCOUNT-08 | inactive Account УДАЛИТЬ | js/core_engine.js, js/acceptance_v50.js | NOT RUN; enabled/error/loading/disabled/cancel |
| ACCOUNT-09 | ЗАКРЫТЬ / НАЗАД | js/core_engine.js, js/acceptance_v50.js | NOT RUN; enabled/error/loading/disabled/cancel |
| WORK-01 | my-ID card | js/core_engine.js, js/acceptance_v50.js | NOT RUN; enabled/error/loading/disabled/cancel |
| WORK-02 | network card | js/core_engine.js, js/acceptance_v50.js | NOT RUN; enabled/error/loading/disabled/cancel |
| WORK-03 | [ QR ] scanner | js/core_engine.js, js/acceptance_v50.js | NOT RUN; enabled/error/loading/disabled/cancel |
| WORK-04 | [ + ] add contact | js/core_engine.js, js/acceptance_v50.js | NOT RUN; enabled/error/loading/disabled/cancel |
| WORK-05 | [ ВЫХОД ] | js/core_engine.js, js/acceptance_v50.js | NOT RUN; enabled/error/loading/disabled/cancel |
| WORK-06 | peer/Saved Messages row; Enter/Space | js/core_engine.js, js/acceptance_v50.js | NOT RUN; enabled/error/loading/disabled/cancel |
| WORK-07 | chat delete × | js/core_engine.js, js/acceptance_v50.js | NOT RUN; enabled/error/loading/disabled/cancel |
| WORK-08 | contact progress row | js/core_engine.js, js/acceptance_v50.js | NOT RUN; enabled/error/loading/disabled/cancel |
| WORK-09 | progress sync/refresh | js/core_engine.js, js/acceptance_v50.js | NOT RUN; enabled/error/loading/disabled/cancel |
| SHARE-01 | PRIVATE / PUBLIC tabs | js/core_engine.js, js/acceptance_fixes.js | NOT RUN; enabled/error/loading/disabled/cancel |
| SHARE-02 | public route dropdown | js/core_engine.js, js/acceptance_fixes.js | NOT RUN; enabled/error/loading/disabled/cancel |
| SHARE-03 | copy current payload | js/core_engine.js, js/acceptance_fixes.js | NOT RUN; enabled/error/loading/disabled/cancel |
| SHARE-04 | СОЗДАТЬ PUBLIC ROUTE empty state | js/core_engine.js, js/acceptance_fixes.js | NOT RUN; enabled/error/loading/disabled/cancel |
| SHARE-05 | stock QR КОПИРОВАТЬ / ЗАКРЫТЬ | js/core_engine.js, js/acceptance_fixes.js | NOT RUN; enabled/error/loading/disabled/cancel |
| SCAN-01 | contact scanner ОТМЕНА | js/core_engine.js | NOT RUN; enabled/error/loading/disabled/cancel |
| CONTACT-01 | manual input OK / alias OK | js/core_engine.js, js/runtime_fixes.js, js/acceptance_v50.js | NOT RUN; enabled/error/loading/disabled/cancel |
| CONTACT-02 | name chooser quick-name row | js/core_engine.js, js/runtime_fixes.js, js/acceptance_v50.js | NOT RUN; enabled/error/loading/disabled/cancel |
| CONTACT-03 | ВВЕСТИ ДРУГОЕ ИМЯ | js/core_engine.js, js/runtime_fixes.js, js/acceptance_v50.js | NOT RUN; enabled/error/loading/disabled/cancel |
| CONTACT-04 | preparation ОТМЕНА | js/core_engine.js, js/runtime_fixes.js, js/acceptance_v50.js | NOT RUN; enabled/error/loading/disabled/cancel |
| CONTACT-05 | pending request card | js/core_engine.js, js/runtime_fixes.js, js/acceptance_v50.js | NOT RUN; enabled/error/loading/disabled/cancel |
| CONTACT-06 | ПРИНЯТЬ / продолжить accept | js/core_engine.js, js/runtime_fixes.js, js/acceptance_v50.js | NOT RUN; enabled/error/loading/disabled/cancel |
| CONTACT-07 | ВЫЙТИ И ВЫБРАТЬ АККАУНТ | js/core_engine.js, js/runtime_fixes.js, js/acceptance_v50.js | NOT RUN; enabled/error/loading/disabled/cancel |
| CONTACT-08 | ОТКЛОНИТЬ | js/core_engine.js, js/runtime_fixes.js, js/acceptance_v50.js | NOT RUN; enabled/error/loading/disabled/cancel |
| CONTACT-09 | quick-name accept list / new quick-name | js/core_engine.js, js/runtime_fixes.js, js/acceptance_v50.js | NOT RUN; enabled/error/loading/disabled/cancel |
| CONTACT-10 | ЗАКРЫТЬ / НАЗАД | js/core_engine.js, js/runtime_fixes.js, js/acceptance_v50.js | NOT RUN; enabled/error/loading/disabled/cancel |
| CONTACT-11 | НАЧАТЬ ОБМЕН КЛЮЧАМИ | js/core_engine.js, js/runtime_fixes.js, js/acceptance_v50.js | NOT RUN; enabled/error/loading/disabled/cancel |
| CONTACT-12 | explicit Legacy Relay fallback ДА / НЕТ | js/core_engine.js, js/runtime_fixes.js, js/acceptance_v50.js | NOT RUN; enabled/error/loading/disabled/cancel |
| CHAT-01 | back arrow + browser/mobile Back | js/core_engine.js, js/chat_password.js | NOT RUN; enabled/error/loading/disabled/cancel |
| CHAT-02 | header peer ID click | js/core_engine.js, js/chat_password.js | NOT RUN; enabled/error/loading/disabled/cancel |
| CHAT-03 | rename pencil | js/core_engine.js, js/chat_password.js | NOT RUN; enabled/error/loading/disabled/cancel |
| CHAT-04 | chat password lock | js/core_engine.js, js/chat_password.js | NOT RUN; enabled/error/loading/disabled/cancel |
| CHAT-05 | locked-history password OK / cancel | js/core_engine.js, js/chat_password.js | NOT RUN; enabled/error/loading/disabled/cancel |
| CHAT-06 | composer text field | js/core_engine.js, js/chat_password.js | NOT RUN; enabled/error/loading/disabled/cancel |
| CHAT-07 | SEND / Enter / Shift+Enter | js/core_engine.js, js/chat_password.js | NOT RUN; enabled/error/loading/disabled/cancel |
| CHAT-08 | message delete × | js/core_engine.js, js/chat_password.js | NOT RUN; enabled/error/loading/disabled/cancel |
| NODE-01 | ДОБАВИТЬ УЗЕЛ | js/node_manager.js | NOT RUN; enabled/error/loading/disabled/cancel |
| NODE-02 | ДОБАВИТЬ ПО QR | js/node_manager.js | NOT RUN; enabled/error/loading/disabled/cancel |
| NODE-03 | ЗАПРОСИТЬ УЗЕЛ empty list | js/node_manager.js | NOT RUN; enabled/error/loading/disabled/cancel |
| NODE-04 | row ON / OFF | js/node_manager.js | NOT RUN; enabled/error/loading/disabled/cancel |
| NODE-05 | row QR | js/node_manager.js | NOT RUN; enabled/error/loading/disabled/cancel |
| NODE-06 | row gear | js/node_manager.js | NOT RUN; enabled/error/loading/disabled/cancel |
| NODE-07 | АВТОПОДКЛЮЧЕНИЕ checkbox | js/node_manager.js | NOT RUN; enabled/error/loading/disabled/cancel |
| NODE-08 | РАЗРЕШИТЬ / ВЫКЛЮЧИТЬ УВЕДОМЛЕНИЯ | js/node_manager.js | NOT RUN; enabled/error/loading/disabled/cancel |
| NODE-09 | СДЕЛАТЬ ОСНОВНЫМ | js/node_manager.js | NOT RUN; enabled/error/loading/disabled/cancel |
| NODE-10 | УДАЛИТЬ УЗЕЛ | js/node_manager.js | NOT RUN; enabled/error/loading/disabled/cancel |
| NODE-11 | КОПИРОВАТЬ ССЫЛКУ / НАЗАД | js/node_manager.js | NOT RUN; enabled/error/loading/disabled/cancel |
| NODE-12 | ОТМЕНА | js/node_manager.js | NOT RUN; enabled/error/loading/disabled/cancel |
| NODE-13 | НАЗАД | js/node_manager.js | NOT RUN; enabled/error/loading/disabled/cancel |
| MANAGED-01 | Подключить Node | js/node_account_ui_v4.js, js/managed_node_catalog_v4.js | NOT RUN; enabled/error/loading/disabled/cancel |
| MANAGED-02 | Публичный адрес Node field | js/node_account_ui_v4.js, js/managed_node_catalog_v4.js | NOT RUN; enabled/error/loading/disabled/cancel |
| MANAGED-03 | Ваше имя для запроса field | js/node_account_ui_v4.js, js/managed_node_catalog_v4.js | NOT RUN; enabled/error/loading/disabled/cancel |
| MANAGED-04 | Сообщение для знакомства field | js/node_account_ui_v4.js, js/managed_node_catalog_v4.js | NOT RUN; enabled/error/loading/disabled/cancel |
| MANAGED-05 | Создать / показать публичный адрес | js/node_account_ui_v4.js, js/managed_node_catalog_v4.js | NOT RUN; enabled/error/loading/disabled/cancel |
| MANAGED-06 | Копировать публичный адрес | js/node_account_ui_v4.js, js/managed_node_catalog_v4.js | NOT RUN; enabled/error/loading/disabled/cancel |
| MANAGED-07 | Отправить запрос | js/node_account_ui_v4.js, js/managed_node_catalog_v4.js | NOT RUN; enabled/error/loading/disabled/cancel |
| MANAGED-08 | Обновить запросы | js/node_account_ui_v4.js, js/managed_node_catalog_v4.js | NOT RUN; enabled/error/loading/disabled/cancel |
| MANAGED-09 | Выбрать аккаунт для принятия | js/node_account_ui_v4.js, js/managed_node_catalog_v4.js | NOT RUN; enabled/error/loading/disabled/cancel |
| MANAGED-10 | Принять в текущий аккаунт | js/node_account_ui_v4.js, js/managed_node_catalog_v4.js | NOT RUN; enabled/error/loading/disabled/cancel |
| MANAGED-11 | Подтвердить собеседника | js/node_account_ui_v4.js, js/managed_node_catalog_v4.js | NOT RUN; enabled/error/loading/disabled/cancel |
| MANAGED-12 | Завершить обмен ключами | js/node_account_ui_v4.js, js/managed_node_catalog_v4.js | NOT RUN; enabled/error/loading/disabled/cancel |
| MANAGED-13 | Повторить запрос | js/node_account_ui_v4.js, js/managed_node_catalog_v4.js | NOT RUN; enabled/error/loading/disabled/cancel |
| MANAGED-14 | Отклонить запрос / ДА, ОТКЛОНИТЬ / НЕТ | js/node_account_ui_v4.js, js/managed_node_catalog_v4.js | NOT RUN; enabled/error/loading/disabled/cancel |
| MANAGED-15 | PRIVATE адрес Node field / Проверенный ID собеседника field | js/node_account_ui_v4.js, js/managed_node_catalog_v4.js | NOT RUN; enabled/error/loading/disabled/cancel |
| MANAGED-16 | Создать PRIVATE QR | js/node_account_ui_v4.js, js/managed_node_catalog_v4.js | NOT RUN; enabled/error/loading/disabled/cancel |
| MANAGED-17 | Копировать PRIVATE адрес | js/node_account_ui_v4.js, js/managed_node_catalog_v4.js | NOT RUN; enabled/error/loading/disabled/cancel |
| MANAGED-18 | Проверить PRIVATE адрес | js/node_account_ui_v4.js, js/managed_node_catalog_v4.js | NOT RUN; enabled/error/loading/disabled/cancel |
| MANAGED-19 | Отправить PRIVATE запрос | js/node_account_ui_v4.js, js/managed_node_catalog_v4.js | NOT RUN; enabled/error/loading/disabled/cancel |
| MANAGED-20 | Обновить PRIVATE запросы | js/node_account_ui_v4.js, js/managed_node_catalog_v4.js | NOT RUN; enabled/error/loading/disabled/cancel |
| MANAGED-21 | Показать PRIVATE QR / Повторить PRIVATE запрос / Подтвердить PRIVATE контакт / Отклонить PRIVATE запрос | js/node_account_ui_v4.js, js/managed_node_catalog_v4.js | NOT RUN; enabled/error/loading/disabled/cancel |
| MANAGED-22 | Перевести существующий контакт на Node / confirm / cancel | js/node_account_ui_v4.js, js/managed_node_catalog_v4.js | NOT RUN; enabled/error/loading/disabled/cancel |
| MANAGED-23 | ЗАКРЫТЬ managed panel | js/node_account_ui_v4.js, js/managed_node_catalog_v4.js | NOT RUN; enabled/error/loading/disabled/cancel |
| MEDIA-01 | paperclip + hidden file input | js/core_engine.js, js/file_runtime.js, js/account_recorded_media.js | NOT RUN; enabled/error/loading/disabled/cancel |
| MEDIA-02 | file card ОТКРЫТЬ ФАЙЛ | js/core_engine.js, js/file_runtime.js, js/account_recorded_media.js | NOT RUN; enabled/error/loading/disabled/cancel |
| MEDIA-03 | ОТМЕНИТЬ ОТПРАВКУ stored card | js/core_engine.js, js/file_runtime.js, js/account_recorded_media.js | NOT RUN; enabled/error/loading/disabled/cancel |
| MEDIA-04 | incoming automatic receive status + cancel (NO separate YES/NO file consent) | js/core_engine.js, js/file_runtime.js, js/account_recorded_media.js | NOT RUN; enabled/error/loading/disabled/cancel |
| MEDIA-05 | progress Отмена / Закрыть | js/core_engine.js, js/file_runtime.js, js/account_recorded_media.js | NOT RUN; enabled/error/loading/disabled/cancel |
| MEDIA-06 | Сохранить файл link | js/core_engine.js, js/file_runtime.js, js/account_recorded_media.js | NOT RUN; enabled/error/loading/disabled/cancel |
| MEDIA-07 | microphone start | js/core_engine.js, js/file_runtime.js, js/account_recorded_media.js | NOT RUN; enabled/error/loading/disabled/cancel |
| MEDIA-08 | circle video start | js/core_engine.js, js/file_runtime.js, js/account_recorded_media.js | NOT RUN; enabled/error/loading/disabled/cancel |
| MEDIA-09 | camera-choice row / ОТМЕНА | js/core_engine.js, js/file_runtime.js, js/account_recorded_media.js | NOT RUN; enabled/error/loading/disabled/cancel |
| MEDIA-10 | recording × cancel (voice/circle) | js/core_engine.js, js/file_runtime.js, js/account_recorded_media.js | NOT RUN; enabled/error/loading/disabled/cancel |
| MEDIA-11 | SEND recording | js/core_engine.js, js/file_runtime.js, js/account_recorded_media.js | NOT RUN; enabled/error/loading/disabled/cancel |
| MEDIA-12 | cancel outbound / retry cancelled | js/core_engine.js, js/file_runtime.js, js/account_recorded_media.js | NOT RUN; enabled/error/loading/disabled/cancel |
| MEDIA-13 | incoming Принять / Отклонить | js/core_engine.js, js/file_runtime.js, js/account_recorded_media.js | NOT RUN; enabled/error/loading/disabled/cancel |
| MEDIA-14 | РАСШИФРОВАТЬ / КРУЖОК | js/core_engine.js, js/file_runtime.js, js/account_recorded_media.js | NOT RUN; enabled/error/loading/disabled/cancel |
| MEDIA-15 | ПОВТОРИТЬ decrypt | js/core_engine.js, js/file_runtime.js, js/account_recorded_media.js | NOT RUN; enabled/error/loading/disabled/cancel |
| MEDIA-16 | native audio/video playback controls | js/core_engine.js, js/file_runtime.js, js/account_recorded_media.js | NOT RUN; enabled/error/loading/disabled/cancel |
| MEDIA-17 | circle tap play/pause | js/core_engine.js, js/file_runtime.js, js/account_recorded_media.js | NOT RUN; enabled/error/loading/disabled/cancel |
| MEDIA-18 | image open / download link | js/core_engine.js, js/file_runtime.js, js/account_recorded_media.js | NOT RUN; enabled/error/loading/disabled/cancel |
| CALL-01 | VoIP call button / outbound cancel | index.html, js/core_engine.js, js/call_runtime.js | NOT RUN; enabled/error/loading/disabled/cancel |
| CALL-02 | incoming call accept / decline | index.html, js/core_engine.js, js/call_runtime.js | NOT RUN; enabled/error/loading/disabled/cancel |
| CALL-03 | microphone mute / unmute | index.html, js/core_engine.js, js/call_runtime.js | NOT RUN; enabled/error/loading/disabled/cancel |
| CALL-04 | camera enable / disable | index.html, js/core_engine.js, js/call_runtime.js | NOT RUN; enabled/error/loading/disabled/cancel |
| CALL-05 | switch camera | index.html, js/core_engine.js, js/call_runtime.js | NOT RUN; enabled/error/loading/disabled/cancel |
| CALL-06 | share screen | index.html, js/core_engine.js, js/call_runtime.js | NOT RUN; enabled/error/loading/disabled/cancel |
| CALL-07 | speaker toggle | index.html, js/core_engine.js, js/call_runtime.js | NOT RUN; enabled/error/loading/disabled/cancel |
| CALL-08 | end call | index.html, js/core_engine.js, js/call_runtime.js | NOT RUN; enabled/error/loading/disabled/cancel |
| NOTIFY-01 | ОТКРЫТЬ БОТА external link | js/core_engine.js | NOT RUN; enabled/error/loading/disabled/cancel |
| NOTIFY-02 | ОТКЛЮЧИТЬ МАЯК | js/core_engine.js | NOT RUN; enabled/error/loading/disabled/cancel |
| MODAL-01 | alert OK / modal close/back | js/core_engine.js | NOT RUN; enabled/error/loading/disabled/cancel |
| MODAL-02 | prompt field / OK / Enter | js/core_engine.js | NOT RUN; enabled/error/loading/disabled/cancel |
| MODAL-03 | prompt ОТМЕНА | js/core_engine.js | NOT RUN; enabled/error/loading/disabled/cancel |
| MODAL-04 | confirm ДА / НЕТ | js/core_engine.js | NOT RUN; enabled/error/loading/disabled/cancel |
| MODAL-05 | native confirm/prompt | js/core_engine.js | NOT RUN; enabled/error/loading/disabled/cancel |
| MODAL-06 | backdrop / sidebar / chat-main click | js/core_engine.js | NOT RUN; enabled/error/loading/disabled/cancel |
| LOCK-01 | flipper orientation gesture | js/core_engine.js, js/ui_logic.js | NOT RUN; enabled/error/loading/disabled/cancel |
| LOCK-02 | reload/window close/reopen | js/core_engine.js, js/ui_logic.js | NOT RUN; enabled/error/loading/disabled/cancel |
| ABSENT-01 | Full installation backup / export / import UI | js/file_runtime.js, js/app_shell.js, js/acceptance_fixes.js, js/ui_logic.js | ABSENT; verify absence |
| ABSENT-02 | Public Route DELETE UI | js/file_runtime.js, js/app_shell.js, js/acceptance_fixes.js, js/ui_logic.js | ABSENT; verify absence |
| ABSENT-03 | Generic Node password UI | js/file_runtime.js, js/app_shell.js, js/acceptance_fixes.js, js/ui_logic.js | ABSENT; verify absence |
| ABSENT-04 | Personal Telegram bot configuration UI (unloaded app_shell only) | js/file_runtime.js, js/app_shell.js, js/acceptance_fixes.js, js/ui_logic.js | ABSENT; verify absence |
| ABSENT-05 | Custom ringtone UI | js/file_runtime.js, js/app_shell.js, js/acceptance_fixes.js, js/ui_logic.js | ABSENT; verify absence |
| ABSENT-06 | Diagnostics launcher UI | js/file_runtime.js, js/app_shell.js, js/acceptance_fixes.js, js/ui_logic.js | ABSENT; verify absence |
| ABSENT-07 | Per-file affirmative YES / NO consent UI (trusted files auto-receive) | js/file_runtime.js, js/app_shell.js, js/acceptance_fixes.js, js/ui_logic.js | ABSENT; verify absence |
| ABSENT-08 | Master reconfiguration explicit Back / Cancel control | js/file_runtime.js, js/app_shell.js, js/acceptance_fixes.js, js/ui_logic.js | ABSENT; verify absence |
