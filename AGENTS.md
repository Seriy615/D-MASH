# D-MASH — контекст разработки

Перед работой прочитать CURRENT_HANDOFF.md и D-MASH_Codex_Development_Plan.md.
CURRENT_HANDOFF.md — единственная текущая сводка; docs/archive — история, не
текущие указания, SHA или критерии DONE. Пользователь переводит разработку на
новый сервер; EMS paths в документации описывают прежнее deployment окружение.
Пользователь назначил forge-vps для source/context sync; фактический checkout
и результат синхронизации фиксируются в FORGE_SYNC.md. Production EMS/PWA
не переносятся автоматически вслед за source checkout.

Принятое требование: устройство работает полноценной Node, единая wire role NODE,
реальный чужой transit без Account login. DeviceRoot — локальный secret, а не
сетевая Device-модель. V3 Device gateway — временный migration path, не итоговая
архитектура и не скрытый fallback. Не заменять N0–N8/A–M/E6 целью «сделать v3
регрессию зелёной». Основной остаток — ordinary Account/contacts/UI integration
with NodeRuntimeHostV4, authenticated state/mailbox migration и полный N4 recovery.

Сохранять Node/Account identities, root/history, encrypted DB/keys и ownership.
Не reset storage ради PASS. Transit не использует Account E2EE keys. Не заявлять
анонимность, PCS/PFS/PQ или full DONE без соответствующей приёмки. DHT вне scope.

Reference tests: Python 3.12, Node.js 24.19.0, requirements-test.txt;
.venv/bin/python tools/test_all.py. Browser acceptance требует Playwright +
Chromium и отдельного реального transport. Различать UNIT / BROWSER / DEPLOYED,
historical evidence и новый exact-SHA PASS. Зависший observation не означает
остановленный process: проверить тот же live handle прежде, чем перезапускать.

При новом checkpoint обновлять CURRENT_HANDOFF.md вместо дописывания бесконечной
ленты старых contradictory статусов. Secrets/identities/DB/logs с credentials
не включать в Git. Evidence, пригодный для публикации, проверять и хранить с
SHA/limits; backup и rollback runtime state не подменять Git checkout.


Пользователь явно требует командную работу: основной агент — оркестратор,
тимлид, интегратор и тестировщик, реализацию выполняют делегированные агенты.
Разделять задачи и владение файлами/worktrees, передавать full scope, проверять
интеграцию самостоятельно. Локальное done одного агента не закрывает цель.

Всё проверять браузером. Перед новой разработкой инвентаризировать и нажать
каждую кнопку/меню/модальный control и пройти пользовательские flows, включая
error/loading/disabled/cancel. Завести BROWSER_QA.md с PASS/FAIL/NOT RUN,
версиями page/SW, воспроизведением, evidence, bug owner/fix/retest. Найденные
баги назначить агентам, исправить и повторно проверить реальными UI actions.
Подробный обязательный список — раздел 7 CURRENT_HANDOFF.md. Console/Core
вызовы и unit tests дополняют, но не заменяют клики и видимый результат.
Destructive сценарии — только на тестовых profiles/Accounts; не reset реальных
данных ради PASS. Browser-first аудит не отменяет Node архитектуру и N0–N8.
