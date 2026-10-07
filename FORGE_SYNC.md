# Forge source/context synchronization — PASS

Дата: 8 октября 2026, Europe/Moscow. Пользователь назначил forge-vps для
синхронизации source/context и дальнейшей разработки.

| Поле | Проверенный результат |
|---|---|
| SSH alias / actual host | forge-vps / forgeai.isgood.host |
| SSH / Git owner | codex / codex:codex |
| Checkout | /home/jcode/D-MASH |
| Branch | transport-v3 |
| Проверенный базовый handoff commit | c14b0b07f9229988f8bbb83f88b3b73504784272 |
| Git tree базового handoff | 0b9aa4e3238f40e813717e7e244c5cd7531c1dfb |
| Runtime baseline | ed200730dab2e64fc8446e344ce54dbd37cfeec5, .24 |
| Обновление | fetch + merge --ff-only, без force/reset всего checkout |
| Проверка | HEAD/tree совпали с local pushed snapshot; 6 context/evidence file SHA256 совпали; clean working tree |
| Fetch origin | https://github.com/Seriy615/D-MASH.git |
| Push origin | git@github.com:Seriy615/D-MASH.git; SSH write access требует настройки |

До обновления на Forge было только локальное изменение CURRENT_HANDOFF.md:
старый .24 checkpoint, 36 добавленных строк. Полный файл, binary diff и SHA256SUMS
сохранены с owner-only permissions вне checkout:
`/home/jcode/dmash-handoff-backups/20261008-before-context-sync`.
Затем восстановлен только этот tracked файл из HEAD для безопасного fast-forward.
Другие локальные данные/ignored runtime state не удалялись.

Первый fetch через существующий SSH GitHub URL получил Permission denied
(publickey). Уже pushed commit получен по публичному HTTPS; origin fetch URL
исправлен на HTTPS, существующий SSH push URL сохранён. Частные SSH keys с Mac
не копировались. Перед первым remote push необходимо настроить разрешённый
GitHub write access на Forge либо использовать установленный пользователем
аутентифицированный workflow. Source sync уже завершён; отсутствие write key
не мешает читать репозиторий или работать локально с ним.

Файл фиксирует проверку базового handoff snapshot выше; этот отчёт добавлен
следующим documentation commit, который также синхронизируется на Forge.
Актуальный полный handoff SHA всегда получать через `git rev-parse HEAD` и
сверять с `git rev-parse origin/transport-v3`, без самоссылки SHA в содержимом
его собственного commit. После последнего sync обе ревизии должны совпадать,
рабочая директория должна быть чистой.

Это **source/context sync**. Messenger PWA, EMS production backend, его
identities/DB/TURN secrets и домены этим действием на Forge не переносились.
Runtime release остаётся .24. Другие Forge apps не менялись. Checklist реальной
runtime migration есть в CURRENT_HANDOFF.md.

Первое действие следующего сеанса: прочитать CURRENT_HANDOFF.md, AGENTS.md,
BROWSER_QA.md и полный план; организовать делегированные агенты; проверить в
браузере каждую кнопку и сценарий, исправить FAIL и выполнить browser retest.
Принятое требование единой Node-модели сохраняется: v3 gateway временный,
ordinary Account/contact UI → Node v4 cutover остаётся главным этапом.
