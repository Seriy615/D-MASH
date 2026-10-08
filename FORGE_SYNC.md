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
| Push origin | git@github.com:Seriy615/D-MASH.git; direct Forge SSH denied; verified EMS temporary publisher workflow available |

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
На момент первоначального sync runtime был .24; актуальная публикация ниже. Другие Forge apps не менялись. Checklist реальной
runtime migration есть в CURRENT_HANDOFF.md.

Первое действие следующего сеанса: прочитать CURRENT_HANDOFF.md, AGENTS.md,
BROWSER_QA.md и полный план; организовать делегированные агенты; проверить в
браузере каждую кнопку и сценарий, исправить FAIL и выполнить browser retest.
Принятое требование единой Node-модели сохраняется: v3 gateway временный,
ordinary Account/contact UI → Node v4 cutover остаётся главным этапом.

## Текущая разработка и публикация

8 октября 2026: Forge HEAD и origin/transport-v3 после push/fetch совпали:
`a4fd2aa24f31f07c372da5573f638f8d331df8af` (Account committed-session
lifecycle + QA helper; exact UNIT280+11+76, browser UI29/29 source-overlay,
ordinary v4 UI not wired).
Production runtime остаётся `3c513601ef3990b6514e247d879324b7b72da494`. Предыдущий QA-only checkpoint:
`2c4523d533df34681fdb682ffeccded5d791b5eb`. Текущий runtime release `.26`
опубликован через existing EMS get_commit.sh по полному SHA;214 source files
совпадают, missing/changed отсутствуют. Backup static PWA:
`/srv/messenger.d-mash.ru/backups/manual-rollback-20261008T004036Z`.
Текущая браузерная приёмка/FAIL/limits — CURRENT_HANDOFF.md и BROWSER_QA.md.

Прямой Forge SSH push всё ещё denied(publickey). Авторизованный existing EMS
GitHub key публикует exact Forge commits через отдельный temporary bare
repository и проверенный incremental Git bundle. Push обычный fast-forward,
без force. Production checkout EMS остался на `ed200730…`: deploy извлекает
полный SHA через git archive, поэтому checkout HEAD не runtime evidence.
Root deploy использует scoped safe.directory и SSH от codex, без копирования
секретов или глобальной настройки. Backend обновлён только route_discovery_v4.py после consistent protected snapshot
6 DB,4 key files unchanged; dependencies/config/storage schema не менялись.
Разработка и интеграция остаются на Forge; production не переносился.
