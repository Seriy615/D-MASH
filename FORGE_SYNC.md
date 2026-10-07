# Forge source/context synchronization

Пользователь назначил forge-vps для синхронизации репозитория и нового контекста
8 октября 2026 года. Обнаружен host forgeai.isgood.host, SSH user codex,
checkout /home/jcode/D-MASH, owner codex:codex. Имя jcode в path не означает,
что команды должны запускаться от несуществующего/другого пользователя.

Исходное состояние проверено: transport-v3, runtime SHA
`ed200730dab2e64fc8446e344ce54dbd37cfeec5`, локальная правка только
CURRENT_HANDOFF.md (старый checkpoint, 36 добавленных строк). Перед обновлением
она сохранена вместе с diff и SHA256SUMS в protected off-checkout backup:
`/home/jcode/dmash-handoff-backups/20261008-before-context-sync`. Восстановлен
только этот tracked файл из HEAD; reset всей рабочей директории не выполнялся.
Checkout теперь clean. Итог fast-forward sync будет зафиксирован после push
и проверки remote HEAD/tree/context hashes.
Это source/context sync, не deployment Messenger PWA на Forge, не перенос EMS
production runtime и не transfer secrets/databases. Не менять чужие Forge apps.

Текущий authoritative context: CURRENT_HANDOFF.md, AGENTS.md, BROWSER_QA.md и
полный D-MASH_Codex_Development_Plan.md. Runtime baseline — .24,
ed200730dab2e64fc8446e344ce54dbd37cfeec5. Финальный handoff commit брать из
Git history/rev-parse, чтобы не создавать самоссылку SHA внутри его содержимого.
