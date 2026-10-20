# Forge source/context sync

**20 октября 2026 UTC — текущая проверенная сводка. Цель ACTIVE, не DONE.**

| Поле | Фактическое состояние |
|---|---|
| Actual host | forgeai.isgood.host (`hostname` проверен) |
| Checkout | `/home/jcode/D-MASH` |
| Branch | `codex/native-clients-20261020` |
| Последний опубликованный local checkpoint | `f63999927916daee7fd7c7f2baae4e55bf46fb61` |
| Его Git tree | `7223bc5867c8df77abdc7e16cec1a567fcbcb8b8` |
| GitHub CI snapshot | `ec66d1142cdc94a8859cec4e29f6b72c4baef45b` |
| Remote branch | `codex/native-clients-ci-20261020` |
| Draft PR | https://github.com/Seriy615/D-MASH/pull/8 |
| Source sync | Exact tracked tree uploaded through connected GitHub app; create_tree SHA exactly matches local tree; remote head independently checked with `git ls-remote` |
| Worktree | Agent WIP preserved; not clean, not a release tree |
| Direct Git push | HTTPS credentials absent; SSH publickey denied. No credentials copied or global auth altered |

GitHub snapshot commits have different commit SHAs because the connector creates
commits; the compared **file tree** is exact. Source/context checkpoints do not
back up runtime DBs, keys, identities, or accepted queues. Private profiles,
owning backups and frozen executable checkpoints remain outside Git under
`/home/jcode/.cache`; public bounded evidence is linked from CURRENT_HANDOFF.md.

Current open platform edits: Android normal Views/credential service integration,
excluded from the published tree. Broker pause and native private pairing work
use separate worktrees. `/home/jcode/D-MASH-Gamma` is old WIP and untouched.
No reset/clean/force-push, production deployment or EMS/PWA/backend migration was
performed. Earlier EMS paths describe the previous deployment environment.

Published f639999 includes accepted fresh Root/foreign transit source and evidence,
Windows bounded startup diagnostics and pinned dependency cache, Android fixed
startup markers plus Qt-loader reason collector (including warning severity),
and platform-specific CI path scopes. Android/Desktop normal UI WIP and isolated
pause/pairing branches are not in this published tree. No application release
or runtime success follows from source publication.

[CURRENT_HANDOFF.md](CURRENT_HANDOFF.md) is the current implementation/acceptance
authority, with original FAIL and scoped retests. CI snapshots are development
source, not release or deployment acceptance. Historical8/15October sync and
production records remain in Git history; their branches/SHAs/statuses are not
current source-sync instructions.
