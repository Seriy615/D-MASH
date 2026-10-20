# Forge source/context sync

**20 октября 2026 UTC — текущая проверенная сводка. Цель ACTIVE, не DONE.**

| Поле | Фактическое состояние |
|---|---|
| Actual host | forgeai.isgood.host (`hostname` проверен) |
| Checkout | `/home/jcode/D-MASH` |
| Branch | `codex/native-clients-20261020` |
| Последний опубликованный local checkpoint | `4bdf1da6693adacfb18cd975d7ce1645f54c79fc` |
| Его Git tree | `5b6c9a4cc725b615bd04bd4d10ebc51db7c5b395` |
| GitHub CI snapshot | `4edab65caa3d0d7d2c4a27f827c5e167887babbe` |
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

Published4bdf1da includes accepted remote Account/retry integration, corrected
host recovery/lease, freshRoot1930b80, Desktop selector33a6273 and Android fixed
startup stage diagnostics c145656/5d1d2ce. Independent fixture05dd2cc and newer
root evidence/docs are newer than that published snapshot; they do not become
a published or rebuilt platform binary implicitly.

[CURRENT_HANDOFF.md](CURRENT_HANDOFF.md) is the current implementation/acceptance
authority, with original FAIL and scoped retests. CI snapshots are development
source, not release or deployment acceptance. Historical8/15October sync and
production records remain in Git history; their branches/SHAs/statuses are not
current source-sync instructions.
