# Forge source/context sync

**20 октября 2026 UTC — текущая проверенная сводка. Цель ACTIVE, не DONE.**

| Поле | Фактическое состояние |
|---|---|
| Actual host | forgeai.isgood.host (`hostname` проверен) |
| Checkout | `/home/jcode/D-MASH` |
| Branch | `codex/native-clients-20261020` |
| Последний опубликованный local checkpoint | `e727884b1d689675e466512d69c01242e69bad6a` |
| Его Git tree | `4ee4c17f713282a5313a2ac1bc024a5ae9c90faf` |
| GitHub CI snapshot | `177cebc72bad180b36cd38f1678c0c82348fa220` |
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

Published e727884 includes d0f6990 Android ordinary Account Views/credential
service and matching actual UI CI, eea5c69 Desktop fresh setup, independent scoped
proofs, and explicit restored Telegram design requirement. Current old layout is
functional infrastructure, not accepted Telegram design. Telegram redesign WIP,
isolated pause/pairing and later docs are not implicitly published. No release,
deployment or platform runtime success follows from source publication.

[CURRENT_HANDOFF.md](CURRENT_HANDOFF.md) is the current implementation/acceptance
authority, with original FAIL and scoped retests. CI snapshots are development
source, not release or deployment acceptance. Historical8/15October sync and
production records remain in Git history; their branches/SHAs/statuses are not
current source-sync instructions.
