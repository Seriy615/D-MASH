# Forge source/context sync

**20 октября 2026 UTC — текущая проверенная сводка. Цель ACTIVE, не DONE.**

| Поле | Фактическое состояние |
|---|---|
| Actual host | forgeai.isgood.host (`hostname` проверен) |
| Checkout | `/home/jcode/D-MASH` |
| Branch | `codex/native-clients-20261020` |
| Последний опубликованный local checkpoint | `d0d41d99784b75846f27d3dc740eb82d91879e2c` |
| Его Git tree | `23c7f6224c254dadec8781e9326a8373e170450b` |
| GitHub CI snapshot | `39c8790657393bf7be967f7a8549b76528c31d28` |
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

Current open edits belong to the platform agent: visible Desktop Node controls
and Android credential service integration. Broker recovery and remote Account
work use separate worktrees. `/home/jcode/D-MASH-Gamma` is old WIP and untouched.
No reset/clean/force-push, production deployment or EMS/PWA/backend migration was
performed in this native-client work. Earlier EMS paths in repository documents
refer to the previous deployment environment and are not a migration result.

Linux independent accepted scopes: retained Account import/history, initial
import recovery, actual foreign transit/durable delivery, resident host scoped
cancellation, actual Widgets controls and UI-process death preserving Node.
Android/Windows actual acceptance, remote Account delivery, full crash recovery,
NAT, buffered files and complete UI/policies remain open. Automatic capability
renewal was withdrawn in abf1c16 after a stronger context-retention check failed;
private extension/recovery fixes remain under verification.

CURRENT_HANDOFF.md is the current development authority. Earlier8/15October
source sync and deployment records are historical evidence in Git history;
their branch names, SHAs and pause/release statuses are not current instructions.
