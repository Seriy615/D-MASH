# Forge source/context sync

**20 октября 2026 UTC — текущая проверенная сводка. Цель ACTIVE, не DONE.**

| Поле | Фактическое состояние |
|---|---|
| Actual host | forgeai.isgood.host (`hostname` проверен) |
| Checkout | `/home/jcode/D-MASH` |
| Branch | `codex/native-clients-20261020` |
| Последний опубликованный local checkpoint | `3728b200004e53ddb3ba3ba5bf4283752999dfd5` |
| Его Git tree | `8605797e1d27dd283f8b63053cc18a07c9ab4355` |
| GitHub CI snapshot | `83709da24fa0a09e8feb5db358175a26f2a5c14c` |
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

Current open platform edits: Desktop test file-chooser correction and Android
credential service integration. Broker recovery and remote Account
work use separate worktrees. `/home/jcode/D-MASH-Gamma` is old WIP and untouched.
No reset/clean/force-push, production deployment or EMS/PWA/backend migration was
performed in this native-client work. Earlier EMS paths in repository documents
refer to the previous deployment environment and are not a migration result.

Linux independent accepted scopes: retained Account import/history, initial
import recovery, actual foreign transit/durable delivery, resident host scoped
cancellation, actual Widgets controls and UI-process death preserving Node.
Native Linux remote Account E2EE/durable commit-before-consume crash/replay independently
accepted on immutable283ba51 (integrated3e3e845), separately from normal UI. Android
KVM launcher/Details/off-state retest PASS; first scoped service install times out.
Windows reaches C++ compilation but failed QuickJS VERSION shadowing <version>;
069c360/3728b20 fixes now published for actual CI. Full apps, crash recovery, NAT,
buffered files and complete UI/policies remain open. Automatic host renewal was
withdrawn in abf1c16; private lease-extension64e independently passes real expiry.
Corrected hosta52e9f5 now independently passes root process/crash/ACTIVE grant
lease fixtures and integrates as f8b17d2/1a5f179/87fc172; these newer commits are
not in the published3728b20 tree yet. Original405 bootstrap failure remains an
unexplained observation. Desktop clipboard test33a6273 root Account-onlyPASS;
full optionalNode gate remains timed out. Current evidence is in CURRENT_HANDOFF.md.

CURRENT_HANDOFF.md is the current development authority. Earlier8/15October
source sync and deployment records are historical evidence in Git history;
their branch names, SHAs and pause/release statuses are not current instructions.
