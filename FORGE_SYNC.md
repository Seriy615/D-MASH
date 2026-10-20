# Forge source/context sync

**20 октября 2026 UTC — текущая проверенная сводка. Цель ACTIVE, не DONE.**

| Поле | Фактическое состояние |
|---|---|
| Actual host | forgeai.isgood.host (`hostname` проверен) |
| Checkout | `/home/jcode/D-MASH` |
| Branch | `codex/native-clients-20261020` |
| Последний опубликованный local checkpoint | `3a7249230d245da703e3c3540591baa3ee137873` |
| Его Git tree | `a0d4b0ed35e0709774776aac253dfb6d0f5295ac` |
| GitHub CI snapshot | `214c5c5aced874cdc2e9e08e09688f3525112a05` |
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

Current app direction is actual Telegram forks, per explicit user correction.
The earlier custom Widgets/Views UI work is stopped and preserved; its scoped
PASS is not final frontend acceptance. Actual source checkouts independently
verified by root:

| Client | Checkout | Pinned upstream | License file SHA256 |
|---|---|---|---|
| Telegram Desktop | `/home/jcode/.cache/dmash-native-20261020/telegram-desktop-fork` | `86262333a457f62709726ee4ab9c48fa58824da4` | `30e52a0e4d8207c631458d98be89adcadf5b60e2608fe9c9a3eff1cde1877c8e` (GPLv3 + OpenSSL exception) |
| Telegram Android | `/home/jcode/.cache/dmash-native-20261020/worktrees/telegram-android` | `0aae959806c57be8ad457980f2a5c6277ff18635` | `8177f97513213526df2cf6184d8ff986c675afb514d4e68a404010521b880643` (GPLv2) |

Pinned fork recipes/patches39b5f02 Desktop and40c6c3b/e2053c7 Android are now
in published3a72492. The external mutable checkouts themselves and later changes
are not implicitly published or accepted binaries. Reproducible source/patch/build manifests will live under
clients/telegram-desktop and clients/telegram-android; no mass vendoring or
license reassignment. Separate own MIT core remains authoritative for
Account/Node state. Telegram network is not a fallback transport.

Published3a72492 includes actual Telegram fork recipes/initial adapters, accepted
private pairing and first-send durable queue, independent scoped evidence and
page/SW45. Root create_tree equality and git ls-remote verified; draft PR8 title/
body now describe actual forks. Connector PR head snapshots can be stale; actual
branch ref/tree is authoritative. Fork full builds/render/three-platform acceptance
remain open; old native CI harnesses are component checks only. No release,
deployment or runtime-state backup follows from source publication.

[CURRENT_HANDOFF.md](CURRENT_HANDOFF.md) is the current implementation/acceptance
authority, with original FAIL and scoped retests. CI snapshots are development
source, not release or deployment acceptance. Historical8/15October sync and
production records remain in Git history; their branches/SHAs/statuses are not
current source-sync instructions.
