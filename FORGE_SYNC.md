# Forge source/context sync

**20 октября 2026 UTC — текущая проверенная сводка. Цель ACTIVE, не DONE.**

| Поле | Фактическое состояние |
|---|---|
| Actual host | forgeai.isgood.host (`hostname` проверен) |
| Checkout | `/home/jcode/D-MASH` |
| Branch | `codex/native-clients-20261020` |
| Последний опубликованный local checkpoint | `6c1bbbc4ff80ad865959b0d13eff236b1b001b51` |
| Его Git tree | `d7dafc0697a349e8941de7164e1baae621776d83` |
| GitHub CI snapshot | `aa30fb2cafa8198665f41f406af58c01c29d3022` |
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

Published6c1bbbc includes Desktop draftc6db2fa (original Intro/Account/DataSession/
History/composer) and Android70f5513 two-patch recipe (Java module16b2cbf PASS,
no APK/runtime), MIT core text/GPL dependency scope and root independent actual
browser/native interop. All27Desktop/21Android patched files independently
reconstructed from pinned upstream and verified against manifest digests.

Root create_tree equals tracked local tree d7dafc... and git ls-remote independently
confirms aa30fb2...; PR8 remains draft. The source checkout/source snapshot does
not include later agent WIP or imply final app/deployment acceptance. Actual
fork full builds/render/three-platform acceptance remain open; existing native
CI workflows still exercise intermediate component harnesses. No production,
release or runtime-state backup follows from source publication.

[CURRENT_HANDOFF.md](CURRENT_HANDOFF.md) is the current implementation/acceptance
authority, with original FAIL and scoped retests. CI snapshots are development
source, not release or deployment acceptance. Historical8/15October sync and
production records remain in Git history; their branches/SHAs/statuses are not
current source-sync instructions.
