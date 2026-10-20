# Forge source/context sync

**20 октября 2026 UTC — текущая проверенная сводка. Цель ACTIVE, не DONE.**

| Поле | Фактическое состояние |
|---|---|
| Actual host | forgeai.isgood.host (`hostname` проверен) |
| Checkout | `/home/jcode/D-MASH` |
| Branch | `codex/native-clients-20261020` |
| Последний опубликованный local checkpoint | `e00db0abb1baddc4c18bfd2ec6dd757c398f3d5e` |
| Его Git tree | `5ec547e905de8c901645ce6eab4be278f2525188` |
| GitHub CI snapshot | `0783fd0440767e76433c2902b5c8c80a918f0883` |
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

Publishede00db0a includes actual Desktop full-application Linux CI c8b393c,
Desktop projection/storage fencing0917d37, Android six-patch recipe cd7cc30,
Account connection/worker binding0288bff and root independent process acceptance.
Root reconstructed all30Android patched files from exact upstream+six patches.
Existing native Android/Windows workflows remain intermediate component harnesses;
new Linux workflow builds the selected actual Telegram application. Owned launch paths/MIT notices/cache-location correction e740454, exact pool
URLs02250ac and actual Android KVM workflow e00db0a are included. Root confirmed
all131 Linux package versions/hashes unchanged and downloaded failing protobuf
archive with matching pinned hash. Actual Android39467452315/Linux39467452496
CI runs are in progress; no runtime/screenshot PASS yet. A workflow being published does not imply its build/runtime passed.

Root create_tree equals tracked local tree5ec547e9... and git ls-remote independently
confirms0783fd04...; PR8 remains draft. This source snapshot excludes unstaged old
UI WIP. Actual fork render/ordinary messaging/three-platform acceptance remain
open. No production, release or runtime-state backup follows from publication.

[CURRENT_HANDOFF.md](CURRENT_HANDOFF.md) is the current implementation/acceptance
authority, with original FAIL and scoped retests. CI snapshots are development
source, not release or deployment acceptance. Historical8/15October sync and
production records remain in Git history; their branches/SHAs/statuses are not
current source-sync instructions.
