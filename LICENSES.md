# License scope and source distribution

The [MIT license](LICENSE) applies to original D-MASH core code and original
project documentation, except files with their own applicable license or
third-party provenance. This implements the project's existing MIT declaration;
it does not grant rights to somebody else's code or erase their notices.

| Component | Applicable scope |
| --- | --- |
| Original D-MASH core and daemon | MIT; preserve third-party notices within source and dependencies. |
| Telegram Desktop fork and adaptation patches | Upstream GPLv3 with its preserved OpenSSL linking exception. See [client notices](clients/telegram-desktop/README.md) and pinned upstream license/LEGAL. |
| Telegram Android fork and adaptation patches | Upstream license text and GPLv2-or-later source headers retained. See [client notices](clients/telegram-android/README.md). |
| Dependencies and vendored code | Their existing licenses; repository-level MIT does not replace them. |

The clients communicate with the independent Account/Node processes through
local IPC. Client GPL adaptations remain published as client source; they are
not copied into the MIT core. Packages built from either fork need the matching
upstream source revision, our exact patches/build instructions and applicable
upstream/dependency notices. The source pins alone are not a completed package
license audit or a substitute for supplying the corresponding source.

[Native package notices](native/platforms/licenses/THIRD_PARTY_NOTICES.md) cover
the intermediate native harness dependencies. Actual fork packages contain
additional upstream dependencies and need their own resolved inventory.
[Account provenance](native/account/README.md) records the exact legacy Kyber
WASM/generated C and WABT translation/runtime boundary. That artifact is not
relicensed by this file; its complete redistribution provenance remains a
release gate. Embedded notices such as the ISC fragment in route-discovery code
must also remain intact.

Actual fork builds and package distribution acceptance are still open. No
complete redistribution/license audit is claimed for the three final apps.
