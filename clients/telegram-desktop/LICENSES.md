# Client fork licensing boundary

The checkout is the original Telegram Desktop project at the exact revision in
UPSTREAM.json. LICENSE.upstream and LEGAL.upstream are unchanged copies of its
license and copyright notice. Keep both in distributed client source and packages.

The patch series, `dmash/` client adapters and their changes to Telegram source
are GPL-3.0-only, with the original upstream OpenSSL linking exception preserved.
Existing upstream copyright and license headers remain intact. This classification
covers client integration code; it does not relicense upstream dependencies.

`dmash/local_client.{cpp,h}` originated in this repository's
`native/platforms/desktop/credential_client.{cpp,h}`; `dmash/os_windows.{cpp,h}`
originated in `native/src/os_windows.{cpp,h}`. Their origin is recorded here rather
than implying they came from Telegram. The separate D-MASH native core continues
under its own existing license/provenance declarations. No Telegram source or
assets are copied into the separate core, and no blanket MIT label applies to
this GPL client or its dependencies.
