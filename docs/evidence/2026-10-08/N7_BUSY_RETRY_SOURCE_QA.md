# N7 concurrent incoming file retry: real browser source gate

Isolated product commit `d24e6132ee8977ea627ecf68ed2b1ded307ba616`.
Three fresh synthetic PRIVATE-paired Accounts used actual UI key exchange and
EMS S-TURN. Chromium 156.0.8078.4, mobile viewport/UA, page label `.32`,
service workers blocked for source overlay. All 201 captured source responses
matched the frozen candidate bytes; page errors: 0. This is not a deployed
or physical Android gate.

23/23 checks passed. Two senders paired independently with one receiver.
Sender 1 started a valid 16 MiB WAV through the attachment button. Sender 2
attached a 1 MiB + 13 B generic file while the first transfer was active.
The receiver showed a visible busy notice, sender 2 showed a waiting state,
and sender 1 delivered. Sender 2 then retried automatically, delivered once,
and the receiver had exactly one inline card. An explicit download click gave
the same SHA-256 as the synthetic source bytes. Both text preflights passed.

Earlier setup attempts were harness-only failures before any file action:
the first omitted QR package copy; the second clicked an unstable list index;
the third tried the contact list while a mobile chat overlay required its
visible back button. The passing run used actual back and contact clicks,
without force clicks. The protected synthetic reports remain outside Git;
this note contains no identities, keys, payloads, or raw logs.

Remaining gates include integrated `.35` page/SW, old `.34` profile migration,
quota/cancel and image/video preview UI, ordinary Node v4 authenticated
CONTROL, and physical Android timing.
