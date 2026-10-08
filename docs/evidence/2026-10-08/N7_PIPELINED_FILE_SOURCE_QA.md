# N7 pipelined file candidate: real browser source gate

Scope: isolated commit `79974e734c03db5668a8c2a6a28d4a68b19eb396`,
source-overlay UI with two fresh synthetic PRIVATE-paired Accounts and actual EMS
S-TURN transport. Chromium 156.0.8078.4, mobile viewport/UA. Both page release
labels were `transport-v3-node-preparation-20261008.32`; service workers were
intentionally blocked for the source overlay. All 268 captured source responses
matched the candidate bytes. This is not a deployed or physical Android gate.

All 17 browser checks passed: Account setup, Node request/transport readiness,
PRIVATE package copy/import/route, chat clicks, key exchange, ordinary text,
1 MiB + 13 byte generic file automatic receive and explicit download with
equal SHA-256, valid 16 MiB WAV automatic receive and inline audio preview,
and both file cards/sender delivered state after reload. There was no per-file
Accept button, no page error, and no unexpected modal. The four console
warnings were the expected blocked service-worker registrations.

| Transfer | UI elapsed | File chunks, first to last sender ACK | Other measured stages |
| --- | ---: | ---: | --- |
| 1 MiB + 13 B | 6.720 s | 0.631 s | sender admission 2.940 s; sender at-rest AES 0.038 s; receiver commit 0.052 s |
| 16 MiB WAV | 27.330 s | 13.222 s (~1.21 MiB/s) | sender admission 0.709 s; sender at-rest AES 0.511 s; manifest SHA 0.212 s; receiver encrypted commit 0.332 s |

The earlier real-browser stop-and-wait baseline for 16 MiB was 163.605 s,
with 154.57 s in 512 sequential 32 KiB ACKs. The eight-in-flight window is
about 6.0× faster end to end in this desktop run. This supports retaining
the current WebRTC DataChannel over forced S-TURN while measuring real Android
and adverse networks; it does not establish mobile speed or complete N7.

Remaining gates: image/video preview controls, offline/cancel and quota UI,
ordinary Node v4 authenticated CONTROL authority, integrated exact-release
unit/browser gates, deployed page and active SW, and physical Android timing.
The full synthetic report remains protected outside Git; this evidence contains
only whitelisted metadata, with no identities, keys, payloads or raw logs.
