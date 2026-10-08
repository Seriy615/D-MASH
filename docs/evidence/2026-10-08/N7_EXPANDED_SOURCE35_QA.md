# N7 expanded `.35` source-overlay browser gate

Exact isolated integration source `6a01feb252c1b94772a2b19503c9e1576a8c6356`.
Two fresh synthetic PRIVATE-paired Accounts used real UI and EMS S-TURN in
Chromium 156.0.8078.4 with mobile viewport/UA. Both page labels were `.35`;
service workers were intentionally blocked. All 268 captured source responses
matched the frozen tree. Page errors: 0. This is source-overlay evidence, not
a deployed or physical Android result.

21/21 checks passed: Account/Node setup, package copy/import, route, key
exchange, text preflight, and four file kinds. The generic 1 MiB + 13 B file,
valid WAV audio, PNG image, and browser-generated valid WebM video were
automatically received without a per-file Accept prompt. They appeared as
inline chat cards; image/video/audio previews rendered with media controls
where applicable. Each explicit Save click produced the same SHA-256 as its
synthetic source. No download event occurred merely from rendering a preview.

After successful media, a **test-only receiver `navigator.storage.estimate()`
low-free-space seam** caused the next real UI attachment to show a quota error
at the receiver and authenticated FAILED at the sender. The sender's local
encrypted file remained readable. This exercises the visible low-free-space
path without rewriting application quota constants or claiming real disk
exhaustion. The sender was then put offline after loading; actual attachment
and Cancel clicks yielded durable CANCELLED, retained local encrypted bytes,
and no recipient card. Reload preserved the four delivered cards plus sender
FAILED/CANCELLED states. Protected IndexedDB snapshots from paired, media,
and terminal checkpoints remain outside Git, mode 0600.

The original protected report accidentally allowed a fixture result object
to overwrite the word PASS on the two quota/cancel rows with their persisted
file states `failed` and `cancelled`; both assertions completed and printed
PASS. A separate protected normalized copy moves these values to `fileStatus`
and records the normalization. No observed result was changed.

This new-profile gate does **not** prove old `.34` schema migration, active
controlling SW `.35`, ordinary Node v4 authenticated media CONTROL, or Android
speed. Those remain separate release gates.

## Retained synthetic Saved Messages audit

On a retained `.35` Account/IndexedDB snapshot, 6/6 actual UI checks passed;
55/55 loaded source responses matched the same tree, SW blocked, page errors 0.
The Saved Messages contact deliberately has no whole-chat Delete control,
while a remote contact does. A new Saved text survived the visible Delete →
No path and disappeared after Delete → Yes. The unrelated remote chat still
showed all six file cards. The internal `Storage.deleteChatGamma()` path for
the special local peer was not invoked and is not claimed as a UI control.

Full synthetic reports and IndexedDB snapshots are protected outside Git;
this note contains no identities, keys, payloads, or raw logs.
