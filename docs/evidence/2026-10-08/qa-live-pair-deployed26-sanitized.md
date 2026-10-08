# Live pairing with user — sanitized checkpoint

- Date: 2026-10-08 UTC. Target: EMS deployed PWA, page/SW
  `transport-v3-node-preparation-20261008.26`, backend release `.26`.
- User supplied a public pairing package in chat. A new, separate synthetic
  Account imported it through `[ + ]`; the reciprocal package was imported by
  the user. The synthetic Account connected to one EMS Node through UI.
- Actual chat UI showed an established key channel. One marked test text was
  sent; authenticated `READ` receipt appeared. User reply appeared in the same
  chat and both messages remained in local history. User sent one recorded
  voice note; receiver clicked `РАСШИФРОВАТЬ`, browser audio metadata loaded
  (`readyState=4`, duration 2.3 s, error null).
- This proves a single real bidirectional v3 contact/message exchange with
  this user and inbound voice decode. It does not prove N3 Node cutover,
  long-term reliability, mobile FlipLock or S-TURN recorded-note delivery.
- User reported a long sender `шифрование` state and supplied a screenshot of
  `Recorded-note queue full`. A separate fresh synthetic two-profile run on
  deployed `.26` reproduced ~54 s for a 2.3 s note over 13 Mesh fragments,
  stale sender `⌛` after recipient received it, and queue-full on a third
  immediate recording. Existing durable rows were preserved; the rejected
  third recording was discarded by the current UI. New media transport work
  remains open.
- The user's pairing identifiers, contribution, audio bytes and screenshots
  are kept outside Git. No real profile storage was reset, exported or edited.
