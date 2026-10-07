# Account / local history / media browser audit

Fresh synthetic profile against published `https://messenger.d-mash.ru/not_messenger/`.
Page and active SW: `transport-v3-recorded-fragments-20261008.24`.
Browser reported `156.0.8078.4`; Node runner `24.19.0`.
Canonical per-action results and visible DOM control inventory: `qa-account-media.json`.
Reproducer: `tools/qa_account_media.cjs`, set `DMASH_PLAYWRIGHT_MODULE` and `DMASH_CHROME`.
All mutations use actual click/fill/native file chooser. Script evaluation only observes
page/SW versions, visible controls and media playback progress. Microphone/camera synthetic.

The JSON is authoritative for the final run. Earlier selector mistakes (message text
includes the delete glyph, duplicate sidebar/header title, overwritten settings method)
were harness errors, not product bugs; rerun uses actual rendered locators.

## Scope limits

- Account create/registry/logout/select/relogin is covered. Different Account switch,
  concurrent locked Account, credential recovery and invalid nonempty login: NOT RUN.
- Saved Messages text, empty SEND, rename cancel, delete cancel/confirm, password
  cancel/set/wrong/unlock/remove and retained history are covered.
- Local voice start/cancel/SEND/decrypt/native playback and circle start/cancel covered.
  Remote voice/circle send, video playback, permission denied, device selection,
  failed playback retry/download, chat/Account switch during capture: NOT RUN.
- Local file selection proves explicit unsupported Saved Messages response only.
  Remote consent/reject/transfer/cancel/progress/download/hash/bounds: NOT RUN.
- Calls start/accept/decline/hangup/mute/video/screen share and RTC stats: NOT RUN.
- Notification consent/wake/locked neutral display: NOT RUN.
- Master change is included in the final run: wrong old code, rotation, reload,
  old-code refusal, new-code unlock, same registry Account and retained local history.
- This local audit is not Node transit, remote transport, physical device or N8 acceptance.
