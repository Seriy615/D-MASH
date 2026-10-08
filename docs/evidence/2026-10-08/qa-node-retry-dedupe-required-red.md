# Required red: identical recipient ciphertext on a fresh granted path

Observed against unchanged routing sources at source HEAD
`6cc79167196716a0ff3b87ac1442ca62ae4acdfb`:

- Python SHA256: `2a4cd261d8a245b4a91c3213d008f6c585386f7580a4e368520478c73cff238f`.
- JavaScript SHA256: `2cc00afd2eb7fe5926479b7867c26389b0aed0f819e45532e4a33ec1a48ab419`.
- Python handle 30312: exit 1, required assertion failure.
- JavaScript handle 84937: exit 1, same required assertion failure.

The three real routing runtimes use admitted-operation channel adapters, genuine
signed discovery certificates and opaque recipient encryption. This is routing
UNIT evidence, not authenticated socket or browser acceptance. No Account keys
or identifiers participate.

First DATA is dropped on the hub-to-recipient leg after the hub processes it.
An identical retry on the same grant is correctly suppressed. Fresh signed
rediscovery produces a different granted hop-local label. Retrying the unchanged
recipient ciphertext through this grant incorrectly remains suppressed by the
hub's payload-only DATA deduplication. The recipient never receives it.

Required assertion: a fresh certified grant must permit the identical ciphertext
retry, while duplicate delivery on the same grant stays suppressed and bounded.
Destination packet-ID/Account deduplication remains independently required.

The first Python fixture run (55061) failed initial discovery because its fault
adapter accidentally matched a missing payload; that run is excluded. Corrected
30312 reached the intended assertion. Raw synthetic ciphertext from the JavaScript
assertion output is deliberately omitted from this sanitized evidence.

## Narrow correction, pre-commit frozen source

DATA duplicate identity now includes the already validated incoming peer and
hop-local grant label. PROBE identity and all packet schemas remain unchanged.
Python/JavaScript remain bounded by the existing 4096-entry expiry-pruned table.
The JavaScript post-await check still rejects replaced bindings or removed peers.

- Corrected standalone Python 57094 and JavaScript 54320: exit 0.
- Existing Python routing 95764: six tests, exit 0.
- Existing JavaScript routing 9343: exit 0.
- New standard-suite Python wrapper 56705: one test, exit 0.
- New standard-suite JavaScript wrapper 22949: exit 0.

These checks cover downstream loss before recipient delivery. Endpoint Inbox
packet-ID deduplication is unchanged; they do not establish recovery when an
application response is lost after the original packet was consumed. Real socket,
browser, ordinary UI and exact committed-SHA acceptance remain separate gates.
