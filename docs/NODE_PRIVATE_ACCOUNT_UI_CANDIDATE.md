# Managed PRIVATE Account/UI candidate

Isolated followup to5630a15 plus4262ae2 receipt continuation. Not deployed, no
PRIVATE browser PASS. Page/SW remain review .34; root owns eventual release bump.

The ordinary Node contacts panel now offers a signed PRIVATE QR/link, import,
explicit Account ID inspection, request, selection/decline and bilateral receipt
completion. QR/scanner import routes the explicit private-v4 prefix to this panel;
it never transforms it into a legacy v3 contribution. Existing legacy import
remains an explicit compatibility path for retained contacts.

An encrypted Account index reserves at most eight offer slots before creating
material. Signed bundle, route keys, Account-specific KEM reference, migration ID
and exact request bytes remain encrypted in pairing_material. Reopen verifies and
reuses them; missing material remains PENDING rather than regenerating a published
identity. The compression wrapper preserves signed bytes and bounds inflation to
12KiB. QR uses L error correction if the resulting URI fits; otherwise it visibly
requires copying the full address. Actual camera scan reliability remains a gate.

The same managed public-v1 Host already supports the separate private bootstrap
namespace. A genuine owner capability provisions BOOTSTRAP_ONLY. REQUEST delivers
the second signed bundle; selected Account journal reserves ACCEPT/CONFIRM before
sending. Only both verified receipts permit Host PREPARED → Account atomic commit
→ Host ACTIVE. Ordinary N4 then establishes keys; ACTIVE alone never enables text.
Final exact receipt retries use the bounded4262 continuation, never new REQUEST or
user payload after ACTIVE. Routes/grants remain owner-scoped and are released after
control submission. Existing peer migration still requires its explicit UI action
and trusted same-tx SessionStore proof; missing N4 proof support fails closed.

Nine focused UNIT suites PASS: signed offer/IDB index preservation and wrong-peer/
missing-request refusal (synthetic KEM/Host boundary); private compressed link size,
canonical encoding/inflation refusal; existing public/Core/UI/history/loader seams.
These are not a substitute for genuine KEM/Worker/Python/QR browser acceptance.

Open gates: actual two-party PRIVATE QR/request/receipt/N4/text; last-receipt loss
and root reload; preserved legacy contact migration; meaningful Account switch and
cross-owner attempts; draft-slot recovery/pruning policy; expired route renewal;
root-only transit and full lock; final CONTROL/S-TURN media. Never reset real data.
