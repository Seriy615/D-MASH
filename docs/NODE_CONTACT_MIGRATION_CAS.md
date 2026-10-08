# Contact migration transaction barrier

Followup to root lifecycle22994f9. Trusted History.verifyMigration must now return
{peer,bindingDigest,generation,sessionId,dependencies:[{alias,blob},...]} with exactly
three distinct SessionStore rows. The Runtime owns validation/provenance of these
rows; caller strings/booleans do not authorize migration. The orchestrator verifies
same active owner/binding/session and current route, then passes the trusted proof.

History compares all three ciphertexts in the SAME readwrite transaction as the
contact profile and migration marker. Concurrent rekey/missing rows abort. Duplicate
migration also crosses the barrier. Proof snapshots are not copied into the
migration marker; previous encrypted contact remains preserved. History, legacy
keys, identity and message sequence remain unchanged.

Runtime.contactMigrationProof is an independently owned N4 dependency, not present
in this slice. Until supplied the UI fails PUBLIC_MIGRATION_PROOF_UPGRADE_REQUIRED;
there is no fallback to a weaker proof. Worker ownership and Account storage are
separate databases; live root/owner guards are not advertised as a cross-DB atomic
transaction. Real same-identity legacy migration/rekey browser test remains open.

UNIT: authenticated-history fixture now checks missing proof refusal, three-row
barrier, unchanged retained messages/secrets, and persistent interleaved rekey
refusal with unchanged contact ciphertext. Runtime proof crypto remains its own
required suite. No production or browser changes.
