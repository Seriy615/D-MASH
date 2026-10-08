# Bounded transport receipt proof retention

Separate follow-up to candidate366860c. Red0a2ebaf proves that unrelated fresh
CONTROL previously pruned expired APPLIED, losing the proof needed to repeat
an authenticated transport ACK. No semantic action was safe to recreate.

Receiver now retains exact APPLIED through signed `payload.expiresAt + 86400`
seconds. At `now >= deadline`, expired replay is rejected even if the row still
exists; unrelated future work may prune it. Replay never moves the deadline.
The encrypted journal remains bounded to 64 records and existing byte bounds;
fresh intake rejects at capacity rather than evicting retained receipt proof.
Expired PENDING never becomes APPLIED. Accepted file tasks keep their independent
one-hour deadline and immutable manifest; neither retention authorizes new bytes.
Semantic COMMIT_ACK remains a separate CONTROL operation, not transport delivery.

N4 sender owner must stop automatic CONTROL retries at the same fixed boundary,
retain encrypted intent/ledger and expose EXPIRED_UNCONFIRMED (not undelivered),
while permitting a later genuine authenticated ACK. Sender follow-up is separate.
Tests: real WebCrypto with IDB emulator, reopen, unrelated fresh control,
capacity refusal without proof eviction, exact deadline refusal and reclamation.
Browser proof remains required; no production change.
