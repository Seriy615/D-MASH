# CONTROL dispatcher successor barrier

Private constructor dependency `verifySuccessor({peer,operationId,from,to})`
receives the old encrypted dispatcher context and new AEAD-authenticated context.
It must use Runtime.createPendingSuccessorProof/verifyPendingSuccessor and return
{valid:true,dependencies:[three exact SessionStore {alias,blob} rows]}.

Only sessionId may change. Logical operation, type, payload, binding and binding
generation must be identical. Dispatcher CAS-checks its old encrypted journal and
all three supplied SessionStore rows in one transaction, preserves PENDING/APPLIED,
and returns duplicate:true. It never reapplies an APPLIED semantic media action.
No verifier or mismatched dependencies fail closed. Authenticated CONTROL ACK can
be emitted only after this callback succeeds; COMMIT_ACK stays a separate action.

Meaningful UNIT: missing verifier refusal, changed payload refusal, interleaved
SessionStore change abort/retry, APPLIED retained after successful successor and
idempotent current-session replay. Real Runtime crypto/Worker/browser integration
is required separately; trusted verifier test double does not prove authentication.
