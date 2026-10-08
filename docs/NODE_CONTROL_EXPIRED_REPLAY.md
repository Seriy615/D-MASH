# Expired CONTROL acknowledgement reconciliation

The trusted AEAD consumer may call `dispatch.persistExpiredReplay(value)` instead
of normal persist only for an expired authenticated replay. This method verifies
the strict payload schema at its original expiry boundary, then requires an exact
existing encrypted APPLIED record. Missing, PENDING, changed type/payload/expiry,
peer or binding is refused; it cannot insert work, extend TTL or reapply an action.
A confirmed successor session still requires the private Runtime proof and same-tx
three-row SessionStore CAS from the existing dispatcher successor contract.

Normal persist continues to reject expired controls. If bounded journal pruning
already removed the APPLIED marker, reconciliation fails closed; this API does not
invent a receipt or recover absent history. Sender expiry policy is separate.

UNIT: exact APPLIED duplicate accepted without action, normal expired refusal,
missing/PENDING/changed-type/changed-payload refusal, confirmed successor through
trusted verifier dependency. No new crypto authority is introduced by this method;
Runtime must authenticate before invoking it. Browser and N4 AEAD integration are
separate mandatory gates.
