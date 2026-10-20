# PRIVATE ACTIVE-before-detach recovery

Separate candidate after b386742. Regression first failed because restart saw
ACTIVE and skipped an unsuspended bootstrap configuration. Final receipt
continuation then had no durable bounded window despite preserved keys/rows.

The encrypted final ownership row now records `activatedAt` in the same CAS as
NODE_PREPARED→ACTIVE. Bootstrap restore reconciles ACTIVE into suspended config
without creating a provisional route. Its continuation deadline is at most
`activatedAt+300` and the original signed offer expiry. Reopening an already
suspended config does not reset counters/deadline. Old ACTIVE rows without this
new timestamp are preserved and suspended with deadline zero, never assigned a
new 300-second window. RETIRED/changed ownership fails closed.

Targeted regression RED→GREEN plus existing continuation and owner persistence
UNIT pass. These use storage/crypto boundary doubles; real Worker crash/reload
PRIVATE UI is still a required browser gate. No identities/keys are regenerated.
