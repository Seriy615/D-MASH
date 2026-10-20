# Independent review of S01 caller integration

Reviewed exact commit `d8eff7d064b63423b53898cad902ee95c13b5a25`, using an
immutable git archive. This is a read-only security review plus **11 independent
focused suite executions**, all passing on Node 24.19.0. Exact 25 changed-file
hashes, suite names and log hash are in
[S01_INTEGRATION_REVIEW.json](S01_INTEGRATION_REVIEW.json). The earlier
[foundation review](S01_FOUNDATION_REVIEW.md) remains a separate checkpoint.

No new blocking credential publication, CAS or cancellation issue was found in
the reviewed effective callgraph. This is scoped acceptance of the integration,
not a claim that S01/S02, all controls or the complete application are finished.

| Boundary | Reviewed behavior and evidence |
| --- | --- |
| Calculator/Core | Effective eval delegates setup, verification, unlock and changes to the service. No standalone sys_m/sys_w authorization remains in the loaded UI/Core/runtime/v50/v51/v54/v55 paths. Wrong unwrap does not reset identity. Core adopts only the exact currently published Root state and checks UI generation after await. |
| Setup/recovery | Empty-installation inventory and durable pending setup preserve an existing Root. Recovery requires an explicit legacy secret or fresh bound OS proof; full deletion uses a separate confirm and typed phrase. Neither unwrap failure nor missing fast verifier authorizes replacement. |
| Biometric owner | runtime_fixes no longer assigns plaintext Root state. v50 delegates to DeviceRoot prepared APIs. Trusted get begins before the first IDB await; epoch/store checks reject late assertions. Binding is checked against current persisted wraps both at publication and in the credential CAS transaction, so removal invalidates an outstanding repair proof. |
| Credential commit | CAS merges the versioned wrap and credential metadata atomically. Independent reopen verification precedes commit. Cleanup failures carry committed/revision information; master-changing calls mark useNewMaster and the UI tells the user which credential now applies. Cancellation before commit and cancellation after a durable commit have different receipts. |
| Lock/lifecycle | Service cancellation aborts active workers/transactions; Root lock invalidates prepared handles and owned secret arrays. Bootstrap's Root observer terminates Core Account state, guarded against recursive lock. Post-await publication validates persisted proof and current lifecycle. |
| Wipe | v51 recovery and v54 emergency use one durable coordinator. Authorization happens before irreversible intent; cancellation before intent does not delete. After intent the coordinator owns completion/retry independently of the initiating UI cancellation. Pending markers prevent fresh setup, and Root deletion follows other databases/ancillary cleanup. |
| Loader | ensureCredentials deduplicates exact versioned scripts and initializes service/worker before calculator operations; v51 full loading reuses the same loader. Dedicated worker uses an explicit legacy/type2 profile and versioned vendor URL. Account KDF remains explicit deployed type0 with unchanged slices. No global enum replacement changes Account identity. |
| SW upgrade | Release .39 caches the new modules and checks controller release plus other in-scope window count before migration. A mismatched/older controller fails closed. This is a cooperative client snapshot, not an atomic inter-version lock or sandbox against arbitrary old same-origin JS. A newly opened tab after the check is outside that guarantee. |

One concrete remaining UI defect was found: the final v54 wrapper overwrote the
token-specific biometric setup instructions with “any button”. The author fixed
the source text in `3541458`; this review inspected that delta. The root's real
[UI instruction retest](root-biometric-instruction-retest.json) passed separately
on the retained profile; it is not this reviewer's browser execution.

The independent suites exercise actual modules with synthetic adapters; several
KDF/race fixtures intentionally use deterministic lightweight KDFs. Actual
bundled-WASM profile checks were established in the foundation review. Those
fixtures do not establish OS authenticator hardware behavior, SW-enabled offline
upgrade, arbitrary process compromise resistance or power-loss durability.

Root-owned [retained migration](root-s01-retained-migration.json) separately
records actual Chromium calculator unlock, worker-backed migration, original
Account/Saved history, old-master rejection and new-master reload on one
persistent synthetic profile. [Worker cancellation](root-s01-worker-cancel.json)
records actual AC cancellation with unchanged encrypted record and subsequent
same-identity retry. Both block Service Workers and external networking. This
review does not relabel them as independent browser executions or as successful
SW-enabled migration, real Node transit or native platform acceptance.
