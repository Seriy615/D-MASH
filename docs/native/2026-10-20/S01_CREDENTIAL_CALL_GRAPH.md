# S01 effective credential callers

Current integrated checkpoint `3541458`; historical entry-gate findings were resolved by the foundation and `d8eff7d` wiring. [Design](../../audits/2026-10-20/verification/MASTER_SECRET_FIX_DESIGN.md) and [verification](S01_FOUNDATION.md) define scope. Native S02 remains open.

| Effective source | Current delegation and boundary |
|---|---|
| `js/ui_logic.js` | Calculator setup/change/unlock/wipe/repair uses shared service; generation abort owns pending KDF; AC cancels. Committed cleanup failure explicitly retains new-master authority. |
| `js/core_engine.js` | Root adoption/startup follows current prepared authentication; separate wipe change requires authenticated master. Legacy Account Argon2d type0 and128-byte slicing remain explicit. Recovery refuses missing-Root identity replacement. |
| `js/device_root.js` | Existing-only prepared handles, v1 reader/v2 writer, same-root reopen proof, epoch fencing, atomic IDB CAS and affected-slot metadata concurrency. OS-auth repair proof cannot be replaced by unlocked RAM or legacy hash. |
| `js/local_credentials.js` | Canonical pending/ready credential state, expensive wipe verifier, commit/cleanup status, shared lock, lifecycle invalidation, durable wipe intent and explicit resume. |
| `js/local_credentials_worker.js` | Cancellable actual bundled Argon2 job; separate wrap KDF profile, no global enum alias. |
| `js/local_credentials_bootstrap.js` | Pinned loader, fail-closed inventory, actual shutdown/ancillary deletion, cooperative cross-context lifecycle and old-tab SW upgrade exclusion. |
| `js/acceptance_v50.js` | Delegates actual owning Root biometric operations; no fast-hash repair authority and no forced credential-change reload. |
| `js/acceptance_v51.js` | Effective lazy loader includes service; explicit full reset delegates durable coordinator. Biometric removal checks active Root and expected metadata transaction. |
| `js/acceptance_v54.js` | Internal1020 emergency delegates authenticated shared service; instruction text uses valid tokens and effective duration. |
| `js/acceptance_v55.js` | Preserves public0010 translation to internal1020; wrong suffix has zero deletion authority. |
| `js/runtime_fixes.js` | Readiness wrapper retains owning Root biometric bodies rather than installing stale weak overrides. |
| `js/acceptance_fixes.js` | BIO introduction/hold hint uses effective duration and valid digits/operators; BIO Cancel guards in ui_logic remain intact. |
| `sw.js`, release catalog | Release `.39` pins service/bootstrap/worker; SW query blocks legacy migration while other scope windows remain. |

Unloaded `stability_fixes.js` and `acceptance_v53.js` retain historical paths; they are not release credential authorities. Source guards prevent their accidental promotion as replacements. `sys_m/sys_w` remain only legacy migration/cleanup inputs in effective service code; no loaded caller uses a fast hash as authentication. This does not claim safety against arbitrary old same-origin JavaScript that ignores new coordination.

The integration-contract and existing conservation tests check this chain. All158JS suites on immutable354 pass; real SW upgrade and disposable wipe evidence is separate from UNIT and from physical/native acceptance.
