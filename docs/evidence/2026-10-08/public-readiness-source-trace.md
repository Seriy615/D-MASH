# PUBLIC readiness diagnosis — source trace, not browser acceptance

Runtime frozen at candidate .26. No new browser or miner was launched for this trace.

| Stage | Source behavior | Safe observation |
|---|---|---|
| Local intent | `recordOutgoing` persists request_pending + initial envelope; UI now returns saved result before dispatch finishes | Status, attempt count, nextRetryAt delta only; no IDs/envelope |
| Dispatch serialization | `ContactFlowV3.exclusive` serializes initial send and resume | Stage timestamps; distinguish waiting in a prior operation from a new attempt |
| DNSS binding | `DeviceAuthorityV3.bind` caches one promise; REGISTER_DNSS may reject DNSS_NOT_REGISTERED, then work(DNSS), then re-register | Actual AUTH_OK difficulty; RPC operation/error code; proof kind/difficulty/progress |
| Local reply activation | `Core.sendInitial` activates local reply on every capable connection; waits Promise.allSettled | Node count, per-result state/error category |
| Route proof | REGISTER_ROUTE may reject INVALID_RESOURCE_POW, then work(ENTRY_GRANT), then retry | Separate RPC/proof stages; never log resource, grant, signature, DNSS or route |
| Probe | Successful route registration followed by START_PROBE | Result state; activation must become ACTIVATED |
| Remote readiness | `ensurePublicRouteV3` only calls routeStatus; its timeout argument is unused. It does not wait or discover the target | ROUTE_STATUS_RESULT state and boolean ready |
| Submission | `submitDeviceEnvelopeV3` checks ROUTE_STATUS again, then SUBMIT with hop label/ciphertext | Operation/result state only; no label/ciphertext |
| Retry | Failure becomes false; nextRetryAt was scheduled before attempt: 5,10,20,40,80,160,300 seconds, capped. Core sync runs every 7 seconds | Attempts, next retry delta, last successful submission marker |
| Mailbox | Existing PULL/drain path feeds CONN_REQUEST ingestion | PULL operation/response type and UI pending appearance; no packet contents |

Important error masking: `_dispatchInitial` catches every sendInitial rejection and returns false without retaining error details. `resume` continues after that false, so its failed count does not describe these failures. Core's registration aggregation replaces per-connection reasons with `Contact reply registration unavailable`. The visible waiting card cannot currently tell proof work from registration rejection or absent remote route. The v50 comment claiming errors are recorded is inaccurate; frozen runtime was not modified to correct the comment.

Potential duplicate work (not yet demonstrated for the failed exact run): postAuthReady probes active public routes after DNSS; UI route creation and contact dispatch also activate routes. Only DNSS bind has singleflight. The v3 route activation method has no per-route in-flight deduplication, so concurrent missing-proof rejections can start multiple ENTRY_GRANT workers. Worker presence alone is insufficient to identify which stage blocked contact delivery.

`tools/qa_public_readiness.cjs` defines 14 observational CDP conditional logpoints. It does not launch Chromium. Source anchors must be unique and are checked before installation. Events include only whitelisted stages, protocol types/error categories, booleans, counts, policy difficulty, attempts and elapsed time. Worker progress is sampled per 1,048,576 attempts. No application function is replaced; no storage/identity mutation or protocol operation is performed by the observer. Debugger observation may change timing, so this is diagnosis, not an uninstrumented latency benchmark.

For the authorized isolated run: preserve the same two synthetic profiles and keep a live browser/CDP handle after the original deadline. Record deadline FAIL at 180 seconds if it occurs, then continue diagnosis without converting that result to PASS. Inspect stages/progress/retry timing on those profiles; do not restart accounts, force readiness, invoke Core sends or increase the acceptance timeout. Correlate loaded response hashes with exact commit and capture real UI controls throughout.
