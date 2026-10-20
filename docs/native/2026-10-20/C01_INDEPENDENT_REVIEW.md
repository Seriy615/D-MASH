# Independent C01 native actor review

Read-only review of `f3a3dee0a50d79601c905b366d2a61bf816b08b6`, followed by
review of corrective commit `8bc67f0`. The three findings below are corrected
and the bounded integration is accepted within the limits stated here. This is a headless Linux integration
checkpoint, not acceptance of the complete native products or an Account SDK.

The independent reviewer executed immutable f3 and corrective platform-adapter/
endpoint-scheduler suites on Node 24; both passed. Corrective native CTest
**6/6 PASS** includes crypto, nonce, bundle, relationship, actor lifecycle and
Inbox fault tests. The actual CLI descriptor-boundary fixture also passed.
Exact source/binary/log hashes are in [C01_INDEPENDENT_REVIEW.json](C01_INDEPENDENT_REVIEW.json).
No new network peer was executed by this reviewer; root/author Python-peer
gates remain separate evidence classes. Author evidence is in
[actor-linux-20261020.json](../../../native/tests/evidence/actor-linux-20261020.json).

## Findings and corrective acceptance

| Finding | f3 behavior | Corrective status |
| --- | --- | --- |
| C01-LIFETIME-01 | close resets the engine but initialize/connectPeer/queryService/snapshot dereference it before checking live state. A post-close SDK call or late queued ready callback can access null. | Corrected in 8bc: all public entry guards and generation-fenced reports. Independently rerun native actor lifecycle test PASS. |
| C01-INITIALIZE-01 | A second native initialize copies a new bundle before the JS owner rejects it. Rejection is before the JS cleanup finally and can stop the first owner. | Corrected in 8bc: native one-shot guard precedes copying; independently rerun lifecycle duplicate-initialize test PASS. |
| C01-INPUT-01 | QFileInfo validates the input pathname before QFile opens it; path replacement can invalidate the checked file properties. This is not a demonstrated privilege escalation against a same-UID attacker. | Corrected in 8bc: descriptor-bound NOFOLLOW/CLOEXEC/NONBLOCK plus fstat type/uid/mode/limit. Independent CLI regular/FIFO/symlink/mode/cap/JSON rejection fixture PASS. |

Corrective Inbox glue was checked against
[InboxSqlStore](../../../native/persistence/README.md): separate row methods,
revision/null shape, bounded IV/ciphertext, same profile database and JS guard
before synchronous CAS are consistent. This observation does not replace the
author/root's exact-commit positive network/local-delivery acceptance after integration.
Author [corrective evidence](../../../native/tests/evidence/actor-inbox-linux-20261020.json)
records real default-work22 Node→Python SERVICE_QUERY and same-profile reopen, with
an encrypted Inbox owner row. That is not an end-to-end route→Inbox→Account flow.

## Reviewed security boundaries

- Existing compiled protocol modules remain the Node wire implementation;
  activation prefix/difficulty/proof checks are not replaced. Optional native
  nonce hashing uses the same big-endian u64 bytes, checked against the original
  independent JS SHA at boundary nonces before use.
- Fixed resource imports and a compiled module allowlist expose no IPC operation
  to evaluate external code, import arbitrary files, execute SQL or fetch Root/
  Account material. Compiled code and native dispatcher remain trusted code.
- Native opaque key handles enforce algorithm/usages and byte limits; AEAD
  failure rejects. JS metadata cannot forge a native key class. This is the
  subset required by the Node modules, not full WebCrypto conformance.
- TLS verification is retained; plaintext ws is limited to explicit loopback
  fixtures. Peer identity still passes existing handshake/admission/registration.
  Native public connect entry uses the broker's pinned endpoint list. The socket
  primitive separately validates URLs, not an independent per-endpoint native ACL.
- Frames, send buffering, clone input, key handles, timers, endpoint attempts and
  worker counts have finite limits. At most two compute threads retain their
  global slots until actual exit; VM cancellation is not implemented by freeing
  live JS from another thread. Retry scheduling deduplicates Node identity and
  serializes alternate URLs for it.
- Private Unix profile/SQLite sidecar permissions and a profile owner lock are
  present; Windows protected-storage ACL currently fails closed. These checks do
  not sandbox hostile same-user code. Raw parsed JSON/QString copies are not
  guaranteed erased by wiping the owned byte array.

## Limits that remain open

The 128 MiB VM limit is **per QuickJS engine**, not a total process memory bound.
Native key buffers, up to two compute engines and Qt socket queues add memory.
Device-specific CPU/RAM/disk/battery limits and slow-peer/concurrency behavior
still require measurement and acceptance.

The checkpoint proves no complete IPC broker/service/UI boundary, private
password peer support, arbitrary-peer file custody, full route/transit recovery,
Account-free durable jobs, default multi-peer provisioning or Android/Windows
runtime. Private password admission is unsupported and fails closed rather than
silently downgrading. It does not establish uninterrupted operation under Doze,
power-loss persistence, endpoint anonymity, PFS/PCS or PQ conformance.

Scoped C01/C02 source/port acceptance has no remaining blocker from this review.
The broader application/recovery/IPC/platform gates above remain open.
