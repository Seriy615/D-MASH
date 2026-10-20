# dmash-local-v1 — implementation contract (C02 in progress)

This is an OS-local protocol, not a mesh wire/ACK extension. The common actor reuses Node v4 route discovery, 500ms batching, recipient-box-v2 and NodeInbox. Account plaintext/E2EE, Root/PIN/Account credentials and legacy KEM stay outside the daemon. No arbitrary SQL, evaluation, file access or material-alias method exists. Actual implementation/tests are recorded separately; this contract alone is not acceptance.

## Authentication and framing

The service owns its private profile and process lock. Linux/Android use a filesystem local socket inside the private directory, `QLocalServer::UserAccessOption`, and kernel peer UID checks; abstract/world-access sockets are forbidden. Windows requires current-user ACL and peer-token validation before enabling the host. Same-UID compromise is outside this boundary. Qt [socket access options](https://doc.qt.io/qt-6.12/qlocalserver.html#SocketOption-enum) supplement capability authentication.

A broker starts the daemon with an inherited authenticated duplex OS-local bootstrap channel; its descriptor number may be an argument, capabilities never are. Startup capabilities are freshly minted by the daemon and returned only through that channel. A later implementation may wrap a transport-only background grant under OS protection; it must not persist full Root. The current private scoped-bundle file CLI is a proof harness, not the final credential broker.

Each frame is a four-byte unsigned big-endian length plus one UTF8 JSON object. The receiver checks length before buffer allocation/materialization or JSON parsing, caps its Qt receive/output queues, and rejects invalid UTF8. Pre-auth/control frames are at most65536 bytes; authenticated data frames at most524288 bytes. Methods have smaller semantic limits. Inbox responses are cursor paged by bytes rather than truncating an individual record. Existing encrypted Inbox envelopes up to65536 bytes remain supported. Existing prepared mesh boxes remain72..16384 raw bytes /21848 canonical-base64 characters; this API does not silently fragment them or introduce a new wire packet.

First request authenticates a fresh random256-bit capability, daemon owner generation, role and permitted method scopes. Thereafter the connection owns that context; request parameters cannot select another caller scope. Tokens expire, are compared in constant time, are absent from URLs/argv/logs, and are invalid after service restart/revocation. A bounded `MintCapability` request over the inherited broker-only FD renews only a startup-configured principal/role, invalidates its old contexts and returns the fresh token privately; accepted jobs survive that context replacement. Connection counts, pending requests, frame/byte rates and output bytes are bounded. Pre-auth failures close the connection without revealing profile/account state.

Request: `{v:1,id,method,params}`. Responses echo only `v,id,ok,result` or a bounded fixed error code. IDs are bounded ASCII strings; duplicate outstanding IDs are rejected. The bootstrap/admin capability grants no Inbox plaintext/ciphertext read right. An owner proves its Account public identity through the EXISTING local ownership challenge/signature API; only the public proof enters the daemon. Its durable ownerSlot, not an ephemeral capability token, scopes jobs/destinations/Inbox. Disconnect/logout retires session tokens, not accepted jobs or ACTIVE route bindings.

## Broker control seam

Exact versioned operations, carried only by a broker/admin scope:

- `InstallTransportSession{request_id,generation,effective_policy_revision,transport_bundle}` uses the existing strict TransportBundle fields. No Root/PIN/Account fields or arbitrary derivation aliases.
- `RevokeTransportSession{generation,reason}` fences writes, closes keys/sockets and preserves encrypted queues.
- `SetTransportPolicy{generation,revision,policy}` requires an increasing durable revision. Adapter checks current owner/grant/policy immediately before each write. Already queued forbidden retransmissions cannot drain after commit.

UI close and Account logout do not revoke Node transport. Explicit full Root lock revokes it. Background OS-wrapped restart authority is a separate explicit policy. Direct/ICE remains a separate carrier implementation; WSS does not imply NAT traversal. A policy cannot authorize an unsupported carrier.

## Owner operations

`owner.challenge/register/prepare/activate/query/retire` are bounded adapters for existing `NodeLocalOwnershipV4`, with the same signed tuple, route generation and encrypted binding transitions. Default native restoration uses managed ACTIVE bindings only; legacy Account/installation keys are never imported by convenience fallback. A capability cannot install a binding for another owner or replace a route generation silently.

`installDestination(certificate,replyRouteId)` verifies the existing Node v4 certificate, live ACTIVE local reply binding and owner tuple, then durably stores a caller-scoped opaque local handle. That handle is not a wire route ID. The destination contains no Account secret. Its expiration is bounded by certificate/reply authority; jobs cannot outlive the accepted grant. Path/peer/session changes rediscover this same certificate without Account callbacks. A changed certificate/key generation requires an explicit authorized grant update; it is not invented from a guessed route ID.

`submit(destinationHandle,callerOperationId,preparedRecipientBox,expiresAt)` keeps the existing recipient-box-v2 profile and validates canonical encoding/curve/certificate binding before acceptance. It commits an encrypted own copy of bytes, digest, owner/destination-scoped operation identity, expiry, generation, retention horizon and job before replying ACCEPTED. Identical retries return the same handle; changed bytes/parameters conflict. Disk/quota failure rejects before acceptance. The application retains its transport intent until ACCEPTED; its E2EE receipts remain separate.

`query/cancel/events` are owner-scoped. `inbox.list` returns only that authenticated owner's opaque Account ciphertext, with cursor/byte limits. `inbox.commitConsumption(recordHandle,applicationCommitToken)` is invoked only after the application durably commits its operation. A persistent local consumption intent makes repeated calls idempotent across the separate Inbox update; it is not a cross-process plaintext transaction and emits no wire receipt.

## Durable state and scheduling

SQLite WAL/FULL binds encrypted job/destination/consumption records to this Node/storage key and version. Owner acquisition transactionally increments a durable owner generation. Every mutation and adapter write checks that generation; a stale owner cannot advance jobs or send. Missing/wrong binding with existing rows fails closed. A backup does not authorize a second writer; external backup anti-rollback/OS authority is an explicit recovery gate.

Jobs transition through `ACCEPTED`, `WAITING_BOOTSTRAP`, `WAITING_PATH`, `IN_FLIGHT`, `TRANSPORT_SENT`, `BLOCKED_POLICY`, `CANCELLED`, `EXPIRED`, `FAILED_RETRY_BUDGET`. Startup resumes interrupted nonterminal attempts using the same bytes and recipient packet ID. One scheduler deadline, bounded active jobs/attempts, per-owner/destination/global quotas and fair selection prevent an idle poll train or one slow route monopolizing work. Missing bootstrap/path/expired grants produce an honest waiting/expiry state, never an Account callback. Missing-bootstrap work waits until its expiry or a peer-connected event, without an offline poll interval. Terminal retention and expired destination cleanup participate in the same scheduler deadline. Retry re-runs existing discovery and preserves its normal authority checks.

The packet enters the SAME existing 500ms batching pipeline used for transit. Trusted local sidecar callbacks may observe queue/send completion; they never enter wire JSON. A successful awaited batch send records only TRANSPORT_SENT. Original bytes/dedupe remain until the declared bounded retention horizon. The first ledger profile allows at most20 actual attempts,64 durable owner scopes,4096 jobs/32MiB of raw opaque job bytes globally,512 jobs/8MiB per owner,128 jobs/2MiB per destination (encrypted/base64/index overhead is additionally bounded by the record count), seven-day maximum grant/job lifetime and24-hour post-expiry retention. Waiting without bootstrap does not consume attempts. Lower quotas reject new work and preserve accepted rows. No DELIVERED, READ or CUSTODY_CONFIRMED is fabricated. A crash after write before recording completion may resend the same box; existing recipient packet-id/route dedupe collapses it. A crash at the recipient after sender OS completion but before Inbox commit remains an ACK-free baseline loss window. This contract does not silently add durable-custody-v1.

## Required executable gates

- Crash before acceptance commit: no job; after commit before reply: identical retry gives one retained job/handle; different bytes conflict.
- Unauthorized/stale/wrong-role capability and wrong owner: no state disclosure/mutation; oversized frames rejected before parse/materialization.
- UI disconnect/kill after acceptance: actual Node discovery/send/recipient durable Inbox proceeds without Account keys/callbacks; reconnect queries the same job.
- Sender restart with authorized scoped boot grant: same job/identity/bytes; failed path/reconnect retries; no storage reset.
- Crash before/after send/Inbox persist/consumption intent: dedupe/retention semantics and known loss window are observed honestly.
- Policy/revocation during queued retry: no forbidden adapter writes after commit; permitted durable bytes survive.
- Android service and Windows/Linux host lifecycle/runtime gates are separate from C++ compilation/JNI linking.
