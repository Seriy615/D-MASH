# EMS call startup — dedicated S-TURN deployment

Before this change, the running dmash-node process had no S-TURN URLs, secret or
enabled capability, and nginx had no `/signal/v1` proxy. The existing coturn on
3478 uses a static long-term account; do not overwrite its authentication mode.

`tools/configure_ems_sturn.py` creates a separate `dmash-sturn` service on
UDP/TCP 3479 with relay UDP ports 55000–55999. It uses a generated 256-bit secret
encoded as a printable 64-character hex string, matching temporary TURN REST
credentials from the Node. Secret/config/environment files stay on EMS; they
are not in Git or printed. Backend secret bounds now accept 32–128 bytes so
printable secrets retain their entropy while existing 32-byte deployments remain
compatible. The algorithm remains standard TURN REST HMAC-SHA1.

The separation is required because coturn's static-user and shared-secret modes
validate credentials differently; see the [official coturn configuration](https://github.com/coturn/coturn/blob/master/examples/etc/turnserver.conf).

Node environment: `DMASH_CAN_S_TURN=1`, signaling
`wss://stage-api-ems.d-mash.ru/signal/v1`, TURN UDP/TCP URLs on port 3479,
and host-private `DMASH_TURN_SHARED_SECRET_B64`. The script adds the existing
staging TLS proxy snippet for `/signal/v1` -> `127.0.0.1:18080`, validates nginx,
and restarts the Node. It backs up changed files under `/root/dmash-sturn-backups`
and restores previous configuration/service state if an operation fails. It
preserves existing Node identities/databases and the global coturn service.

Call startup errors must appear in UI, including unavailable service and denied
microphone. Manual cancellation must not create a stale failure popup. A media
track event does not prove an established connection; connection state starts the
call timer. Production sessions use relay-only ICE; explicit local fixtures may
disable remote ICE servers and use local candidates.

Required live evidence: actual Account-encrypted invitation via EMS, public WSS
session/ticket admission at production difficulty, both selected candidates are
relay, inbound audio RTP on both peers, real UI acceptance and hangup cleanup.
`DMASH_TEST_CALL=1 tools/test_pwa_two_accounts.cjs` exercises this path. A local
RTC fixture or TCP health probe alone is insufficient to claim calls working.

Scope remains PARTIAL N7: video switching/files, renewal and broad fault/mobile
matrix are still required. Invitation E2EE and DTLS-SRTP do not make SDP/ICE
opaque to the signaling server in the current adapter; authenticated encrypted
signaling/fingerprint binding remains a security/privacy requirement. Relay also
observes network endpoints. Do not claim global endpoint anonymity or completed
unified v4 Account call integration from v3 migration call acceptance.
