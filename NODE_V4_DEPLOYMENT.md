# Native Node v4 deployment

The application mounts `/mesh/v4`. It rejects WebSocket upgrade while
`DMASH_NODE_V4_ENABLED` is unset/false. Existing v3 Account traffic remains a
migration path; enabling this listener does not migrate the browser application.

## EMS configuration

Source revision when enabled: `7f5b74f379a5521bfc444780c41278fca49b34a3`.
Existing Node signing identity is reused; no Account or Node identity reset.

`/etc/systemd/system/dmash-node.service.d/40-node-v4.conf`:

```ini
[Service]
StateDirectory=dmash-node-v4
StateDirectoryMode=0700
Environment=DMASH_NODE_V4_ENABLED=1
Environment=DMASH_NODE_V4_STATE_DIR=/var/lib/dmash-node-v4
```

`StateDirectory` is necessary under the existing service filesystem protection.
Setting only a writable-looking path in the environment failed with read-only
filesystem; the first enable attempt restored the previous configuration.
The successful configuration backup is
`/root/dmash-v4-enable-backups/20260925T144551Z` on EMS.

Added to the `stage-api-ems.d-mash.ru` TLS server in the existing nginx site:

```nginx
location = /mesh/v4 {
    proxy_pass http://127.0.0.1:18080/mesh/v4;
    include /etc/nginx/snippets/d-mash-ems-staging-proxy.conf;
    proxy_read_timeout 330s;
}
```

The existing snippet forwards Upgrade/Connection headers and preserves TLS at
nginx. The application bounds frames to 2 MiB and receive queue to 16; transport
and routing apply their own tighter logical quotas. Listener quotas are aggregate,
not an Internet-scale DoS mitigation claim. No raw password is in this configuration.
Private Node policy additionally requires `DMASH_NODE_V4_CREDENTIAL_FILE` as
specified in TRANSPORT_V4.md; missing credentials fail startup, never OPEN fallback.

## Verification and rollback

Run the exact revision verifier, check service health, then run
`tools/test_worker_v4_remote.cjs` with `DMASH_REMOTE_V4_URL` and an independently
obtained `DMASH_REMOTE_NODE_ID`. The test uses a fresh browser profile and no Account
login, performs real mutual v4 authorization twice with the same persisted browser
Node identity, and checks full DeviceRoot lock. It does not prove Account migration,
mailbox delivery, endpoint privacy or the entire N8 matrix.

For rollback, remove only the dedicated v4 systemd drop-in and restore the saved
nginx configuration, validate with `nginx -t`, then reload systemd and restart the
Node/reload nginx. Preserve `/var/lib/dmash-node-v4` and the original Node identity;
never delete persistent state to make startup pass. The directory must remain 0700,
material files 0600. The current encrypted recovery bundle does not include this
new relationship store, so a complete v4 backup/restore path remains required.


Verified on the public endpoint: real Chrome Worker reconnect/root lock, plus two
native Nodes exchanging encrypted discovery and a recipient payload through EMS
as their only neighbor. `tools/test_node_v4_remote.py` exercises the latter.
The native test exposed an initiator clock-window mismatch with JS; both now use
the same bounded tolerance, without extending the responder AUTH deadline.
These tests do not exercise Account migration or mailbox recovery.
