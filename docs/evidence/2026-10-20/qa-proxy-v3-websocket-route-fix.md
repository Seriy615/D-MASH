# EMS DMP-C v3 WebSocket alias repair

Date: 20 October 2026 UTC  
PWA release: `transport-v3-node-preparation-20261020.38`  
Host: `proxy.d-mash.ru`

## Reproduction and cause

The deployed client attempted `wss://proxy.d-mash.ru/dmash-client/v3`. Before
repair, the exact HTTPS virtual host returned nginx `404` for this path. The
backend endpoint itself was healthy: a direct handshake to
`127.0.0.1:18080/dmp-c/v3` returned `101 Switching Protocols` and DMP-C v3
`WELCOME`. The EMS nginx file already proxied `/dmp-c/v3` and the v1 alias, but
had no exact `/dmash-client/v3` location.

## Change and verification

Added the missing exact alias in
`/etc/nginx/conf.d/dmash-proxy-api.conf`, forwarding to the existing backend
`/dmp-c/v3`. The change preserved every other vhost and location. Before editing,
the file was saved mode `0600` under
`/root/dmash-proxy-route-fix-20261020/dmash-proxy-api.conf`; the backup directory
is mode `0700`. `nginx -t` passed and nginx reloaded. The configured backup is
for explicit rollback; it was not copied to Git.

After repair, the deployed browser ran the actual `DeviceClientV3` from release
`.38` with the active `.38` service worker and a fresh synthetic DeviceRoot. It
completed the pinned DMP-C handshake on the same `wss://proxy.d-mash.ru/dmash-client/v3`
URL, reached `connected`, and completed an encrypted `STATUS` request. The
returned Node identity matched the configured pin, the response was `STATUS`,
S-TURN capability was true, and page errors were zero. Browser transport frames
were observed as `WELCOME → CHALLENGE → SECURE` and `HELLO → AUTH → SECURE`; no
payloads, keys, or synthetic identity values are included here.

The source generator and regression test now include this fifth exact endpoint
alias: `python3 tools/test_ems_domain_migration.py` — 5 tests PASS. The running
PWA and backend source did not change for this repair; only nginx routing and
source tooling/tests changed.
