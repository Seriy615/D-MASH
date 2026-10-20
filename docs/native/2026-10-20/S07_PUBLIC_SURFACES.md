# S07 legacy PHP public surfaces — 20 October 2026

Status: unsupported PHP relay/webhook retired in source; real isolated PHP
regressions pass. This is not production exposure/deployment confirmation or
closure of all S07 operational work. Signed Node/Origin paths are unchanged.

## Inventory and supported callers

| Surface | Actual authority and callers before this change | Current disposition |
| --- | --- | --- |
| `api/pidorskiy_api.php` POST | Public `X-DMASH-AGENT: V1Silent-Node` string. set_tg/check_batch have no owner proof; PUSH verifies only blob against supplied sender public key, not recipient/flags. Core.sendKyberFinal and legacy Core.sendMessage call it only in explicit legacy transport mode. | Unconditional 410 before application body read, parse, DB, provider or logging. No insecure opt-in/header bypass. |
| Same PHP GET | Signature verifies supplied pub||timestamp, while h is independently caller-controlled. Reads/deletes that h spool and updates online state. Legacy Core.syncNetwork calls it with public key, signature and alias in query. | Same early 410. No mailbox ACK/custody semantics added. Existing DB files are not erased or migrated by the source change. |
| `api/tg_webhook.php` | No webhook secret/signature/owner verification. `/start <hash>` can bind arbitrary hash to supplied chat; no in-repository client/registration caller found. It is an operator-facing legacy template with token/DB placeholders. | Unconditional 410 with no body/DB/Telegram/log access. |
| Authenticated Node | Default NodeManager transportMode is mesh; managed-v4 is a separate Node profile. Ordinary DMP-C gateways/authenticated Node sockets do not import/call PHP. | Unchanged. Node ownership/authentication is not replaced with a static header. |
| Signed Origin | Separate Python notification_service routes use signed/sealed Node requests, signed personal actions/nonces and webhook secrets. NodeManager origin notification adapter uses its configured Origin URL, not PHP. | Unchanged by this patch; [S03](S03_DEPENDENCY_SECURITY.md) provides its prior body bounds/patched dependencies. |

Production source search found exactly three PHP fetch sites, all in
[Core](../../../D-MASH%20PWA/not_messenger/js/core_engine.js): sendKyberFinal,
sendMessage and syncNetwork. Guards use accountTransportMode/NodeManager mode.
[NodeManager](../../../D-MASH%20PWA/not_messenger/js/node_manager.js) defaults to
mesh, and restores legacy only from the explicit `dmash_transport_mode_v1` value.
**The default profile named legacy-migration does not mean transportMode=legacy.**
No tracked caller of PHP set_tg/check_batch or webhook registration was found.
The only other reference is optional syntax lint in tools/m0_smoke.py. External
operator integrations and actual PHP publication are unknown: no server or
third-party service was queried.

## Confirmed isolated baseline defects

The unchanged handlers from source 9446c22 were executed with real PHP 8.3/sodium/
PDO SQLite against synthetic data. Only the placeholder DB_PATH was redirected
to the private fixture. No authentication code was copied/reimplemented.

- A signature produced by the attacker's own Ed25519 key for pub||timestamp,
  alongside a different victim h, returned the victim's one spool row and
  deleted it. This is an ownership/availability failure and unauthorized access
  to stored ciphertext/metadata, not a bypass of Account E2EE decryption.
- Public static agent header plus unsigned set_tg changed a notification binding.
  An unsigned webhook `/start` also changed a binding. Knowing an alias/static
  header is not authority to rebind it.
- A missing DB table caused raw tg_error.log creation; it was retrievable by HTTP
  in this isolated webroot. This demonstrates raw exception/implementation-detail
  exposure. No real bot token/private key leak was tested or asserted.
- A php://input trap confirmed both applications read the request body before
  refusal. The relay also had wildcard CORS, unbounded query/fetch/body operations
  and increased memory/execution limits. PUSH's signature omitted routing metadata;
  legacy spool deletion preceded client durable persistence. These source facts
  are not upgraded into a claim of every exploit's production reachability.

The new endpoint sources contain only constant refusal headers/status/body and
exit. They do not inspect request parameters or trust any agent-header value,
parse input, initialize PDO, embed bot credentials, emit exception details or
write logs. Both return 410 for all methods, remove wildcard CORS and X-Powered-By,
and send no-store/nosniff headers. Old database/history files are untouched.
Reintroducing a relay needs a separately reviewed versioned ownership contract;
an environment flag or shared static secret is not supplied as a bypass.

## Runtime evidence and reproduction

[S07_PHP_RESULTS.json](S07_PHP_RESULTS.json) records exact inputs, sanitized
observations and private-log hashes. Before the fix: 8 test methods, 43 failed
subcases, 0 harness errors. After the fix: 8/8 methods PASS, including 30 method/
agent/origin combinations, malformed 512 KiB/chunked input, genuine wrong-alias
signature, binding attempts, body-read trap, absent PDO/network extensions,
no state changes and no public exception log. Both PHP files also pass php -l.
These tests run the actual scripts through a PHP loopback HTTP server.

```sh
python tools/test_legacy_php_boundary.py \
  --php /owned-prefix/usr/bin/php8.3 \
  --extensions /owned-prefix/usr/lib/php/20230831 \
  --report /private-cache/php-results.json
```

For RED reproduction, archive source 9446c22's two PHP files under another
source-root preserving `D-MASH PWA/api/`, then pass `--source-root PATH`. The test
copies them to a temporary webroot and changes DB_PATH only. Never run the old
handlers against real databases or enable provider egress. Synthetic keys/DB and
temporary server files are private and removed at completion; only bounded
sanitized observations enter Git.

PHP was absent initially. Three official Ubuntu noble-security packages were
downloaded into an owned prefix, without installing/mutating system packages.
The cached 19 October InRelease signature was validated with the Ubuntu archive
keyring, its SHA256/size for Packages verified, and each downloaded artifact
checked against that signed index before extraction. Runtime is PHP 8.3.6 with
Ubuntu revision 8.3.6-0ubuntu0.24.04.12. This is a test tool, not a recommendation
to deploy this base version without ongoing security updates. See
[S07_PHP_PROVENANCE.json](S07_PHP_PROVENANCE.json),
[official Ubuntu package information](https://packages.ubuntu.com/noble-updates/php8.3-cli)
and the [security archive](https://security.ubuntu.com/ubuntu/).

## Explicit limits and remaining integration

External effects were blocked in the controlled fixture: URL fopen/include off,
cURL/mail/process/socket functions disabled, open_basedir limited to the fixture,
no operator credentials, only loopback requests. This is not a general PHP sandbox
claim against arbitrary hostile PHP code. No Telegram messages or production
operations were performed.

The body-read trap proves **no explicit application read/parser**, not zero bytes
received by the HTTP server or zero PHP SAPI startup buffering. PHP may populate
POST/FILES before the script executes; enable_post_data_reading is a per-directory
setting, not a reliable per-request ini_set defense. Web server/SAPI configuration,
upstream refusal, body/header limits, deadlines, concurrency and access-log
redaction remain deployment responsibilities. See the
[PHP core directive documentation](https://www.php.net/manual/en/ini.core.php#ini.enable-post-data-reading).
Retiring script code does not change unknown deployed copies or historical logs.

Core's explicit legacy send path previously ignored HTTP status before showing
SENT. Root was notified and the UI owner must make unsupported legacy operation
fail visibly; this PHP-only checkpoint does not fix that caller. No automatic
mode/key/history reset or silent relay fallback is introduced. Safe authenticated
recovery/migration of old remote spool, removal/archiving of old public log files,
actual publication inventory and tested operator configuration remain open.
No all-S07/all-vulnerabilities/full-application DONE claim is made.
