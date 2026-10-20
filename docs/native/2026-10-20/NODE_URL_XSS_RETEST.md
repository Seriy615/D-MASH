# NODE-URL-XSS-01

Fixed in `690cb1b`, release `.40`. [Root reproduced JavaScript execution on354](root-node-url-xss-red.json) by adding a synthetic WSS URL containing an apostrophe and clicking Global Nodes → ОСНОВНОЙ. `encodeURIComponent` leaves the apostrophe unescaped, allowing it to terminate the inline JavaScript string.

Node actions now use DOM listeners closing over the original endpoint. Related effective UI/Core/v50/v51 data arguments use HTML-attribute-escaped JSON and an explicit allowlist of delegated DOM commands. This preserves names, IDs and URLs without executing them. Labels stay escaped text. The trace also removed direct dynamic inline media/file/camera/peer/message handlers. Remaining interpolated handlers in these files use static branch strings or a local numeric biometric index. Unloaded historical stability/v53 code is unchanged; regression prevents it returning to effective loaders.

[Actual browser GREEN](NODE_URL_XSS_RETEST.json): the same stored apostrophe URL survives reload; select succeeds without the former Unknown endpoint error; connect follows the isolated blocked-network path; removal Cancel preserves it, then confirmation removes it. No sentinel executes. Five response hashes match immutable690; DeviceID and the canonical encrypted record remain unchanged. Only this fixture's preliminary SW/cache were cleared before loading exact source; Root/IDB/localStorage were preserved. This is separate from [genuine SW upgrade proof](S01_BROWSER_UPGRADE_WIPE.json).

`ui_data_actions.test.js` exercises the production delegated binder with hostile quote/markup/Unicode/newline strings, rejects unknown/inherited commands, checks original URL delivery to all three Node actions and guards effective loader exclusion of historical unsafe wrappers. Browser media/physical-device behavior remains a separate acceptance scope.

[Full immutable690 JS run](NODE_URL_XSS_ALL_JS.json):159/159PASS, inputs unchanged, Node24.19.0. Raw stdout stays private mode0600; the public summary exposes only test status/timing and source digests. This does not claim Python/native/full-platform acceptance.
