<?php
// Retired legacy PHP relay. No request body, credentials, DB or provider call.
// The public X-DMASH-AGENT value never authenticated a caller. Re-enabling this
// format requires a separately reviewed ownership/protocol migration; there is
// intentionally no environment/header bypass for the unsafe legacy contract.
declare(strict_types=1);

http_response_code(410);
header_remove('X-Powered-By');
header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store');
echo '{"detail":"Legacy PHP endpoint retired; use authenticated Node/Origin services."}';
exit;
