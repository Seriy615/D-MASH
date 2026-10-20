# S03 dependencies and S07 HTTP boundary — 20 October 2026

Status: implemented and locally tested; no production deployment. This is a
backend/Origin checkpoint, not acceptance of the complete application or native
clients. Frozen audit evidence is unchanged.

## Result and exact inputs

The client and Origin use FastAPI **0.135.4**, Starlette **1.3.1** and Pydantic
**2.14.1**. The client pins python-multipart **0.0.32**. FastAPI's compatible
Pydantic v2 requirement necessitates the Pydantic update; unrelated application
dependencies retain their direct pins. These are compatible patched versions,
not a claim that every selected version is the newest release. Published package
metadata: [FastAPI](https://pypi.org/project/fastapi/0.135.4/),
[Starlette](https://pypi.org/project/starlette/1.3.1/),
[python-multipart](https://pypi.org/project/python-multipart/0.0.32/).

[S03_VERIFICATION.json](S03_VERIFICATION.json) records the exact 114 Python and
requirements input hashes, before-run capture, commands, counts and raw-log
hashes. The candidate overlay was tested on source base `d8eff7d`; the input
hashes identify the tested changes independently of unrelated shared-checkout
JS/native work. Backend **303/303** and Origin **22/22** passed. Backend includes
the original 293 tests, nine dependency probes and one new route-boundary test;
Origin includes its original 11 and 11 ingress tests.

The final backend run used Python 3.12.3 and Node 24.19.0. A prior attempt used
system Node 18 and failed (302 tests, three failures/four errors); its log hash
is retained. Canonical Node 24 subsequently passed 302 tests before the HTTP
fix and 303 after it. An Origin discovery command from the wrong working
directory failed imports; the component-directory rerun passed. These failed
attempts are not reclassified as passes. The earlier source591 whole-project
runner failure remains historical evidence, not superseded by a claimed full
runner PASS here.

## Dependency closure and reproducibility

[constraints-python312.txt](../../../constraints-python312.txt) freezes all 29
resolved runtime/test-client components. `requirements-test.txt` applies these
constraints. [requirements-python312.lock](../../../requirements-python312.lock)
lists every component and the SHA256 of its downloaded wheel; a pip
`--dry-run --ignore-installed --require-hashes` check passed. The wheels target
**CPython 3.12 Linux x86_64**. Other Python/OS targets require their own resolved,
tested artifact hashes; this lock is not Windows or Android packaging evidence.

[S03_PACKAGE_PROVENANCE.json](S03_PACKAGE_PROVENANCE.json) preserves public
download URLs, wheel hashes and interpreter markers from pip's install report.
[S03_RUNTIME_SBOM.cdx.json](S03_RUNTIME_SBOM.cdx.json) inventories those 29
components in CycloneDX format. It is a flat component inventory, not a verified
application-wide dependency graph or inventory of bundled browser/native code.
[S03_PIP_AUDIT.json](S03_PIP_AUDIT.json), produced by pip-audit 2.10.1 against
the exact constraint pins in a separate environment, reports **zero known
vulnerabilities** on 20 October 2026. This does not exclude unknown defects.
The reference environment was not modified.

Reproduce in an isolated Python 3.12 environment:

```sh
python -m pip install --require-hashes -r requirements-python312.lock
python -m pip check
# From D-MASH/client, with Node24 first on PATH:
python -m unittest discover -s tests -v
# From origin:
python -m unittest discover -s tests -v
# Separate audit environment:
python -m pip_audit --disable-pip --no-deps -r constraints-python312.txt -f json
```

## Original advisory matches and actual reachability

[S03_ADVISORIES.json](S03_ADVISORIES.json) preserves all 14 unique GHSA entries
from the frozen dependency findings, their current metadata and hashes of the
retrieved GitHub advisory records. The FastAPI entry is explicitly a withdrawn
duplicate. Fourteen version matches therefore do not mean fourteen distinct
remotely exploitable application flaws.

| Original advisory | Patched floor | Application relevance |
| --- | --- | --- |
| [qf9m-vfgh-m389](https://github.com/advisories/GHSA-qf9m-vfgh-m389) | FastAPI 0.109.1 | Withdrawn duplicate Content-Type advisory; original match retained. |
| [wp53-j4wj-2cfg](https://github.com/Kludex/python-multipart/security/advisories/GHSA-wp53-j4wj-2cfg) | multipart 0.0.22 | Arbitrary file write needs nondefault parser upload configuration; no production application caller found. |
| [mj87-hwqh-73pj](https://github.com/Kludex/python-multipart/security/advisories/GHSA-mj87-hwqh-73pj) | multipart 0.0.26 | Multipart preamble/epilogue resource exhaustion; no application form upload handler found. |
| [pp6c-gr5w-3c5g](https://github.com/Kludex/python-multipart/security/advisories/GHSA-pp6c-gr5w-3c5g) | multipart 0.0.27 | Header count/size bounds exercised with the actual installed parser. |
| [v9pg-7xvm-68hf](https://github.com/Kludex/python-multipart/security/advisories/GHSA-v9pg-7xvm-68hf) | multipart 0.0.31 | Negative Content-Length in parse_form; no application parse_form caller found. Fixture proves rejection before stream read. |
| [5rvq-cxj2-64vf](https://github.com/Kludex/python-multipart/security/advisories/GHSA-5rvq-cxj2-64vf) | multipart 0.0.30 | Query-string semicolon CPU behavior; fixture checks semicolon is field data, not separator. No timing/complexity proof claimed. |
| [6jv3-5f52-599m](https://github.com/Kludex/python-multipart/security/advisories/GHSA-6jv3-5f52-599m) | multipart 0.0.30 | Semicolon parameter ambiguity; same installed-parser fixture covers semantics. |
| [f96h-pmfr-66vw](https://github.com/Kludex/starlette/security/advisories/GHSA-f96h-pmfr-66vw) | Starlette 0.40.0 | Multipart resource bounds; no production Form/File/UploadFile/request.form handler found. |
| [2c2j-9gv5-cj73](https://github.com/Kludex/starlette/security/advisories/GHSA-2c2j-9gv5-cj73) | Starlette 0.47.2 | Large-file parser behavior; no production multipart upload handler found. |
| [86qp-5c8j-p5mr](https://github.com/Kludex/starlette/security/advisories/GHSA-86qp-5c8j-p5mr) | Starlette 1.0.1 | Malformed Host must not rewrite URL.path; actual Request fixture passes. No application URL.path authorization guard found. |
| [wqp7-x3pw-xc5r](https://github.com/Kludex/starlette/security/advisories/GHSA-wqp7-x3pw-xc5r) | Starlette 1.1.0 | StaticFiles is mounted by backend; exploit condition is Windows UNC behavior. Installed version patched; Windows exploit execution NOT RUN on Linux. |
| [x746-7m8f-x49c](https://github.com/Kludex/starlette/security/advisories/GHSA-x746-7m8f-x49c) | Starlette 1.1.0 | No production HTTPEndpoint subclass found; fixture rejects private-helper method dispatch. |
| [jp82-jpqv-5vv3](https://github.com/Kludex/starlette/security/advisories/GHSA-jp82-jpqv-5vv3) | Starlette 1.3.0 | Request path cannot cross into URL authority; actual Request fixture passes. No application hostname authorization guard found. |
| [82w8-qh3p-5jfq](https://github.com/Kludex/starlette/security/advisories/GHSA-82w8-qh3p-5jfq) | Starlette 1.3.1 | URL-encoded form field-count/size limits now enforced by actual Request.form fixtures. |

Search scope was production Python under `D-MASH/client/backend` and `origin`,
excluding test fixtures. Removing a reachable handler is not substituted for
upgrading the affected dependency. Nine adversarial dependency tests failed on
the unchanged old environment (seven failures and one unsupported-API error),
then passed on the new pins. This is targeted semantic coverage, not a bespoke
exploit test for every advisory.

## HTTP boundary fixes

`D-MASH/client/backend/api.py`: a router dependency rejected retired HTTP before
state mutation but **after** FastAPI body parsing. Malformed `/api/login` JSON
was consumed and returned 422. `RetiredHttpRoute.handle` now returns 410 before
calling receive or a parser; include_router preserves the route class. The
actual app regression covers all seven retired POST paths with JSON/multipart
content types and a receive trap. Direct function guards remain. Node WebSocket
routes do not use this route class.

`origin/http_boundary.py` and `origin/notification_service.py`: pure ASGI ingress
bounds all POST bodies to **65,536 bytes** before JSON, authentication, DB or
Telegram work. Origin receives signed notification/control envelopes and webhook
metadata, not file/media uploads. The cap provides headroom for those messages.
Oversized declared bodies return 413 without reading; duplicate, negative or
nonnumeric Content-Length returns 400; thousands-digit lengths cannot overflow
integer parsing. Absent/chunked or dishonest lengths are bounded by actual bytes.
Only the complete bounded bytes are replayed downstream.

Origin regressions exercise all nine POST routes, no handler/DB/network work on
oversized data, exact cap versus cap+1, absent/declared/chunked bodies, malformed
JSON, duplicate/many-digit lengths, disconnect, unchanged GET and unchanged WS
scope forwarding. The exact-cap test reaches authentication with the complete
bytes; it does not promise acceptance of invalid or unsigned payloads.

The bounded bytearray avoids unbounded bookkeeping for many empty chunks.
The application still requires transport read deadlines, header limits,
concurrency/rate quotas and deployment validation against slow peers. The cap
does not solve all denial of service. Existing backend Uvicorn WebSocket size/
queue/compression settings and Node wire semantics were not changed; no native,
real-NAT, multi-peer or production acceptance is implied.
