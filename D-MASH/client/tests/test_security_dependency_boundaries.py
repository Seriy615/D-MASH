"""Adversarial semantics behind S03 pins; probe routes are fixtures, not product exposure."""
import io
import unittest

from python_multipart import MultipartParser, parse_form
from python_multipart.exceptions import MultipartParseError
from starlette.applications import Starlette
from starlette.endpoints import HTTPEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient


def scope(path="/private", host=b"trusted.invalid"):
    return {
        "type": "http", "scheme": "http", "path": path,
        "root_path": "", "query_string": b"", "method": "GET",
        "headers": [(b"host", host)], "server": ("fallback.invalid", 80),
    }


class SecurityDependencyBoundaryTests(unittest.TestCase):
    def test_malformed_host_cannot_rewrite_url_path(self):
        request = Request(scope(host=b"trusted.invalid/allowed?override="))
        self.assertEqual(request.url.path, "/private")
        self.assertEqual(request.url.hostname, "fallback.invalid")

    def test_path_cannot_cross_into_url_authority(self):
        request = Request(scope(path="@attacker.invalid"))
        self.assertEqual(request.url.hostname, "trusted.invalid")
        self.assertEqual(request.url.path, "/@attacker.invalid")

    def test_nonstandard_method_cannot_dispatch_private_helper(self):
        invoked = []

        class FixtureEndpoint(HTTPEndpoint):
            async def get(self, request):
                return JSONResponse({"ok": True})

            async def _do_delete(self, request):
                invoked.append(True)
                return JSONResponse({"internal": True})

        with TestClient(Starlette(routes=[Route("/", FixtureEndpoint)])) as client:
            self.assertEqual(client.get("/").status_code, 200)
            self.assertEqual(client.request("_DO_DELETE", "/").status_code, 405)
        self.assertEqual(invoked, [])

    def test_urlencoded_field_count_limit_is_enforced(self):
        async def parse(request):
            async with request.form(max_fields=2) as form:
                return JSONResponse({"fields": len(form)})

        with TestClient(Starlette(routes=[Route("/", parse, methods=["POST"])])) as client:
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
            self.assertEqual(client.post("/", content="a=1&b=2", headers=headers).status_code, 200)
            self.assertEqual(client.post("/", content="a=1&b=2&c=3", headers=headers).status_code, 400)

    def test_urlencoded_field_size_limit_is_enforced(self):
        async def parse(request):
            async with request.form(max_part_size=8) as form:
                return JSONResponse({"fields": len(form)})

        with TestClient(Starlette(routes=[Route("/", parse, methods=["POST"])])) as client:
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
            self.assertEqual(client.post("/", content="x=1234", headers=headers).status_code, 200)
            self.assertEqual(client.post("/", content="x=123456789", headers=headers).status_code, 400)

    def test_negative_content_length_rejects_before_stream_read(self):
        class NoRead:
            def read(self, size):
                raise AssertionError("negative Content-Length must never reach body read")

        with self.assertRaisesRegex(ValueError, "non-negative"):
            parse_form({"Content-Type": b"application/x-www-form-urlencoded", "Content-Length": b"-1"}, NoRead(), None, None)

    def test_semicolon_is_field_data_not_a_parameter_separator(self):
        fields = []
        data = b"x=a;b=c&z=d"
        parse_form(
            {"Content-Type": b"application/x-www-form-urlencoded", "Content-Length": str(len(data)).encode()},
            io.BytesIO(data), lambda field: fields.append((field.field_name, field.value)), None,
        )
        self.assertEqual(fields, [(b"x", b"a;b=c"), (b"z", b"d")])

    def test_default_multipart_header_count_is_bounded(self):
        payload = b"--boundary\r\n" + b"X-Header: value\r\n" * 9 + b"\r\nvalue\r\n--boundary--\r\n"
        with self.assertRaises(MultipartParseError):
            MultipartParser(b"boundary").write(payload)

    def test_default_multipart_header_size_is_bounded(self):
        payload = b"--boundary\r\nX-Header: " + b"x" * 5000 + b"\r\n\r\nvalue\r\n--boundary--\r\n"
        with self.assertRaises(MultipartParseError):
            MultipartParser(b"boundary").write(payload)
