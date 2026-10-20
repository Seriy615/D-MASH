"""Actual Origin ASGI ingress must bound bytes before JSON/auth/DB handlers."""
import unittest
from unittest.mock import patch

from fastapi import HTTPException
import notification_service as service

LIMIT = 64 * 1024


def scope(path="/v1/notify", headers=(), method="POST"):
    return {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": method, "scheme": "http", "path": path, "raw_path": path.encode(), "query_string": b"", "root_path": "", "server": ("test", 80), "client": ("127.0.0.1", 1), "headers": [(b"content-type", b"application/json"), *headers]}


async def invoke(app, request_scope, chunks):
    messages, reads = [], []
    iterator = iter(chunks)

    async def receive():
        reads.append(True)
        try:
            return next(iterator)
        except StopIteration:
            raise AssertionError("unexpected read after supplied body/disconnect")

    async def send(message):
        messages.append(message)

    await app(request_scope, receive, send)
    status = next((m["status"] for m in messages if m["type"] == "http.response.start"), None)
    return status, len(reads), messages


def body(data, more=False):
    return {"type": "http.request", "body": data, "more_body": more}


class OriginHttpBoundaryTests(unittest.IsolatedAsyncioTestCase):
    async def test_oversized_declared_length_denies_all_posts_before_receive_or_state(self):
        paths = ["/v1/beacon/remove", "/v1/telegram/webhook", "/v1/personal-bots/enroll", "/v1/personal-bots/status", "/v1/personal-bots/test", "/v1/personal-bots/disable", "/v1/personal-bots/remove", "/v1/telegram/personal-webhook", "/v1/notify"]
        with patch.object(service, "connect_db", side_effect=AssertionError("DB reached")), patch.object(service, "decrypt_node_request", side_effect=AssertionError("decrypt reached")), patch.object(service, "telegram_call", side_effect=AssertionError("network reached")):
            for path in paths:
                with self.subTest(path=path):
                    status, reads, _ = await invoke(service.app, scope(path, [(b"content-length", str(LIMIT + 1).encode())]), [])
                    self.assertEqual((status, reads), (413, 0))

    async def test_absent_content_length_is_counted_and_stops_on_overflow(self):
        with patch.object(service, "decrypt_node_request", side_effect=AssertionError("handler reached")):
            status, reads, _ = await invoke(service.app, scope(), [body(b"x" * LIMIT, True), body(b"x", True)])
        self.assertEqual((status, reads), (413, 2))

    async def test_small_declared_length_does_not_bypass_actual_byte_count(self):
        with patch.object(service, "decrypt_node_request", side_effect=AssertionError("handler reached")):
            status, reads, _ = await invoke(service.app, scope(headers=[(b"content-length", b"1")]), [body(b"x" * (LIMIT + 1))])
        self.assertEqual((status, reads), (413, 1))

    async def test_invalid_or_ambiguous_content_length_refuses_without_body_read(self):
        for headers in [[(b"content-length", b"-1")], [(b"content-length", b"abc")], [(b"content-length", b"1"), (b"content-length", b"2")]]:
            with self.subTest(headers=headers):
                status, reads, _ = await invoke(service.app, scope(headers=headers), [])
                self.assertEqual((status, reads), (400, 0))

    async def test_large_numeric_length_cannot_overflow_integer_parser(self):
        status, reads, _ = await invoke(service.app, scope(headers=[(b"content-length", b"9" * 5000)]), [])
        self.assertEqual((status, reads), (413, 0))

    async def test_allowed_body_is_forwarded_once_byte_exact(self):
        payload = b'{"synthetic":"bounded"}'
        seen = []

        def decrypt(data):
            seen.append(data)
            raise HTTPException(403, "synthetic authentication refusal")

        with patch.object(service, "decrypt_node_request", side_effect=decrypt):
            status, reads, _ = await invoke(service.app, scope(), [body(payload[:8], True), body(payload[8:])])
        self.assertEqual((status, reads, seen), (403, 2, [payload]))

    async def test_exact_limit_is_allowed_and_headroom_is_not_silently_truncated(self):
        payload = b"x" * LIMIT
        for headers in [[], [(b"content-length", str(LIMIT).encode())], [(b"transfer-encoding", b"chunked")]]:
            with self.subTest(headers=headers):
                with patch.object(service, "decrypt_node_request", side_effect=HTTPException(403, "synthetic authentication refusal")) as decrypt:
                    status, reads, _ = await invoke(service.app, scope(headers=headers), [body(payload[:32768], True), body(payload[32768:])])
                self.assertEqual((status, reads), (403, 2))
                decrypt.assert_called_once_with(payload)

    async def test_small_malformed_json_preserves_existing_400_without_db(self):
        with patch.object(service, "connect_db", side_effect=AssertionError("DB reached")):
            status, _, _ = await invoke(service.app, scope("/v1/beacon/remove"), [body(b"{invalid")])
        self.assertEqual(status, 400)

    async def test_get_health_does_not_receive_a_body(self):
        status, reads, _ = await invoke(service.app, scope("/health", [(b"content-length", str(LIMIT + 1).encode())], "GET"), [])
        self.assertEqual((status, reads), (200, 0))

    async def test_disconnect_does_not_enter_handler_or_touch_state(self):
        with patch.object(service, "decrypt_node_request", side_effect=AssertionError("handler reached")):
            status, reads, messages = await invoke(service.app, scope(), [body(b"{", True), {"type": "http.disconnect"}])
        self.assertEqual((status, reads, messages), (None, 2, []))

    async def test_non_http_scope_is_passed_to_downstream_unchanged(self):
        from http_boundary import OriginBodyLimit
        entered, sent = [], []
        websocket_scope = {"type": "websocket", "headers": [(b"content-length", b"999999999")], "path": "/unused"}

        async def downstream(actual_scope, receive, send):
            entered.append(actual_scope)
            self.assertEqual(await receive(), {"type": "websocket.connect"})
            await send({"type": "websocket.accept"})

        async def receive():
            return {"type": "websocket.connect"}

        async def send(message):
            sent.append(message)

        await OriginBodyLimit(downstream)(websocket_scope, receive, send)
        self.assertIs(entered[0], websocket_scope)
        self.assertEqual(sent, [{"type": "websocket.accept"}])
