"""The retired HTTP control plane must never inspect live Node/Account state."""
import unittest
from unittest.mock import patch

import httpx
from fastapi import FastAPI
from backend import api


class StateTrap:
    def __getattr__(self, name):
        raise AssertionError(f"retired HTTP handler accessed {name}")


class LegacyHttpBoundaryTests(unittest.IsolatedAsyncioTestCase):
    async def test_all_retired_routes_deny_before_state_access(self):
        app = FastAPI()
        app.include_router(api.router)
        requests = [
            ('GET', '/api/debug/packet/test', None),
            ('GET', '/api/debug/outbox', None),
            ('GET', '/api/debug/routes', None),
            ('POST', '/api/debug/get_route_ids', {'sender_id': 'a', 'receiver_id': 'b'}),
            ('POST', '/api/login', {'username': 'test', 'password': 'test-secret'}),
            ('POST', '/api/logout', None),
            ('POST', '/api/connect', {'address': '127.0.0.1:1'}),
            ('POST', '/api/send', {'target_id': 'test', 'text': 'test-secret'}),
            ('GET', '/api/state', None),
            ('GET', '/api/peers', None),
            ('GET', '/api/messages/test', None),
            ('POST', '/api/rename', {'target_id': 'test', 'name': 'test-secret'}),
            ('POST', '/api/read_chat', {'chat_id': 'test'}),
        ]
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
        with patch.object(api, 'state', StateTrap()), patch.object(
            api, 'CryptoManager', side_effect=AssertionError('retired HTTP handler derived keys')
        ):
            async with httpx.AsyncClient(transport=transport, base_url='http://test') as client:
                for method, path, body in requests:
                    with self.subTest(path=path):
                        response = await client.request(method, path, json=body)
                        self.assertEqual(response.status_code, 410, response.text)
                        self.assertNotIn('test-secret', response.text)
                        self.assertIn('unavailable', response.json()['detail'].lower())

    async def test_credentials_and_loopback_headers_do_not_reenable_legacy_api(self):
        app = FastAPI()
        app.include_router(api.router)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://test') as client:
            response = await client.post('/api/logout', headers={
                'Authorization': 'Bearer test', 'X-Forwarded-For': '127.0.0.1',
                'Origin': 'http://localhost',
            })
        self.assertEqual(response.status_code, 410)


class RetiredHttpBeforeReceiveTests(unittest.IsolatedAsyncioTestCase):
    async def test_retired_post_routes_deny_without_reading_or_parsing_body(self):
        app = FastAPI()
        app.include_router(api.router)
        paths = ["/api/login", "/api/logout", "/api/connect", "/api/send", "/api/rename", "/api/read_chat", "/api/debug/get_route_ids"]
        for path in paths:
            for content_type in [b"application/json", b"multipart/form-data; boundary=synthetic"]:
                with self.subTest(path=path, content_type=content_type):
                    messages, reads = [], []

                    async def receive():
                        reads.append(True)
                        raise AssertionError("retired HTTP request body was read before denial")

                    async def send(message):
                        messages.append(message)

                    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "POST", "scheme": "http", "path": path, "raw_path": path.encode(), "query_string": b"", "root_path": "", "server": ("test", 80), "client": ("127.0.0.1", 1), "headers": [(b"content-type", content_type), (b"content-length", b"1000000000")]}
                    await app(scope, receive, send)
                    self.assertEqual(messages[0]["status"], 410)
                    self.assertEqual(reads, [])
                    self.assertNotIn(b"1000000000", b"".join(message.get("body", b"") for message in messages))
