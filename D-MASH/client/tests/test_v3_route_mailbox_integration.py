import secrets
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from nacl.signing import SigningKey

from backend.crypto import NodeCryptoManager
from backend.database import DatabaseManager
from backend.transport import NodeTransportService
from backend.device_registration import DeviceRegistration, DeviceSession, RegistrationError, authority_transcript, private_locator
from backend.dnss_mailbox import DnssMailbox
from backend.gateway_v3 import resource_operation
from backend.client_gateway import _routing_registration_operations
from backend.resource_pow import mine_activation_pow
from backend.secure_session import b64


class RouteMailboxIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.crypto = NodeCryptoManager(SigningKey.generate().encode().hex())
        self.db = DatabaseManager(str(Path(self.tmp.name) / "system.db"))
        self.db.set_node_crypto(self.crypto)
        await self.db.connect()
        self.mail = DnssMailbox(Path(self.tmp.name) / "mail.db")
        await self.mail.connect()
        self.transport = NodeTransportService(self.db, can_route=True, can_accept_devices=True)
        self.transport.v3_mailbox = self.mail
        self.registry = DeviceRegistration(self.crypto.node_id, self.crypto.secret_salt, clock=lambda: 1000)
        self.registry.difficulty = 4
        self.state = SimpleNamespace(device_registration=self.registry, dnss_mailbox=self.mail,
                                     node=SimpleNamespace(transport=self.transport))
        self.session = DeviceSession(SigningKey.generate().verify_key.encode().hex(), "ab" * 32)
        self.responses = []
        async def send(payload): self.responses.append(payload)
        self.secure = type("SecureSink", (), {"send_json": staticmethod(send)})()
        self.dnss = "aa" * 16
        await self.request({"type": "REGISTER_DNSS", "dnss": self.dnss,
                            "pow": self.work("DNSS", bytes.fromhex(self.dnss))})

    async def asyncTearDown(self):
        await self.db.close()
        await self.mail.close()
        self.tmp.cleanup()

    def work(self, kind, resource):
        return mine_activation_pow(self.crypto.node_id, kind, self.session.public_key, resource, 1060, difficulty=4)

    async def request(self, request):
        request.setdefault("request_id", secrets.token_hex(16))
        return await resource_operation(self.state, self.secure, self.session, request)

    def route_request(self, key, operation):
        public = b64(key.verify_key.encode())
        auth = {"kind": "PRIVATE", "route_id": private_locator(public), "public_key": public,
                "generation": 1, "expires_at": 2000}
        rid = secrets.token_hex(16)
        auth["signature"] = b64(key.sign(authority_transcript(self.crypto.node_id, self.session, operation, rid, auth)).signature)
        request = {"type": operation, "request_id": rid, "authorization": auth}
        if operation == "REGISTER_ROUTE": request["pow"] = self.work("PRIVATE_ROUTE", auth["route_id"])
        if operation == "START_PROBE": request.update(route_locator=auth["route_id"], back_route_locator=auth["route_id"])
        return request

    async def test_two_routes_one_dnss_one_pull_and_no_account_delivery_claim(self):
        routes = [SigningKey.generate(), SigningKey.generate()]
        for index, key in enumerate(routes):
            registration = self.route_request(key, "REGISTER_ROUTE")
            await self.request(registration)
            await self.request(self.route_request(key, "START_PROBE"))
            result = await self.request({"type": "SUBMIT", "route_locator": registration["authorization"]["route_id"],
                                         "ciphertext": b64(f"opaque device packet {index}".encode())})
            self.assertEqual(result["state"], "NODE_ACCEPTED")
        self.responses.clear()
        await self.request({"type": "PULL"})
        self.assertEqual(len(self.responses), 1)
        result = self.responses[0]
        self.assertEqual(result["type"], "MAILBOX_DRAIN_RESULT")
        self.assertEqual(len(result["entries"]), 2)
        for entry in result["entries"]:
            self.assertEqual(set(entry), {"delivery_id", "ciphertext"})
        await self.request({"type": "PULL"})
        self.assertEqual(self.responses[-1]["entries"], [])

    async def test_pull_cannot_select_other_queue_and_unregistered_route_cannot_probe(self):
        with self.assertRaisesRegex(RegistrationError, "QUEUE_SELECTOR"):
            await self.request({"type": "PULL", "blind_dnss": "ff" * 32})
        with self.assertRaisesRegex(RegistrationError, "ROUTE_NOT_REGISTERED"):
            await self.request(self.route_request(SigningKey.generate(), "START_PROBE"))

    async def test_unregister_does_not_delete_dnss_mailbox(self):
        key = SigningKey.generate()
        request = self.route_request(key, "REGISTER_ROUTE")
        await self.request(request)
        await self.request(self.route_request(key, "START_PROBE"))
        await self.request({"type": "SUBMIT", "route_locator": request["authorization"]["route_id"], "ciphertext": b64(b"opaque")})
        await self.request(self.route_request(key, "UNREGISTER_ROUTE"))
        self.responses.clear()
        await self.request({"type": "PULL"})
        self.assertEqual(len(self.responses[0]["entries"]), 1)

    def test_legacy_endpoint_cannot_bypass_v3_authority(self):
        result = _routing_registration_operations(self.state, {"START_PROBE", "REGISTER_INBOUND_LOCATOR", "UNREGISTER_INBOUND_LOCATOR", "PULL"})
        self.assertEqual(result, {"PING", "STATUS"})

    async def test_expired_authority_cannot_keep_receiving_data(self):
        key = SigningKey.generate()
        request = self.route_request(key, "REGISTER_ROUTE")
        await self.request(request)
        await self.request(self.route_request(key, "START_PROBE"))
        locator = request["authorization"]["route_id"]
        self.registry.clock = lambda: 2001
        with self.assertRaisesRegex(PermissionError, "expired or revoked"):
            await self.transport.submit_envelope(locator, {"version": 1, "ciphertext": b64(b"opaque")})
        self.responses.clear()
        await self.request({"type": "PULL"})
        self.assertEqual(self.responses[-1]["entries"], [])
