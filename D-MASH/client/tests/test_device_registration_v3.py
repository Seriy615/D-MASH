import base64
import secrets
import unittest

from nacl.signing import SigningKey

from backend.device_registration import DeviceRegistration, DeviceSession, RegistrationError, authority_transcript, private_locator
from backend.entry_grant import EntryGrantV1
from backend.resource_pow import mine_activation_pow
from backend.secure_session import b64


class DeviceRegistrationTests(unittest.TestCase):
    def setUp(self):
        self.node = SigningKey.generate().verify_key.encode().hex()
        self.durable = secrets.token_bytes(32)
        self.registry = DeviceRegistration(self.node, self.durable, clock=lambda: 1000)
        self.registry.difficulty = 4
        self.device = SigningKey.generate().verify_key.encode().hex()
        self.session = DeviceSession(self.device, "01" * 32)
        self.dnss = "41" * 16
        self.registry.bind_dnss(self.session, self.dnss, self.work("DNSS", bytes.fromhex(self.dnss)))
        self.route = SigningKey.generate()

    def work(self, kind, resource, session=None):
        return mine_activation_pow(self.node, kind, (session or self.session).public_key, resource, 1060, difficulty=4)

    def authorization(self, kind="PUBLIC", operation="REGISTER_ROUTE", session=None, key=None):
        session, key = session or self.session, key or self.route
        public = b64(key.verify_key.encode())
        route_id = base64.urlsafe_b64encode(key.verify_key.encode()).decode().rstrip("=") if kind == "PUBLIC" else private_locator(public)
        auth = {"kind": kind, "route_id": route_id, "public_key": public, "generation": 1, "expires_at": 2000}
        request_id = secrets.token_hex(16)
        auth["signature"] = b64(key.sign(authority_transcript(self.node, session, operation, request_id, auth)).signature)
        return request_id, auth

    def grant(self, auth, node=None):
        return EntryGrantV1.issue(self.route, auth["route_id"], 2000, entry_node_id=node or self.node, created_at=1000).to_dict()

    def register(self, kind="PUBLIC"):
        request_id, auth = self.authorization(kind)
        self.registry.authorize_route(self.session, "REGISTER_ROUTE", request_id, auth,
            grant=self.grant(auth) if kind == "PUBLIC" else None,
            proof=self.work("ENTRY_GRANT" if kind == "PUBLIC" else "PRIVATE_ROUTE", auth["route_id"]))
        return request_id, auth

    def test_reconnect_preserves_dnss_new_socket_binding(self):
        next_session = DeviceSession(self.device, "02" * 32)
        self.assertEqual(self.registry.bind_dnss(next_session, self.dnss), self.session.blind_dnss)
        self.assertEqual(next_session.dnss, self.session.dnss)
        with self.assertRaisesRegex(RegistrationError, "ALREADY_BOUND"):
            self.registry.bind_dnss(next_session, "42" * 16)

    def test_restart_requires_work_but_mailbox_alias_survives(self):
        restarted = DeviceRegistration(self.node, self.durable, clock=lambda: 1000)
        restarted.difficulty = 4
        session = DeviceSession(self.device, "03" * 32)
        with self.assertRaisesRegex(RegistrationError, "NOT_REGISTERED"):
            restarted.bind_dnss(session, self.dnss)
        self.assertEqual(restarted.bind_dnss(session, self.dnss, self.work("DNSS", bytes.fromhex(self.dnss))), self.session.blind_dnss)
        self.assertNotEqual(restarted.route_alias("route"), self.registry.route_alias("route"))

    def test_wrong_device_cannot_bind_registered_dnss_or_recover_its_mailbox_after_restart(self):
        attacker = DeviceSession(SigningKey.generate().verify_key.encode().hex(), "04" * 32)
        with self.assertRaisesRegex(RegistrationError, "OWNER_MISMATCH"):
            self.registry.bind_dnss(attacker, self.dnss)
        restarted = DeviceRegistration(self.node, self.durable, clock=lambda: 1000)
        restarted.difficulty = 4
        alias = restarted.bind_dnss(attacker, self.dnss, self.work("DNSS", bytes.fromhex(self.dnss), attacker))
        self.assertNotEqual(alias, self.session.blind_dnss)

    def test_public_and_private_authority_and_probe_and_unregister(self):
        for kind in ("PUBLIC", "PRIVATE"):
            self.register(kind)
            rid, auth = self.authorization(kind, "START_PROBE")
            record = self.registry.authorize_route(self.session, "START_PROBE", rid, auth)
            self.assertEqual(record.blind_dnss, self.session.blind_dnss)
            rid, auth = self.authorization(kind, "UNREGISTER_ROUTE")
            self.registry.authorize_route(self.session, "UNREGISTER_ROUTE", rid, auth)
            self.assertNotIn(self.registry.route_alias(auth["route_id"]), self.registry.routes)

    def test_no_work_no_route_side_effect(self):
        for kind in ("PUBLIC", "PRIVATE"):
            rid, auth = self.authorization(kind)
            with self.assertRaisesRegex(RegistrationError, "RESOURCE_POW"):
                self.registry.authorize_route(self.session, "REGISTER_ROUTE", rid, auth,
                    grant=self.grant(auth) if kind == "PUBLIC" else None)
            self.assertFalse(self.registry.routes)

    def test_wrong_grant_node_or_expiry(self):
        for mismatch in ("node", "expiry"):
            rid, auth = self.authorization()
            grant = self.grant(auth, node=SigningKey.generate().verify_key.encode().hex()) if mismatch == "node" else self.grant(auth)
            if mismatch == "expiry": grant["expires_at"] = 999
            with self.assertRaisesRegex(RegistrationError, "ENTRY_GRANT"):
                self.registry.authorize_route(self.session, "REGISTER_ROUTE", rid, auth, grant=grant)

    def test_proof_replay_wrong_session_dnss_and_operation(self):
        self.register()
        rid, auth = self.authorization(operation="START_PROBE")
        self.registry.authorize_route(self.session, "START_PROBE", rid, auth)
        with self.assertRaises(RegistrationError): self.registry.authorize_route(self.session, "START_PROBE", rid, auth)
        for change in ("session", "dnss", "operation"):
            other = DeviceSession(self.device, "05" * 32 if change == "session" else self.session.transcript_hash)
            dnss = "45" * 16 if change == "dnss" else self.dnss
            self.registry.bind_dnss(other, dnss, self.work("DNSS", bytes.fromhex(dnss)))
            with self.assertRaises(RegistrationError):
                self.registry.authorize_route(other, "UNREGISTER_ROUTE" if change == "operation" else "START_PROBE", rid, auth)

    def test_foreign_routes(self):
        for kind in ("PUBLIC", "PRIVATE"):
            self.register(kind)
            rid, auth = self.authorization(kind, "UNREGISTER_ROUTE")
            attacker_key = SigningKey.generate()
            auth["signature"] = b64(attacker_key.sign(authority_transcript(self.node, self.session, "UNREGISTER_ROUTE", rid, auth)).signature)
            with self.assertRaises(RegistrationError): self.registry.authorize_route(self.session, "UNREGISTER_ROUTE", rid, auth)
