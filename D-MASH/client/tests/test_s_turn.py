import unittest

from backend.s_turn import STurnService


class STurnTests(unittest.TestCase):
    def setUp(self):
        self.now = [1000.0]
        self.service = STurnService(signaling_wss="wss://turn.example/signal",
                                    turn_urls=("turn:turn.example:3478",),
                                    shared_secret=b"s" * 32,
                                    health_probe=lambda: True,
                                    clock=lambda: self.now[0])

    def test_health_gates_descriptor_and_credentials(self):
        unhealthy = STurnService(signaling_wss="wss://turn.example/signal",
                                 turn_urls=("turn:turn.example:3478",), health_probe=lambda: False)
        self.assertEqual(unhealthy.descriptor(), {"can_s_turn": False})
        with self.assertRaises(RuntimeError):
            unhealthy.issue_turn_credentials("c" * 32)
        descriptor = self.service.descriptor()
        self.assertTrue(descriptor["can_s_turn"])
        self.assertNotIn("account_id", descriptor)

    def test_turn_rest_credentials_are_short_lived_and_bound_to_runtime_secret(self):
        credentials = self.service.issue_turn_credentials("c" * 32, ttl=30)
        self.assertEqual(credentials["expires_at"], 1030)
        self.assertIn(":", credentials["username"])
        self.assertNotEqual(credentials["credential"], credentials["username"])
        self.now[0] = 1031
        # Credential objects are intentionally not accepted as long-lived state;
        # a new issuance gets a different username and expiry.
        fresh = self.service.issue_turn_credentials("c" * 32, ttl=30)
        self.assertNotEqual(credentials["username"], fresh["username"])

    def test_one_time_tickets_relay_only_opaque_signaling(self):
        session = self.service.create_session("c" * 32, b"k" * 32, ttl=10)
        caller = self.service.join(session["session_id"], session["caller_ticket"], "caller")
        callee = self.service.join(session["session_id"], session["callee_ticket"], "callee")
        self.assertNotEqual(caller, callee)
        self.assertNotIn(caller, {"caller", "callee"})
        self.service.relay(session["session_id"], caller, {"type": "offer", "payload": "opaque-sdp"})
        self.assertEqual(self.service.receive(session["session_id"], callee),
                         [{"type": "offer", "payload": "opaque-sdp"}])
        self.assertEqual(self.service.receive(session["session_id"], caller), [])
        with self.assertRaises(PermissionError):
            self.service.join(session["session_id"], session["caller_ticket"], "callee")
        self.now[0] = 1011
        with self.assertRaises(PermissionError):
            self.service.receive(session["session_id"], callee)

    def test_session_never_accepts_account_or_device_identity_fields(self):
        session = self.service.create_session("c" * 32, b"k" * 32)
        handle = self.service.join(session["session_id"], session["caller_ticket"], "caller")
        with self.assertRaises(ValueError):
            self.service.relay(session["session_id"], handle, {
                "type": "offer", "payload": "x", "account_id": "forbidden"})

    def test_unjoined_principal_cannot_read_destroy_or_write_session(self):
        session = self.service.create_session("c" * 32, b"k" * 32)
        sid = session['session_id']
        handle = self.service.join(sid, session['caller_ticket'], 'caller')
        with self.assertRaises(PermissionError): self.service.receive(sid, 'caller')
        with self.assertRaises(PermissionError): self.service.relay(sid, 'caller', {'type': 'offer', 'payload': 'x'})
        self.service.relay(sid, handle, {'type': 'offer', 'payload': 'x'})
        self.assertIn(sid, self.service._sessions)

    def test_capacity_expiry_and_shutdown(self):
        self.service.capacity = 1
        self.service.max_messages = 1
        session = self.service.create_session('c' * 32, b'k' * 32, ttl=10)
        with self.assertRaises(BufferError): self.service.create_session('d' * 32, b'k' * 32)
        sid = session['session_id']
        handle = self.service.join(sid, session['caller_ticket'], 'caller')
        self.service.relay(sid, handle, {'type': 'ice', 'payload': 'x'})
        with self.assertRaises(BufferError): self.service.relay(sid, handle, {'type': 'ice', 'payload': 'y'})
        self.now[0] += 11
        self.service.create_session('d' * 32, b'k' * 32)
        self.service.close()
        self.assertFalse(self.service.healthy())
        with self.assertRaises(RuntimeError): self.service.create_session('e' * 32, b'k' * 32)

    def test_coturn_password_matches_documented_rest_algorithm(self):
        import base64, hashlib, hmac
        credentials = self.service.issue_turn_credentials('c' * 32)
        expected = base64.b64encode(hmac.new(b's' * 32, credentials['username'].encode(), hashlib.sha1).digest()).decode()
        self.assertEqual(credentials['credential'], expected)

    def test_health_is_not_assumed_from_configuration(self):
        service = STurnService(signaling_wss='wss://turn.example/signal', turn_urls=('turn:turn.example:3478',))
        self.assertFalse(service.healthy())


if __name__ == "__main__":
    unittest.main()
