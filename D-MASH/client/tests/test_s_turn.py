import unittest

from backend.s_turn import STurnService


class STurnTests(unittest.TestCase):
    def setUp(self):
        self.now = [1000.0]
        self.service = STurnService(signaling_wss="wss://turn.example/signal",
                                    turn_urls=("turn:turn.example:3478",),
                                    shared_secret=b"s" * 32,
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
        self.assertEqual((caller, callee), ("caller", "callee"))
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
        self.service.join(session["session_id"], session["caller_ticket"], "caller")
        with self.assertRaises(ValueError):
            self.service.relay(session["session_id"], "caller", {
                "type": "offer", "payload": "x", "account_id": "forbidden"})


if __name__ == "__main__":
    unittest.main()
