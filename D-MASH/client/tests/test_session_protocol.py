import base64
import unittest

from backend.session_protocol import validate_call_request, validate_file_session_request


class SessionProtocolTests(unittest.TestCase):
    def setUp(self):
        self.signaling = {"wss_endpoint": "wss://turn.example/signal", "one_time_key": "t" * 32}

    def test_call_request_accepts_bounded_ringtone_and_opaque_signaling(self):
        request = {"version": 2, "call_id": "a" * 64, "expires_at": 2000,
                   "signaling": self.signaling, "caller_display_name": "Alice",
                   "ringtone": {"mime": "audio/ogg", "base64": base64.b64encode(b"tone").decode()},
                   "media_capabilities": {"audio": True, "video": False}}
        self.assertEqual(validate_call_request(request), request)
        self.assertNotIn("account_id", validate_call_request(request))

    def test_call_ringtone_limits_and_mime_are_strict(self):
        request = {"version": 2, "call_id": "a" * 64, "expires_at": 2000,
                   "signaling": self.signaling, "caller_display_name": "Alice",
                   "ringtone": {"mime": "audio/ogg", "base64": base64.b64encode(b"tone").decode()},
                   "media_capabilities": {}}
        for update in ({"mime": "text/plain"}, {"base64": "%%%"},
                       {"base64": base64.b64encode(b"x" * (256 * 1024 + 1)).decode()}):
            broken = {**request, "ringtone": {**request["ringtone"], **update}}
            with self.assertRaises(ValueError): validate_call_request(broken)

    def test_file_request_is_resumable_and_metadata_stays_opaque(self):
        request = {"version": 1, "session_id": "b" * 64, "expires_at": 2000,
                   "signaling": self.signaling, "encrypted_metadata": "ciphertext",
                   "size_bytes": 1024 * 1024, "chunk_bytes": 64 * 1024,
                   "sha256": "c" * 64, "resumable": True}
        self.assertEqual(validate_file_session_request(request), request)
        for key, value in (("size_bytes", 50 * 1024 * 1024 * 1024 + 1),
                           ("chunk_bytes", 1024), ("sha256", "route-id"),
                           ("encrypted_metadata", "")):
            with self.assertRaises(ValueError):
                validate_file_session_request({**request, key: value})


if __name__ == "__main__":
    unittest.main()
