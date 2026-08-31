import base64
import unittest

from nacl.signing import SigningKey

from backend.client_gateway import (
    auth_transcript,
    device_auth_transcript,
    verify_auth,
    verify_device_auth,
)


class ClientGatewayAuthTests(unittest.TestCase):
    def test_legacy_transcript_helper_remains_verifiable_but_is_not_device_auth(self):
        signing_key = SigningKey.generate()
        public_key = signing_key.verify_key.encode().hex()
        signature = base64.b64encode(signing_key.sign(auth_transcript("session-test", "nonce-test")).signature).decode("ascii")
        self.assertTrue(verify_auth(public_key, signature, "session-test", "nonce-test"))

    def test_device_auth_binds_challenge_node_and_client_nonce(self):
        signing_key = SigningKey.generate()
        public_key = signing_key.verify_key.encode().hex()
        fields = dict(node_id="ab" * 32, session_id="session-test", server_nonce="server-nonce", client_nonce="client-nonce-012345", expires_at=1_900_000_000)
        signature = base64.b64encode(signing_key.sign(device_auth_transcript(**fields)).signature).decode("ascii")
        self.assertTrue(verify_device_auth(public_key, signature, **fields))
        # Capture/replay cannot authenticate a fresh challenge/session.
        self.assertFalse(verify_device_auth(public_key, signature, **{**fields, "server_nonce": "fresh-nonce"}))
        self.assertFalse(verify_device_auth(public_key, signature, **{**fields, "session_id": "fresh-session"}))
        self.assertFalse(verify_device_auth(public_key, signature, **{**fields, "node_id": "cd" * 32}))
        self.assertFalse(verify_device_auth(public_key, signature, **{**fields, "expires_at": fields["expires_at"] + 1}))
        self.assertFalse(verify_device_auth("cd" * 32, signature, **fields))


if __name__ == "__main__":
    unittest.main()
