import base64
import unittest

from nacl.signing import SigningKey

from backend.client_gateway import auth_transcript, verify_auth


class ClientGatewayAuthTests(unittest.TestCase):
    def test_invalid_dmp_c_client_signature_is_rejected(self):
        signing_key = SigningKey.generate()
        public_key = signing_key.verify_key.encode().hex()
        session_id = "session-test"
        nonce = "nonce-test"
        signature = base64.b64encode(
            signing_key.sign(auth_transcript(session_id, nonce)).signature
        ).decode("ascii")
        self.assertTrue(verify_auth(public_key, signature, session_id, nonce))
        self.assertFalse(verify_auth(public_key, signature, session_id, "wrong-nonce"))
        self.assertFalse(verify_auth(public_key, "not-a-signature", session_id, nonce))


if __name__ == "__main__":
    unittest.main()
