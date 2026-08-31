import base64
import asyncio
import unittest

from nacl.signing import SigningKey
from starlette.websockets import WebSocketDisconnect

import backend.client_gateway as gateway
from backend.client_gateway import (
    auth_transcript,
    device_auth_transcript,
    verify_auth,
    verify_device_auth,
    router,
)


class ClientGatewayAuthTests(unittest.TestCase):
    class GatewaySocket:
        """Minimal ASGI WebSocket surface used by the real gateway coroutine."""
        def __init__(self, inbound):
            self.inbound = list(inbound)
            self.sent = []
            self.closed = None

        async def accept(self):
            return None

        async def send_json(self, payload):
            self.sent.append(payload)

        async def receive_text(self):
            if not self.inbound:
                raise RuntimeError("test socket has no more frames")
            frame = self.inbound.pop(0)
            if frame == "__DISCONNECT__":
                raise WebSocketDisconnect()
            return frame(self.sent) if callable(frame) else frame

        async def close(self, code=1000, reason=""):
            self.closed = (code, reason)

    def setUp(self):
        self.node_key = SigningKey.generate()
        self.previous_runtime_state = gateway.runtime_state
        # Gateway auth needs only NodeID and a capability policy. The test
        # never requests a transport operation, so no routing/session state is
        # fabricated or persisted.
        gateway.runtime_state = lambda: type("State", (), {
            "node_crypto": type("NodeCrypto", (), {"node_id": self.node_key.verify_key.encode().hex()})(),
            "capabilities": None,
            "node": None,
        })()

    def tearDown(self):
        gateway.runtime_state = self.previous_runtime_state

    def test_v2_websocket_authenticates_only_valid_device_transcript(self):
        client_key = SigningKey.generate()
        def valid_auth(sent):
            challenge = sent[0]
            client_nonce = "client-nonce-0123456789"
            transcript = device_auth_transcript(
                challenge["node_id"], challenge["session_id"], challenge["nonce"],
                client_nonce, challenge["expires_at"],
            )
            return __import__("json").dumps({
                "type": "AUTH", "auth_mode": "DEVICE_AUTH_V1",
                "public_key": client_key.verify_key.encode().hex(), "client_nonce": client_nonce,
                "signature": base64.b64encode(client_key.sign(transcript).signature).decode("ascii"),
            })
        websocket = self.GatewaySocket([valid_auth, "__DISCONNECT__"])
        asyncio.run(gateway.dmp_client(websocket))
        self.assertEqual(websocket.sent[0]["auth_mode"], "DEVICE_AUTH_V1")
        self.assertEqual(websocket.sent[0]["version"], 2)
        self.assertEqual(websocket.sent[0]["node_id"], self.node_key.verify_key.encode().hex())
        self.assertEqual(websocket.sent[1]["type"], "AUTH_OK")
        self.assertEqual(websocket.sent[1]["auth_mode"], "DEVICE_AUTH_V1")

    def test_v2_rejects_legacy_or_replayed_challenge_signature(self):
        client_key = SigningKey.generate()
        def replayed_auth(sent):
            challenge = sent[0]
            # Signing a captured transcript with a changed fresh client nonce
            # must be rejected by the session rather than falling back.
            captured_nonce = "client-nonce-captured-1"
            transcript = device_auth_transcript(challenge["node_id"], challenge["session_id"], challenge["nonce"], captured_nonce, challenge["expires_at"])
            return __import__("json").dumps({
                "type": "AUTH", "auth_mode": "DEVICE_AUTH_V1",
                "public_key": client_key.verify_key.encode().hex(), "client_nonce": "client-nonce-fresh-222",
                "signature": base64.b64encode(client_key.sign(transcript).signature).decode("ascii"),
            })
        websocket = self.GatewaySocket([replayed_auth])
        asyncio.run(gateway.dmp_client(websocket))
        self.assertEqual(websocket.closed, (1008, "authentication failed"))

    def test_legacy_compatibility_is_explicit_not_a_v2_fallback(self):
        paths = {route.path for route in router.routes}
        self.assertIn("/dmp-c/v1", paths)
        self.assertIn("/dmp-c/legacy-v1", paths)

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
