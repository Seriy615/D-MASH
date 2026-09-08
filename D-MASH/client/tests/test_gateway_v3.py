import unittest
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient
from nacl.signing import SigningKey
from starlette.websockets import WebSocketDisconnect

from backend import gateway_v3
from backend.secure_session import Handshake


class GatewayV3Tests(unittest.TestCase):
    def setUp(self):
        self.key = SigningKey.generate()
        self.node_id = self.key.verify_key.encode().hex()
        self.state = SimpleNamespace(node_crypto=SimpleNamespace(signing_key=self.key, node_id=self.node_id), node=None)
        self.app = FastAPI()
        self.app.include_router(gateway_v3.router)

    def test_real_asgi_encrypted_status_and_fail_closed_resource_surface(self):
        with patch.object(gateway_v3, "runtime_state", return_value=self.state), TestClient(self.app) as client:
            with client.websocket_connect("/dmp-c/v3") as socket:
                self.assertEqual(socket.receive_json()["type"], "WELCOME")
                handshake = Handshake(SigningKey.generate(), "DEVICE")
                socket.send_json(handshake.initiate())
                auth, session = handshake.finish(socket.receive_json(), self.node_id)
                socket.send_json(auth)
                ready = session.open(socket.receive_json())
                self.assertEqual(ready["capabilities"], ["PING", "STATUS"])
                socket.send_json(session.seal({"type": "STATUS", "request_id": "1"}))
                self.assertEqual(session.open(socket.receive_json())["node_id"], self.node_id)
                socket.send_json(session.seal({"type": "REGISTER_INBOUND_LOCATOR", "locator": "victim"}))
                self.assertEqual(session.open(socket.receive_json())["code"], "UNSUPPORTED_OPERATION")

    def test_node_role_cannot_get_device_capabilities(self):
        with patch.object(gateway_v3, "runtime_state", return_value=self.state), TestClient(self.app) as client:
            with client.websocket_connect("/dmp-c/v3") as socket:
                self.assertEqual(socket.receive_json()["type"], "WELCOME")
                socket.send_json(Handshake(SigningKey.generate(), "NODE").initiate())
                with self.assertRaises(WebSocketDisconnect): socket.receive_json()

    def test_plaintext_operation_after_auth_closes_socket(self):
        with patch.object(gateway_v3, "runtime_state", return_value=self.state), TestClient(self.app) as client:
            with client.websocket_connect("/dmp-c/v3") as socket:
                self.assertEqual(socket.receive_json()["type"], "WELCOME")
                handshake = Handshake(SigningKey.generate(), "DEVICE")
                socket.send_json(handshake.initiate())
                auth, session = handshake.finish(socket.receive_json(), self.node_id)
                socket.send_json(auth)
                session.open(socket.receive_json())
                socket.send_json({"type": "STATUS"})
                with self.assertRaises(WebSocketDisconnect): socket.receive_json()


if __name__ == "__main__": unittest.main()
