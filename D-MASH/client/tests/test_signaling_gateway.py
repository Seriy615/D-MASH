import unittest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect
from backend.signaling_gateway import router
from backend.s_turn import STurnService


class SignalingGatewayTests(unittest.TestCase):
    def test_ticket_join_bidirectional_relay_and_replay_rejection(self):
        app = FastAPI()
        app.include_router(router)
        service = STurnService(signaling_wss='wss://example.test/signal/v1',
                               turn_urls=('turn:example.test:3478',), health_probe=lambda: True)
        app.state.s_turn_service = service
        session = service.create_session('c' * 32, b'k' * 32)
        def join(role):
            return {'type': 'JOIN', 'session_id': session['session_id'],
                    'ticket': session[role + '_ticket'], 'role': role}
        with TestClient(app) as client:
            with client.websocket_connect('/signal/v1') as caller:
                caller.send_json(join('caller'))
                self.assertEqual(caller.receive_json(), {'type': 'JOINED'})
                caller.send_json({'type': 'offer', 'payload': 'opaque-offer'})
                with client.websocket_connect('/signal/v1') as callee:
                    callee.send_json(join('callee'))
                    self.assertEqual(callee.receive_json(), {'type': 'JOINED'})
                    self.assertEqual(callee.receive_json(), {'type': 'offer', 'payload': 'opaque-offer'})
                    callee.send_json({'type': 'answer', 'payload': 'opaque-answer'})
                    self.assertEqual(caller.receive_json(), {'type': 'answer', 'payload': 'opaque-answer'})
                    with client.websocket_connect('/signal/v1') as replay:
                        replay.send_json(join('caller'))
                        with self.assertRaises(WebSocketDisconnect): replay.receive_json()
                    caller.send_json({'type': 'ice', 'payload': 'candidate'})
                    self.assertEqual(callee.receive_json(), {'type': 'ice', 'payload': 'candidate'})
        self.assertFalse(service._sessions)

    def test_unconfigured_endpoint_fails_closed(self):
        app = FastAPI()
        app.include_router(router)
        with TestClient(app) as client:
            with self.assertRaises(WebSocketDisconnect):
                with client.websocket_connect('/signal/v1'): pass
