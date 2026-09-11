import unittest
import hashlib
from fastapi import FastAPI, WebSocket
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect
from backend.signaling_gateway import router, serve_signaling
from backend.s_turn import STurnService


class SignalingGatewayTests(unittest.TestCase):
    def admitted_app(self):
        app = FastAPI()
        service = STurnService(signaling_wss='wss://example.test/signal/v1',
                               turn_urls=('turn:example.test:3478',), health_probe=lambda: True)
        @app.websocket('/signal/v1')
        async def endpoint(websocket: WebSocket):
            await serve_signaling(websocket, service, admission_difficulty=4)
        return app, service

    def create(self, ws, *, valid=True):
        ws.send_json({'type': 'CREATE', 'call_id': 'a' * 64, 'secret_verifier': 'b' * 64})
        challenge = ws.receive_json()
        self.assertEqual(challenge['type'], 'CHALLENGE')
        counter = 0
        while True:
            digest = hashlib.sha256(f"{challenge['nonce']}:{'a' * 64}:{'b' * 64}:{counter}".encode()).digest()
            if (int.from_bytes(digest, 'big') < 1 << (256 - challenge['difficulty'])) == valid:
                break
            counter += 1
        ws.send_json({'type': 'PROOF', 'counter': counter})
        return ws.receive_json()

    def test_anonymous_creation_join_and_exchange(self):
        app, service = self.admitted_app()
        with TestClient(app) as client:
            with client.websocket_connect('/signal/v1') as caller:
                session = self.create(caller)
                self.assertEqual(session['type'], 'CREATED')
                self.assertEqual(len(service._sessions), 1)
                caller.send_json({'type': 'JOIN', 'session_id': session['session_id'],
                                  'ticket': session['caller_ticket'], 'role': 'caller'})
                credentials = caller.receive_json()['ice_servers'][0]
                self.assertEqual(credentials['urls'], ['turn:example.test:3478'])
                self.assertNotIn('a' * 64, credentials['username'])
                caller.send_json({'type': 'offer', 'payload': 'queued'})
                with client.websocket_connect('/signal/v1') as callee:
                    callee.send_json({'type': 'JOIN', 'session_id': session['session_id'],
                                      'ticket': session['callee_ticket'], 'role': 'callee'})
                    self.assertEqual(callee.receive_json()['type'], 'JOINED')
                    self.assertEqual(callee.receive_json()['payload'], 'queued')
                    callee.send_json({'type': 'answer', 'payload': 'reply'})
                    self.assertEqual(caller.receive_json()['payload'], 'reply')
        self.assertFalse(service._sessions)

    def test_invalid_work_allocates_no_session(self):
        app, service = self.admitted_app()
        with TestClient(app) as client:
            with client.websocket_connect('/signal/v1') as ws:
                with self.assertRaises(WebSocketDisconnect): self.create(ws, valid=False)
        self.assertFalse(service._sessions)

    def test_abandoned_creation_is_removed(self):
        app, service = self.admitted_app()
        with TestClient(app) as client:
            with client.websocket_connect('/signal/v1') as ws:
                self.create(ws)
                self.assertEqual(len(service._sessions), 1)
        self.assertFalse(service._sessions)

    def test_creator_cannot_consume_recipient_ticket(self):
        app, service = self.admitted_app()
        with TestClient(app) as client:
            with client.websocket_connect('/signal/v1') as ws:
                session = self.create(ws)
                ws.send_json({'type': 'JOIN', 'session_id': session['session_id'],
                              'ticket': session['callee_ticket'], 'role': 'callee'})
                with self.assertRaises(WebSocketDisconnect): ws.receive_json()
        self.assertFalse(service._sessions)

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
                self.assertEqual(caller.receive_json()['type'], 'JOINED')
                caller.send_json({'type': 'offer', 'payload': 'opaque-offer'})
                with client.websocket_connect('/signal/v1') as callee:
                    callee.send_json(join('callee'))
                    self.assertEqual(callee.receive_json()['type'], 'JOINED')
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
