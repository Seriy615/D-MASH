"""Exercise the shipped browser adapter over real TCP/WebSockets."""
import pathlib
import shutil
import socket
import subprocess
import threading
import time
import unittest

import uvicorn
from fastapi import FastAPI, WebSocket
from backend.signaling_gateway import serve_signaling
from backend.s_turn import STurnService


class SignalingClientTests(unittest.TestCase):
    def test_javascript_client_offer_answer_ice_and_hangup(self):
        self.assertIsNotNone(shutil.which('node'), 'Node.js required for PWA integration')
        service = STurnService(signaling_wss='wss://example.test/signal/v1',
                               turn_urls=('turn:example.test:3478',), health_probe=lambda: True)
        app = FastAPI()
        @app.websocket('/signal/v1')
        async def endpoint(websocket: WebSocket):
            await serve_signaling(websocket, service, admission_difficulty=4)
        server = uvicorn.Server(uvicorn.Config(app, log_level='critical', lifespan='off'))
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
            thread = threading.Thread(target=server.run, kwargs={'sockets': [listener]}, daemon=True)
            thread.start()
            try:
                deadline = time.monotonic() + 5
                while not server.started and time.monotonic() < deadline:
                    time.sleep(.01)
                self.assertTrue(server.started)
                root = pathlib.Path(__file__).resolve().parents[3]
                script = root / 'D-MASH PWA/not_messenger/tests/signaling_client.integration.js'
                result = subprocess.run(['node', str(script), f'ws://127.0.0.1:{port}/signal/v1'],
                                        capture_output=True, text=True, timeout=20)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            finally:
                server.should_exit = True
                thread.join(5)
                self.assertFalse(thread.is_alive())
                service.close()
