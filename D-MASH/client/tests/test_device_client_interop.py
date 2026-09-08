import asyncio
import pathlib
import socket
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import uvicorn
from fastapi import FastAPI
from nacl.signing import SigningKey

from backend import gateway_v3


class DeviceClientInteropTests(unittest.IsolatedAsyncioTestCase):
    async def test_browser_client_over_real_websocket(self):
        key = SigningKey.generate()
        node_id = key.verify_key.encode().hex()
        state = SimpleNamespace(node_crypto=SimpleNamespace(signing_key=key, node_id=node_id), node=None)
        app = FastAPI()
        app.include_router(gateway_v3.router)
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        server = uvicorn.Server(uvicorn.Config(app, log_level='critical', lifespan='off'))
        with patch.object(gateway_v3, 'runtime_state', return_value=state):
            task = asyncio.create_task(server.serve(sockets=[listener]))
            try:
                async with asyncio.timeout(5):
                    while not server.started:
                        await asyncio.sleep(0.01)
                proc = await asyncio.create_subprocess_exec(
                    'node', str(pathlib.Path(__file__).with_name('device_client_peer.cjs')),
                    f'ws://127.0.0.1:{listener.getsockname()[1]}/dmp-c/v3', node_id,
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                try:
                    output, errors = await asyncio.wait_for(proc.communicate(), 20)
                except BaseException:
                    proc.kill()
                    await proc.wait()
                    raise
                self.assertEqual(proc.returncode, 0, (output + errors).decode())
            finally:
                server.should_exit = True
                await asyncio.wait_for(task, 5)
                listener.close()
