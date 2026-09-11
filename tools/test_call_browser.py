#!/usr/bin/env python3
"""Local Chrome audio acceptance. No deployment or production credentials.

Set DMASH_PLAYWRIGHT_MODULE to an installed playwright package when it is not
on Node's module search path. Set DMASH_CHROME for a non-default Chrome binary.
"""
import pathlib
import socket
import subprocess
import sys
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'D-MASH/client'))
import uvicorn
from fastapi import FastAPI, WebSocket
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from backend.s_turn import STurnService
from backend.signaling_gateway import serve_signaling


def main():
    app = FastAPI()
    service = STurnService(signaling_wss='wss://local-test.invalid/signal/v1',
                           turn_urls=('turn:127.0.0.1:9',), health_probe=lambda: True)
    @app.websocket('/signal/v1')
    async def signaling(ws: WebSocket):
        await serve_signaling(ws, service, admission_difficulty=4)
    @app.get('/')
    async def page():
        return HTMLResponse('<!doctype html><title>Local call acceptance</title>')
    app.mount('/js', StaticFiles(directory=ROOT / 'D-MASH PWA/not_messenger/js'))
    server = uvicorn.Server(uvicorn.Config(app, log_level='critical', lifespan='off'))
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
        thread = threading.Thread(target=server.run, kwargs={'sockets': [listener]}, daemon=True)
        thread.start()
        try:
            deadline = time.monotonic() + 5
            while not server.started and time.monotonic() < deadline: time.sleep(.01)
            if not server.started: raise RuntimeError('Local server did not start')
            return subprocess.run(['node', str(ROOT / 'tools/test_call_browser.cjs'),
                                   f'http://127.0.0.1:{port}'], timeout=90).returncode
        finally:
            server.should_exit = True
            thread.join(5)
            service.close()


if __name__ == '__main__':
    raise SystemExit(main())
