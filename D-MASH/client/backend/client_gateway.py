"""Minimal authenticated DMP-C client gateway.

User authentication is local to the client↔entry-node boundary. The user key
is never copied into mesh forwarding headers.
"""

import base64
import asyncio
import json
import secrets
import time

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

router = APIRouter()
PROTOCOL = "DMP-C"
VERSION = 1
AUTH_TIMEOUT_SECONDS = 15


def runtime_state():
    """Load runtime state lazily to keep the gateway independent of import order."""
    from core import state
    return state


def auth_transcript(session_id: str, nonce: str) -> bytes:
    return f"{PROTOCOL}|{VERSION}|AUTH|{session_id}|{nonce}".encode("utf-8")


def verify_auth(public_key_hex: str, signature_b64: str, session_id: str, nonce: str) -> bool:
    try:
        public_key = bytes.fromhex(public_key_hex)
        signature = base64.b64decode(signature_b64, validate=True)
        if len(public_key) != 32 or len(signature) != 64:
            return False
        VerifyKey(public_key).verify(auth_transcript(session_id, nonce), signature)
        return True
    except (ValueError, BadSignatureError):
        return False


@router.websocket("/dmp-c/v1")
async def dmp_client(websocket: WebSocket):
    await websocket.accept()
    session_id = secrets.token_hex(16)
    nonce = secrets.token_urlsafe(32)
    await websocket.send_json({
        "type": "CHALLENGE",
        "protocol": PROTOCOL,
        "version": VERSION,
        "session_id": session_id,
        "nonce": nonce,
        "expires_in": AUTH_TIMEOUT_SECONDS,
    })
    try:
        raw = await asyncio.wait_for(websocket.receive_text(), AUTH_TIMEOUT_SECONDS)
        auth = json.loads(raw)
        if auth.get("type") != "AUTH" or not verify_auth(
            auth.get("public_key", ""), auth.get("signature", ""), session_id, nonce
        ):
            await websocket.close(code=1008, reason="authentication failed")
            return

        state = runtime_state()
        await websocket.send_json({
            "type": "AUTH_OK",
            "protocol": PROTOCOL,
            "version": VERSION,
            "node_id": state.node_crypto.node_id if state.node_crypto else None,
            "server_time": int(time.time()),
            "capabilities": ["PING", "STATUS"],
        })

        while True:
            request = json.loads(await websocket.receive_text())
            operation = request.get("type")
            request_id = request.get("request_id")
            if operation == "PING":
                await websocket.send_json({"type": "PONG", "request_id": request_id})
            elif operation == "STATUS":
                await websocket.send_json({
                    "type": "STATUS",
                    "request_id": request_id,
                    "node_id": state.node_crypto.node_id if state.node_crypto else None,
                    "mesh_peers": len(state.node.active_connections) if state.node else 0,
                })
            else:
                await websocket.send_json({"type": "ERROR", "request_id": request_id, "code": "UNSUPPORTED_OPERATION"})
    except (WebSocketDisconnect, TimeoutError, json.JSONDecodeError):
        return
