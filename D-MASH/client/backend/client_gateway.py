"""Minimal authenticated DMP-C client gateway.

User authentication is local to the client↔entry-node boundary. The user key
is never copied into mesh forwarding headers.
"""

import base64
import asyncio
import json
import secrets
import time
from dataclasses import asdict

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
            "capabilities": [
                "PING", "STATUS", "REGISTER_INBOUND_LOCATOR", "START_PROBE",
                "SUBMIT_ENVELOPE", "PULL", "ACK",
            ],
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
            elif operation == "REGISTER_INBOUND_LOCATOR":
                locator = request.get("locator")
                if not isinstance(locator, str) or not locator:
                    await websocket.send_json({"type": "ERROR", "request_id": request_id, "code": "INVALID_LOCATOR"})
                    continue
                handle = await state.node.transport.register_inbound_locator(locator)
                await websocket.send_json({"type": "REGISTER_INBOUND_LOCATOR_RESULT", "request_id": request_id, "locator_handle": handle})
            elif operation == "START_PROBE":
                route_locator = request.get("route_locator")
                back_route_locator = request.get("back_route_locator")
                if not isinstance(route_locator, str) or not isinstance(back_route_locator, str) or not route_locator or not back_route_locator:
                    await websocket.send_json({"type": "ERROR", "request_id": request_id, "code": "INVALID_ROUTE_HANDLE"})
                    continue
                submission = await state.node.transport.start_probe(
                    route_locator, back_route_locator,
                    hops=request.get("hops", 0), ttl=request.get("ttl", 20),
                )
                await websocket.send_json({"type": "START_PROBE_RESULT", "request_id": request_id, **asdict(submission)})
            elif operation == "SUBMIT_ENVELOPE":
                route_locator = request.get("route_locator")
                envelope = request.get("envelope")
                if not isinstance(route_locator, str) or not route_locator or not isinstance(envelope, dict):
                    await websocket.send_json({"type": "ERROR", "request_id": request_id, "code": "INVALID_ENVELOPE"})
                    continue
                submission = await state.node.transport.submit_envelope(route_locator, envelope)
                await websocket.send_json({"type": "SUBMIT_ENVELOPE_RESULT", "request_id": request_id, **asdict(submission)})
            elif operation == "PULL":
                locator_handle = request.get("locator_handle")
                if not isinstance(locator_handle, str) or not locator_handle:
                    await websocket.send_json({"type": "ERROR", "request_id": request_id, "code": "INVALID_LOCATOR_HANDLE"})
                    continue
                packets = await state.node.transport.pull(locator_handle)
                await websocket.send_json({"type": "PULL_RESULT", "request_id": request_id, "packets": packets})
            elif operation == "ACK":
                delivery_id = request.get("delivery_id")
                if not isinstance(delivery_id, str) or not delivery_id:
                    await websocket.send_json({"type": "ERROR", "request_id": request_id, "code": "INVALID_DELIVERY_ID"})
                    continue
                acknowledged = await state.node.transport.ack(delivery_id)
                await websocket.send_json({"type": "ACK_RESULT", "request_id": request_id, "acknowledged": acknowledged})
            else:
                await websocket.send_json({"type": "ERROR", "request_id": request_id, "code": "UNSUPPORTED_OPERATION"})
    except (WebSocketDisconnect, TimeoutError, json.JSONDecodeError):
        return
