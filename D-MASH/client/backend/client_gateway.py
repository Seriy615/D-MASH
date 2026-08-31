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
try:  # Runtime scripts import backend modules as top-level modules.
    from capabilities import allowed_operations
except ModuleNotFoundError:  # Package tests import ``backend.client_gateway``.
    from .capabilities import allowed_operations

router = APIRouter()
PROTOCOL = "DMP-C"
VERSION = 2
LEGACY_VERSION = 1
AUTH_TIMEOUT_SECONDS = 15


def runtime_state():
    """Load runtime state lazily to keep the gateway independent of import order."""
    from core import state
    return state


def auth_transcript(session_id: str, nonce: str) -> bytes:
    """Legacy v1 transcript retained only for explicit compatibility tests."""
    return f"{PROTOCOL}|{LEGACY_VERSION}|AUTH|{session_id}|{nonce}".encode("utf-8")


def device_auth_transcript(node_id: str, session_id: str, server_nonce: str,
                           client_nonce: str, expires_at: int) -> bytes:
    """Canonical DEVICE_AUTH_V1 challenge transcript; all fields are public."""
    fields = (PROTOCOL, str(VERSION), "DEVICE_AUTH_V1", node_id.lower(),
              session_id, server_nonce, client_nonce, str(expires_at))
    return "|".join(fields).encode("utf-8")


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


def verify_device_auth(public_key_hex: str, signature_b64: str, node_id: str,
                       session_id: str, server_nonce: str, client_nonce: str,
                       expires_at: int) -> bool:
    if not isinstance(client_nonce, str) or not 16 <= len(client_nonce) <= 256:
        return False
    try:
        public_key = bytes.fromhex(public_key_hex)
        signature = base64.b64decode(signature_b64, validate=True)
        if len(public_key) != 32 or len(signature) != 64:
            return False
        VerifyKey(public_key).verify(device_auth_transcript(
            node_id, session_id, server_nonce, client_nonce, expires_at
        ), signature)
        return True
    except (ValueError, BadSignatureError):
        return False


@router.websocket("/dmp-c/v1")
async def dmp_client(websocket: WebSocket):
    await websocket.accept()
    state = runtime_state()
    node_id = state.node_crypto.node_id if state.node_crypto else None
    if not node_id:
        await websocket.close(code=1011, reason="node identity unavailable")
        return
    session_id = secrets.token_hex(16)
    nonce = secrets.token_urlsafe(32)
    expires_at = int(time.time()) + AUTH_TIMEOUT_SECONDS
    await websocket.send_json({
        "type": "CHALLENGE",
        "protocol": PROTOCOL,
        "version": VERSION,
        "auth_mode": "DEVICE_AUTH_V1",
        "node_id": node_id,
        "session_id": session_id,
        "nonce": nonce,
        "expires_in": AUTH_TIMEOUT_SECONDS,
        "expires_at": expires_at,
    })
    state = None
    session_locator_handles = set()
    try:
        raw = await asyncio.wait_for(websocket.receive_text(), AUTH_TIMEOUT_SECONDS)
        auth = json.loads(raw)
        if auth.get("type") != "AUTH" or auth.get("auth_mode") != "DEVICE_AUTH_V1" or not verify_device_auth(
            auth.get("public_key", ""), auth.get("signature", ""), node_id,
            session_id, nonce, auth.get("client_nonce", ""), expires_at
        ):
            await websocket.close(code=1008, reason="authentication failed")
            return

        operations = allowed_operations(state)
        await websocket.send_json({
            "type": "AUTH_OK",
            "protocol": PROTOCOL,
            "version": VERSION, "auth_mode": "DEVICE_AUTH_V1",
            "node_id": node_id,
            "server_time": int(time.time()),
            "capabilities": sorted(operations),
        })

        while True:
            request = json.loads(await websocket.receive_text())
            operation = request.get("type")
            request_id = request.get("request_id")
            if operation not in operations:
                await websocket.send_json({"type": "ERROR", "request_id": request_id, "code": "UNSUPPORTED_OPERATION"})
                continue
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
                try:
                    handle = await state.node.transport.register_inbound_locator(locator)
                except Exception:
                    # A storage failure must be visible to the authenticated
                    # client, rather than leaving it to wait for its timeout.
                    # Do not serialize the locator or backend exception.
                    await websocket.send_json({"type": "ERROR", "request_id": request_id, "code": "NODE_OPERATION_FAILED"})
                    continue
                await websocket.send_json({"type": "REGISTER_INBOUND_LOCATOR_RESULT", "request_id": request_id, "locator_handle": handle})
                state.node.transport.attach_local_delivery_session(handle, websocket)
                session_locator_handles.add(handle)
            elif operation == "UNREGISTER_INBOUND_LOCATOR":
                locator = request.get("locator")
                if not isinstance(locator, str) or not locator:
                    await websocket.send_json({"type": "ERROR", "request_id": request_id, "code": "INVALID_LOCATOR"})
                    continue
                try:
                    removed = await state.node.transport.unregister_inbound_locator(locator)
                except Exception:
                    await websocket.send_json({"type": "ERROR", "request_id": request_id, "code": "NODE_OPERATION_FAILED"})
                    continue
                await websocket.send_json({"type": "UNREGISTER_INBOUND_LOCATOR_RESULT", "request_id": request_id, "removed": removed})
            elif operation == "START_PROBE":
                route_locator = request.get("route_locator")
                back_route_locator = request.get("back_route_locator")
                if not isinstance(route_locator, str) or not isinstance(back_route_locator, str) or not route_locator or not back_route_locator:
                    await websocket.send_json({"type": "ERROR", "request_id": request_id, "code": "INVALID_ROUTE_HANDLE"})
                    continue
                try:
                    submission = await state.node.transport.start_probe(
                        route_locator, back_route_locator,
                        hops=request.get("hops", 0), ttl=request.get("ttl", 20),
                    )
                except (PermissionError, ValueError):
                    await websocket.send_json({"type": "ERROR", "request_id": request_id, "code": "NODE_OPERATION_FAILED"})
                    continue
                await websocket.send_json({"type": "START_PROBE_RESULT", "request_id": request_id, **asdict(submission)})
            elif operation == "SUBMIT_ENVELOPE":
                route_locator = request.get("route_locator")
                envelope = request.get("envelope")
                if not isinstance(route_locator, str) or not route_locator or not isinstance(envelope, dict):
                    await websocket.send_json({"type": "ERROR", "request_id": request_id, "code": "INVALID_ENVELOPE"})
                    continue
                try:
                    submission = await state.node.transport.submit_envelope(route_locator, envelope)
                except (PermissionError, ValueError):
                    await websocket.send_json({"type": "ERROR", "request_id": request_id, "code": "NODE_OPERATION_FAILED"})
                    continue
                await websocket.send_json({"type": "SUBMIT_ENVELOPE_RESULT", "request_id": request_id, **asdict(submission)})
            elif operation == "PULL":
                locator_handle = request.get("locator_handle")
                if not isinstance(locator_handle, str) or not locator_handle:
                    await websocket.send_json({"type": "ERROR", "request_id": request_id, "code": "INVALID_LOCATOR_HANDLE"})
                    continue
                if locator_handle not in session_locator_handles:
                    await websocket.send_json({"type": "ERROR", "request_id": request_id, "code": "LOCATOR_NOT_REGISTERED"})
                    continue
                packets = await state.node.transport.pull(locator_handle)
                await websocket.send_json({"type": "PULL_RESULT", "request_id": request_id, "packets": packets})
            elif operation == "ACK":
                delivery_id = request.get("delivery_id")
                if not isinstance(delivery_id, str) or not delivery_id:
                    await websocket.send_json({"type": "ERROR", "request_id": request_id, "code": "INVALID_DELIVERY_ID"})
                    continue
                acknowledged = await state.node.transport.ack(
                    delivery_id, allowed_locator_handles=session_locator_handles,
                )
                await websocket.send_json({"type": "ACK_RESULT", "request_id": request_id, "acknowledged": acknowledged})
            else:
                await websocket.send_json({"type": "ERROR", "request_id": request_id, "code": "UNSUPPORTED_OPERATION"})
    except (WebSocketDisconnect, TimeoutError, json.JSONDecodeError):
        return
    finally:
        if state and state.node:
            state.node.transport.detach_local_delivery_session(websocket)
