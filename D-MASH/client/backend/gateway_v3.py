"""DMP-C v3 endpoint; capability surface expands only with implemented gates."""
import asyncio

from fastapi import APIRouter, WebSocket

if __package__:
    from .secure_socket import accept_secure
else:
    from secure_socket import accept_secure

router = APIRouter()


def runtime_state():
    if __package__:
        from .core import state
    else:
        from core import state
    return state


@router.websocket("/dmp-c/v3")
async def dmp_v3(websocket: WebSocket):
    await websocket.accept()
    secure = None
    try:
        state = runtime_state()
        if not state.node_crypto or not state.node_crypto.signing_key:
            await websocket.close(code=1011, reason="node identity unavailable")
            return
        secure, device_key = await accept_secure(websocket, state.node_crypto.signing_key, "DEVICE")
        # No resource operations until DNSS/password/authority integration is
        # complete. In particular a NODE hello never inherits this surface.
        await secure.send_json({"type": "AUTH_OK", "version": 3,
                                "role": "DEVICE", "capabilities": ["PING", "STATUS"]})
        while True:
            request = await secure.receive_json()
            request_id = request.get("request_id")
            if request.get("type") == "PING":
                response = {"type": "PONG", "request_id": request_id}
            elif request.get("type") == "STATUS":
                response = {"type": "STATUS", "request_id": request_id,
                            "node_id": state.node_crypto.node_id,
                            "mesh_peers": len(state.node.active_connections) if state.node else 0}
            else:
                response = {"type": "ERROR", "request_id": request_id, "code": "UNSUPPORTED_OPERATION"}
            await secure.send_json(response)
    except asyncio.CancelledError:
        raise
    except Exception:
        # No untrusted packet fields, signatures, or keys in logs/close text.
        try: await websocket.close(code=1008, reason="v3 session ended")
        except Exception: pass
    finally:
        if secure: secure.session.close()
