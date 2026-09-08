"""DMP-C v3 endpoint; capability surface expands only with implemented gates."""
import asyncio
import base64

from fastapi import APIRouter, WebSocket

if __package__:
    from .secure_socket import accept_secure
    from .device_registration import DeviceSession, RegistrationError
    from .dnss_mailbox import MailboxError
else:
    from secure_socket import accept_secure
    from device_registration import DeviceSession, RegistrationError
    from dnss_mailbox import MailboxError

router = APIRouter()


def operations(state):
    surface = ["PING", "STATUS"]
    if (getattr(state, "device_registration", None) is not None
            and getattr(state, "dnss_mailbox", None) is not None
            and getattr(getattr(state, "capabilities", None), "can_accept_devices", False)):
        surface += ["REGISTER_DNSS", "PULL"]
        if state.capabilities.can_route:
            surface += ["REGISTER_ROUTE", "UNREGISTER_ROUTE", "START_PROBE", "ROUTE_STATUS", "SUBMIT"]
    return surface


async def resource_operation(state, secure, session, request):
    registry = state.device_registration
    op, rid = request.get("type"), request.get("request_id")
    if op == "REGISTER_DNSS":
        registry.bind_dnss(session, request.get("dnss"), request.get("pow"))
        return {"type": "REGISTER_DNSS_RESULT", "request_id": rid}
    alias = registry.require_dnss(session)
    if op == "PULL":
        if set(request) - {"type", "request_id"}:
            raise RegistrationError("PULL_HAS_NO_QUEUE_SELECTOR")
        await state.dnss_mailbox.drain(alias, secure.send_json, rid)
        return None
    transport = state.node.transport
    if op in {"REGISTER_ROUTE", "UNREGISTER_ROUTE", "START_PROBE"}:
        auth = request.get("authorization")
        if not isinstance(auth, dict): raise RegistrationError("INVALID_ROUTE_AUTHORITY")
        if op == "START_PROBE" and request.get("back_route_locator") != auth.get("route_id"):
            raise RegistrationError("PROBE_ORIGIN_MISMATCH")
        registry.authorize_route(session, op, rid, auth, grant=request.get("entry_grant"), proof=request.get("pow"))
        if op == "REGISTER_ROUTE":
            handle = await transport.register_inbound_locator(auth["route_id"], blind_dnss=alias)
            transport.attach_local_delivery_session(handle, secure)
            return {"type": "REGISTER_ROUTE_RESULT", "request_id": rid}
        if op == "UNREGISTER_ROUTE":
            await transport.unregister_inbound_locator(auth["route_id"])
            return {"type": "UNREGISTER_ROUTE_RESULT", "request_id": rid}
        result = await transport.start_probe(request.get("route_locator"), auth["route_id"], ttl=15)
        # Do not echo the transient probe packet or topology in the response.
        return {"type": "START_PROBE_RESULT", "request_id": rid, "state": result.state}
    if op == "ROUTE_STATUS":
        return {"type": "ROUTE_STATUS_RESULT", "request_id": rid, **await transport.route_status(request.get("route_locator"))}
    if op == "SUBMIT":
        ciphertext = request.get("ciphertext")
        # Validate size and canonical ciphertext before any route/outbox work.
        if not isinstance(ciphertext, str) or not 1 <= len(ciphertext) <= 64 * 1024:
            raise RegistrationError("CIPHERTEXT_LIMIT")
        try:
            raw = base64.b64decode(ciphertext, validate=True)
            if base64.b64encode(raw).decode() != ciphertext: raise ValueError()
        except Exception as error: raise RegistrationError("INVALID_CIPHERTEXT") from error
        result = await transport.submit_envelope(request.get("route_locator"), {"version": 1, "ciphertext": ciphertext})
        return {"type": "SUBMIT_RESULT", "request_id": rid, "state": result.state, "delivery_id": result.delivery_id}
    raise RegistrationError("UNSUPPORTED_OPERATION")


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
        session = DeviceSession(device_key, secure.session.transcript_hash.hex())
        surface = operations(state)
        await secure.send_json({"type": "AUTH_OK", "version": 3,
                                "role": "DEVICE", "capabilities": surface})
        while True:
            request = await secure.receive_json()
            request_id = request.get("request_id")
            if request.get("type") == "PING":
                response = {"type": "PONG", "request_id": request_id}
            elif request.get("type") == "STATUS":
                response = {"type": "STATUS", "request_id": request_id,
                            "node_id": state.node_crypto.node_id,
                            "mesh_peers": len(state.node.active_connections) if state.node else 0}
            elif request.get("type") in surface:
                try:
                    response = await resource_operation(state, secure, session, request)
                except (RegistrationError, MailboxError) as error:
                    response = {"type": "ERROR", "request_id": request_id, "code": str(error)}
                except (ValueError, TypeError):
                    response = {"type": "ERROR", "request_id": request_id, "code": "INVALID_REQUEST"}
            else:
                response = {"type": "ERROR", "request_id": request_id, "code": "UNSUPPORTED_OPERATION"}
            if response is not None: await secure.send_json(response)
    except asyncio.CancelledError:
        raise
    except Exception:
        # No untrusted packet fields, signatures, or keys in logs/close text.
        try: await websocket.close(code=1008, reason="v3 session ended")
        except Exception: pass
    finally:
        if secure: secure.session.close()
        if secure and getattr(state, "node", None):
            state.node.transport.detach_local_delivery_session(secure)
