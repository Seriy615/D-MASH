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
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey
try:  # Runtime scripts import backend modules as top-level modules.
    from capabilities import allowed_operations
except ModuleNotFoundError:  # Package tests import ``backend.client_gateway``.
    from .capabilities import allowed_operations
try:  # Isolated routing primitives have no runtime-state dependencies.
    from dnss import node_blind_hash
    from entry_grant import EntryGrantV1
except ModuleNotFoundError:
    from .dnss import node_blind_hash
    from .entry_grant import EntryGrantV1
try:
    from resource_pow import (verify_activation_pow, activation_pow_difficulty,
                              MAX_ACTIVATION_VALIDITY_SECONDS)
except ModuleNotFoundError:
    from .resource_pow import (verify_activation_pow, activation_pow_difficulty,
                               MAX_ACTIVATION_VALIDITY_SECONDS)

router = APIRouter()
PROTOCOL = "DMP-C"
VERSION = 2
LEGACY_VERSION = 1
AUTH_TIMEOUT_SECONDS = 15
ACTIVATION_POW_DIFFICULTY = activation_pow_difficulty()
ACTIVATION_POW_REPLAY_CAPACITY = 4096
# key -> proof expiry.  Expiry is also the natural pruning timestamp.
_USED_ACTIVATION_POW: dict[tuple[str, str, str, int, int], int] = {}

# The application lifecycle owns the registry's database and close policy.  It
# injects this factory at startup with ``factory(node_crypto) ->
# RegistrationRegistry``.  Do not infer a path from the async system database:
# opening another synchronous SQLite connection to it here would create an
# uncoordinated durability/locking boundary.  Keeping the seam explicit also
# makes a gateway-only deployment fail closed rather than silently using an
# ephemeral registry.
registration_registry_factory = None


def _registration_registry_available() -> bool:
    return callable(registration_registry_factory)


def _decode_dnss(value: str) -> bytes:
    """Decode a previously wire-validated DNSS without retaining its wire form."""
    if len(value) == 32:
        return bytes.fromhex(value)
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _routing_registration_operations(state, operations):
    """Add registration only alongside the already implemented route surface.

    Capability flags are deliberately not treated as a protocol grant: a
    partially initialized state, or a node that only advertises PING/STATUS,
    must not expose route-registration operations.
    """
    if ("START_PROBE" in operations and "ROUTE_STATUS" in operations and
            getattr(state, "node", None) and
            getattr(state.node, "transport", None) and
            _registration_registry_available()):
        return frozenset(operations) | {"REGISTER_DNSS", "REGISTER_ENTRY_GRANT"}
    return frozenset(operations)


def _valid_dnss(value: Any) -> bool:
    """Accept the wire forms emitted by DNSS primitives, but never store raw data."""
    if not isinstance(value, str) or not value or len(value) > 256:
        return False
    try:
        if len(value) == 32:
            return len(bytes.fromhex(value)) == 16
        return len(base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))) == 16
    except (ValueError, TypeError, base64.binascii.Error):
        return False


def _canonical_node_id(value: Any) -> str | None:
    """Return the lowercase hex NodeID for trusted runtime identity material.

    NodeCrypto normally exposes its Ed25519 public key as lowercase hex, while
    small embedders and older launchers can expose the raw 32-byte key.  The
    protocol always signs and verifies the hex wire form, so normalize only
    those two unambiguous representations at this boundary.
    """
    if isinstance(value, str):
        candidate = value
    elif isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
        if len(raw) == 32:
            return raw.hex()
        try:
            candidate = raw.decode("ascii")
        except UnicodeDecodeError:
            return None
    else:
        return None
    if len(candidate) != 64:
        return None
    try:
        bytes.fromhex(candidate)
    except ValueError:
        return None
    return candidate.lower()


def _entry_grant_wire_value(value: Any) -> Any:
    """Decode byte-like JSON field values without accepting binary wire data.

    A WebSocket JSON message contains text, but direct ASGI integrations may
    have decoded JSON fields into bytes.  Accept only strict ASCII equivalents
    of the canonical textual grant fields; EntryGrantV1 still owns schema,
    signature, expiry, and node-binding validation.
    """
    if not isinstance(value, dict):
        return value
    decoded = {}
    for key, field in value.items():
        if isinstance(key, (bytes, bytearray, memoryview)):
            try:
                key = bytes(key).decode("ascii")
            except UnicodeDecodeError:
                return value
        if isinstance(field, (bytes, bytearray, memoryview)):
            try:
                field = bytes(field).decode("ascii")
            except UnicodeDecodeError:
                return value
        decoded[key] = field
    return decoded


def _verify_entry_grant(value, node_id: str):
    """Verify a self-contained EntryGrantV1 without accepting Account material."""
    try:
        value = _entry_grant_wire_value(value)
        grant = EntryGrantV1.from_dict(value) if isinstance(value, dict) else EntryGrantV1.from_json(value)
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    return grant if grant.verify(expected_node_id=node_id) else None


def _activation_pow_ok(request: dict, node_id: str, device_key: str,
                       activation_type: str, resource: bytes | str) -> bool:
    """Check and consume a node/device/type/resource-bound activation proof."""
    proof = request.get("pow")
    if not isinstance(proof, dict):
        return False
    try:
        canonical_resource = resource.hex() if isinstance(resource, bytes) else resource
        if (proof.get("v") != 1 or proof.get("type") != activation_type or
                proof.get("resource") != canonical_resource or
                not isinstance(proof.get("digest"), str)):
            return False
        nonce, expires_at = proof["nonce"], proof["expires_at"]
        difficulty = proof.get("difficulty", ACTIVATION_POW_DIFFICULTY)
        if (not isinstance(difficulty, int) or difficulty < ACTIVATION_POW_DIFFICULTY or
                difficulty > 24):
            return False
        digest = proof["digest"]
        if not verify_activation_pow(node_id, activation_type, device_key, resource,
                                     nonce, expires_at, difficulty, digest):
            return False
        now = int(time.time())
        # Prune expired entries on every validation and enforce a hard cap even
        # when an attacker submits many distinct, still-live proofs.
        for key, expiry in list(_USED_ACTIVATION_POW.items()):
            if expiry <= now:
                del _USED_ACTIVATION_POW[key]
        # Normalize hex versus bytes representations so wire encoding changes
        # cannot evade replay detection for the same validated proof.
        digest_id = bytes.fromhex(digest).hex() if isinstance(digest, str) else bytes(digest).hex()
        replay_key = (node_id, activation_type, digest_id, nonce, expires_at)
        if replay_key in _USED_ACTIVATION_POW:
            return False
        if len(_USED_ACTIVATION_POW) >= ACTIVATION_POW_REPLAY_CAPACITY:
            # Never evict a live proof: doing so would make that proof
            # replayable if it were submitted again before expiry.  The cache
            # is intentionally fail-closed under sustained distinct-proof
            # pressure; expired entries were pruned above.
            return False
        _USED_ACTIVATION_POW[replay_key] = expires_at
        return True
    except (KeyError, TypeError, ValueError):
        return False


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
    node_id = _canonical_node_id(state.node_crypto.node_id) if state.node_crypto else None
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
    # Keep the runtime state for the authenticated operation loop below.  The
    # challenge itself exposes only `node_id`; clearing this reference here
    # makes the PWA's immediate STATUS request crash the gateway after AUTH_OK.
    session_locator_handles = set()
    registration_registry = None
    try:
        raw = await asyncio.wait_for(websocket.receive_text(), AUTH_TIMEOUT_SECONDS)
        auth = json.loads(raw)
        if auth.get("type") != "AUTH" or auth.get("auth_mode") != "DEVICE_AUTH_V1" or not verify_device_auth(
            auth.get("public_key", ""), auth.get("signature", ""), node_id,
            session_id, nonce, auth.get("client_nonce", ""), expires_at
        ):
            await websocket.close(code=1008, reason="authentication failed")
            return
        device_transport_key = auth.get("public_key")

        operations = _routing_registration_operations(state, allowed_operations(state))
        # Registration state is intentionally scoped to this authenticated
        # session. A registry receives a DNSS only after both it and its grant
        # validate. Until then, the raw 16 bytes are held only in this coroutine.
        pending_dnss = None
        pending_grant = None

        def get_registration_registry():
            nonlocal registration_registry
            if registration_registry is None:
                registration_registry = registration_registry_factory(state.node_crypto)
            return registration_registry
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
            elif operation == "REGISTER_DNSS":
                dnss = request.get("dnss")
                if not _valid_dnss(dnss):
                    await websocket.send_json({"type": "ERROR", "request_id": request_id, "code": "INVALID_DNSS"})
                    continue
                # The raw value never crosses into storage by itself.  It is
                # retained in this session only until a verified grant arrives.
                pending_dnss = _decode_dnss(dnss)
                # An existing DNSS by itself is not an activation.  A following
                # changed grant is checked below; only an exact registered pair
                # is allowed to repeat without new work.
                try:
                    existing_record = get_registration_registry().lookup(pending_dnss)
                    already_registered = existing_record is not None and pending_grant is None
                except Exception:
                    existing_record = None
                    already_registered = False
                if not already_registered and not _activation_pow_ok(
                        request, node_id, device_transport_key, "DNSS", pending_dnss):
                    pending_dnss = None
                    await websocket.send_json({"type": "ERROR", "request_id": request_id, "code": "INVALID_RESOURCE_POW"})
                    continue
                try:
                    dnss_handle = node_blind_hash(node_id, state.node_crypto.secret_salt, pending_dnss)
                except Exception:
                    pending_dnss = None
                    await websocket.send_json({"type": "ERROR", "request_id": request_id, "code": "REGISTRATION_FAILED"})
                    continue
                await websocket.send_json({
                    "type": "REGISTER_DNSS_RESULT", "request_id": request_id,
                    "dnss_handle": dnss_handle,
                })
                if pending_grant is not None:
                    try:
                        get_registration_registry().register(pending_dnss, pending_grant.to_dict())
                    except Exception:
                        await websocket.send_json({"type": "ERROR", "request_id": request_id, "code": "REGISTRATION_FAILED"})
                        continue
                    pending_dnss = pending_grant = None
            elif operation == "REGISTER_ENTRY_GRANT":
                grant = _verify_entry_grant(request.get("entry_grant"), node_id)
                if grant is None:
                    await websocket.send_json({"type": "ERROR", "request_id": request_id, "code": "INVALID_ENTRY_GRANT"})
                    continue
                # A DNSS may already exist with a different grant: compare the
                # signed grant itself, not just DNSS presence.  Only an exact
                # repeat of a validated registration is idempotent without PoW.
                # The route id is the canonical work resource.
                already_registered = False
                existing_record = None
                if pending_dnss is not None:
                    try:
                        existing_record = get_registration_registry().lookup(pending_dnss)
                        already_registered = (existing_record is not None and
                            existing_record.grant.to_dict() == grant.to_dict())
                    except Exception:
                        already_registered = False
                if not already_registered and not _activation_pow_ok(
                        request, node_id, device_transport_key, "ENTRY_GRANT", grant.route_id):
                    await websocket.send_json({"type": "ERROR", "request_id": request_id, "code": "INVALID_RESOURCE_POW"})
                    continue
                pending_grant = grant
                if pending_dnss is not None:
                    try:
                        get_registration_registry().register(pending_dnss, pending_grant.to_dict())
                    except Exception:
                        await websocket.send_json({"type": "ERROR", "request_id": request_id, "code": "REGISTRATION_FAILED"})
                        continue
                    pending_dnss = pending_grant = None
                await websocket.send_json({
                    "type": "REGISTER_ENTRY_GRANT_RESULT", "request_id": request_id,
                    "route_id": grant.route_id, "expires_at": grant.expires_at,
                })
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
            elif operation == "REGISTER_NOTIFICATION_BEACON":
                beacon_handle = request.get("beacon_handle")
                try:
                    alias = await state.node.transport.register_notification_beacon(beacon_handle)
                    await websocket.send_json({"type": "REGISTER_NOTIFICATION_BEACON_RESULT", "request_id": request_id, "beacon_alias": alias})
                except Exception:
                    await websocket.send_json({"type": "ERROR", "request_id": request_id, "code": "NODE_OPERATION_FAILED"})
            elif operation == "UNREGISTER_NOTIFICATION_BEACON":
                beacon_handle = request.get("beacon_handle")
                try:
                    removed = await state.node.transport.unregister_notification_beacon(beacon_handle)
                    await websocket.send_json({"type": "UNREGISTER_NOTIFICATION_BEACON_RESULT", "request_id": request_id, "removed": removed})
                except Exception:
                    await websocket.send_json({"type": "ERROR", "request_id": request_id, "code": "NODE_OPERATION_FAILED"})
            elif operation == "BIND_LOCATOR_NOTIFICATION_BEACON":
                locator, beacon_handle = request.get("locator"), request.get("beacon_handle")
                try:
                    bound = await state.node.transport.bind_locator_notification_beacon(locator, beacon_handle)
                    await websocket.send_json({"type": "BIND_LOCATOR_NOTIFICATION_BEACON_RESULT", "request_id": request_id, "bound": bound})
                except Exception:
                    await websocket.send_json({"type": "ERROR", "request_id": request_id, "code": "NODE_OPERATION_FAILED"})
            elif operation == "START_PROBE":
                route_locator = request.get("route_locator")
                back_route_locator = request.get("back_route_locator")
                if not isinstance(route_locator, str) or not isinstance(back_route_locator, str) or not route_locator or not back_route_locator:
                    await websocket.send_json({"type": "ERROR", "request_id": request_id, "code": "INVALID_ROUTE_HANDLE"})
                    continue
                try:
                    submission = await state.node.transport.start_probe(
                        route_locator, back_route_locator,
                        hops=request.get("metric", request.get("hops", 0)), ttl=min(15, max(1, int(request.get("hop_limit", request.get("ttl", 15))))),
                    )
                except (PermissionError, TypeError, ValueError):
                    await websocket.send_json({"type": "ERROR", "request_id": request_id, "code": "NODE_OPERATION_FAILED"})
                    continue
                await websocket.send_json({"type": "START_PROBE_RESULT", "request_id": request_id, **asdict(submission)})
            elif operation == "ROUTE_STATUS":
                route_locator = request.get("route_locator")
                if not isinstance(route_locator, str) or not route_locator:
                    await websocket.send_json({"type": "ERROR", "request_id": request_id, "code": "INVALID_ROUTE_HANDLE"})
                    continue
                try:
                    status = await state.node.transport.route_status(route_locator)
                except (PermissionError, ValueError):
                    await websocket.send_json({"type": "ERROR", "request_id": request_id, "code": "NODE_OPERATION_FAILED"})
                    continue
                await websocket.send_json({"type": "ROUTE_STATUS_RESULT", "request_id": request_id, **status})
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
            elif operation == "SUBMIT_CONTACT":
                route_locator = request.get("route_locator")
                envelope = request.get("envelope")
                reply_route = request.get("reply_route")
                if (not isinstance(route_locator, str) or not route_locator or
                        not isinstance(envelope, dict) or
                        (reply_route is not None and not isinstance(reply_route, str))):
                    await websocket.send_json({"type": "ERROR", "request_id": request_id, "code": "INVALID_CONTACT_ENVELOPE"})
                    continue
                try:
                    submission = await state.node.transport.submit_contact(
                        route_locator, envelope, reply_route=reply_route,
                    )
                except (PermissionError, ValueError):
                    await websocket.send_json({"type": "ERROR", "request_id": request_id, "code": "INVALID_CONTACT_ENVELOPE"})
                    continue
                await websocket.send_json({"type": "SUBMIT_CONTACT_RESULT", "request_id": request_id, **asdict(submission)})
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
        if registration_registry is not None:
            try:
                registration_registry.close()
            except Exception:
                pass
        if state and state.node:
            state.node.transport.detach_local_delivery_session(websocket)


@router.websocket("/dmp-c/legacy-v1")
async def legacy_dmp_client(websocket: WebSocket):
    """Explicit temporary compatibility boundary for pre-cutover clients.

    New PWA code never selects this route and DEVICE_AUTH_V1 never falls back
    to it. It remains until a separately accepted legacy-retirement milestone.
    """
    await websocket.accept()
    session_id = secrets.token_hex(16)
    nonce = secrets.token_urlsafe(32)
    await websocket.send_json({
        "type": "CHALLENGE", "protocol": PROTOCOL, "version": LEGACY_VERSION,
        "auth_mode": "LEGACY_AUTH_V1", "session_id": session_id, "nonce": nonce,
        "expires_in": AUTH_TIMEOUT_SECONDS,
    })
    try:
        raw = await asyncio.wait_for(websocket.receive_text(), AUTH_TIMEOUT_SECONDS)
        auth = json.loads(raw)
        if auth.get("type") != "AUTH" or auth.get("auth_mode") != "LEGACY_AUTH_V1" or not verify_auth(
            auth.get("public_key", ""), auth.get("signature", ""), session_id, nonce
        ):
            await websocket.close(code=1008, reason="legacy authentication failed")
            return
        state = runtime_state()
        await websocket.send_json({
            "type": "AUTH_OK", "protocol": PROTOCOL, "version": LEGACY_VERSION,
            "auth_mode": "LEGACY_AUTH_V1",
            "node_id": state.node_crypto.node_id if state.node_crypto else None,
            "server_time": int(time.time()), "capabilities": sorted(allowed_operations(state)),
        })
        # Compatibility acknowledgement only: no mixed post-auth operation
        # surface survives beside the DEVICE_AUTH_V1 endpoint.
        await websocket.close(code=1000, reason="legacy compatibility acknowledged")
    except (WebSocketDisconnect, TimeoutError, json.JSONDecodeError):
        return
