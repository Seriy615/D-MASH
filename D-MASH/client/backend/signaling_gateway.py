"""Ticket-authenticated, identity-free signaling WebSocket endpoint."""
import asyncio
import json
import hashlib
import secrets
import re
from fastapi import APIRouter, WebSocket

router = APIRouter()


async def serve_signaling(websocket, service, *, admission_difficulty=18):
    if type(admission_difficulty) is not int or not 1 <= admission_difficulty <= 20:
        raise ValueError('invalid admission difficulty')
    if (service is None or not service.healthy()
            or service.active_signaling_connections >= service.max_signaling_connections):
        await websocket.close(code=1013)
        return
    service.active_signaling_connections += 1
    sid = handle = created_sid = None
    tasks = []
    try:
        await websocket.accept()
        raw = await asyncio.wait_for(websocket.receive_text(), 10)
        if len(raw) > 4096: raise ValueError('oversized join')
        request = json.loads(raw)
        if isinstance(request, dict) and request.get('type') == 'CREATE':
            if set(request) != {'type', 'call_id', 'secret_verifier'}:
                raise ValueError('invalid creation')
            if any(not isinstance(request[k], str) or not re.fullmatch('[0-9a-f]{64}', request[k])
                   for k in ('call_id', 'secret_verifier')):
                raise ValueError('invalid creation token')
            nonce = secrets.token_hex(32)
            await websocket.send_json({'type': 'CHALLENGE', 'nonce': nonce, 'difficulty': admission_difficulty})
            raw = await asyncio.wait_for(websocket.receive_text(), 30)
            if len(raw) > 1024: raise ValueError('oversized proof')
            proof = json.loads(raw)
            if not isinstance(proof, dict) or set(proof) != {'type', 'counter'} or proof['type'] != 'PROOF':
                raise ValueError('invalid proof')
            counter = proof['counter']
            if type(counter) is not int or not 0 <= counter <= 2**53 - 1: raise ValueError('invalid counter')
            text = ':'.join((nonce, request['call_id'], request['secret_verifier'], str(counter)))
            digest = hashlib.sha256(text.encode('ascii')).digest()
            if int.from_bytes(digest, 'big') >= 1 << (256 - admission_difficulty):
                raise PermissionError('invalid work')
            result = service.create_session(request['call_id'], bytes.fromhex(request['secret_verifier']))
            created_sid = result['session_id']
            await websocket.send_json({'type': 'CREATED', **result})
            raw = await asyncio.wait_for(websocket.receive_text(), 10)
            if len(raw) > 4096: raise ValueError('oversized join')
            request = json.loads(raw)
        if not isinstance(request, dict) or set(request) != {'type', 'session_id', 'ticket', 'role'} or request['type'] != 'JOIN':
            raise ValueError('invalid join')
        if not isinstance(request['session_id'], str): raise ValueError('invalid session')
        sid = request['session_id']
        if created_sid is not None and (sid != created_sid or request['role'] != 'caller'):
            raise PermissionError('creation scope mismatch')
        handle = service.join(sid, request['ticket'], request['role'])
        await websocket.send_json({'type': 'JOINED', 'ice_servers': [{
            'urls': service.turn_urls,
            **{k: v for k, v in service.issue_turn_credentials(sid).items() if k in {'username', 'credential'}}}]})

        async def read():
            while True:
                raw = await websocket.receive_text()
                if len(raw.encode('utf-8')) > 512 * 1024: raise ValueError('oversized signal')
                service.relay(sid, handle, json.loads(raw))

        async def write():
            while True:
                for message in await service.wait_messages(sid, handle):
                    await asyncio.wait_for(websocket.send_json(message), 10)
        tasks = [asyncio.create_task(read()), asyncio.create_task(write())]
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    except asyncio.CancelledError:
        raise
    except Exception:
        pass  # Never log ticket, payload, SDP or peer identity.
    finally:
        service.active_signaling_connections -= 1
        for task in tasks: task.cancel()
        if tasks: await asyncio.gather(*tasks, return_exceptions=True)
        if handle is not None: service.close_session(sid)
        if created_sid is not None: service.close_session(created_sid)
        await websocket.close()


@router.websocket('/signal/v1')
async def signaling_endpoint(websocket: WebSocket):
    # Missing runtime wiring fails closed; configuration alone is not health.
    await serve_signaling(websocket, getattr(websocket.app.state, 's_turn_service', None))
