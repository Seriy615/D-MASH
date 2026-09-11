"""Ticket-authenticated, identity-free signaling WebSocket endpoint."""
import asyncio
import json
from fastapi import APIRouter, WebSocket

router = APIRouter()


async def serve_signaling(websocket, service):
    if service is None or not service.healthy():
        await websocket.close(code=1013)
        return
    await websocket.accept()
    sid = handle = None
    tasks = []
    try:
        raw = await asyncio.wait_for(websocket.receive_text(), 10)
        if len(raw) > 4096: raise ValueError('oversized join')
        request = json.loads(raw)
        if not isinstance(request, dict) or set(request) != {'type', 'session_id', 'ticket', 'role'} or request['type'] != 'JOIN':
            raise ValueError('invalid join')
        if not isinstance(request['session_id'], str): raise ValueError('invalid session')
        sid = request['session_id']
        handle = service.join(sid, request['ticket'], request['role'])
        await websocket.send_json({'type': 'JOINED'})

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
        for task in tasks: task.cancel()
        if tasks: await asyncio.gather(*tasks, return_exceptions=True)
        if handle is not None: service.close_session(sid)
        await websocket.close()


@router.websocket('/signal/v1')
async def signaling_endpoint(websocket: WebSocket):
    # Missing runtime wiring fails closed; configuration alone is not health.
    await serve_signaling(websocket, getattr(websocket.app.state, 's_turn_service', None))
