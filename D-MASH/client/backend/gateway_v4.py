"""Explicit v4 NODE-only WebSocket endpoint; disabled until lifecycle configured."""
from fastapi import APIRouter, WebSocket

router = APIRouter()

@router.websocket('/mesh/v4')
async def node_v4(socket: WebSocket):
    service = getattr(socket.app.state, 'node_v4', None)
    if service is None:
        await socket.close(code=1008)
        return
    # Listener reserves quota before accepting the HTTP upgrade. Browser/native
    # peers then execute the same v4 identity and directional admission protocol.
    await service.listener.handle(socket, accept=True)
