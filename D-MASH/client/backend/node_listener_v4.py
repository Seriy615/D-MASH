"""Bounded native owner of incoming v4 Node connections.

The endpoint adapter supplies an accepted WebSocket with frame/queue limits.
The caller owns credentials and persistent storage. This owner contains no Account
state and does not enable a production endpoint by merely importing it.
"""
import asyncio
import time
from collections import deque

if __package__:
    from .secure_socket import accept_secure
    from .node_channel_v4 import authorize_node_v4
else:
    from secure_socket import accept_secure
    from node_channel_v4 import authorize_node_v4


class NodeListenerV4:
    def __init__(self, signing_key, relationships, runtime, *, password_gate=None,
                 peer_password_key=None, require_peer_password=False,
                 difficulty=None, max_connections=8, max_pending=2,
                 attempts_per_minute=16, monotonic=time.monotonic):
        for value, upper in ((max_connections, 8), (max_pending, 8),
                             (attempts_per_minute, 256)):
            if type(value) is not int or not 1 <= value <= upper:
                raise ValueError('Invalid listener quota')
        if max_pending > max_connections:
            raise ValueError('Invalid pending quota')
        self.signing_key, self.relationships, self.runtime = signing_key, relationships, runtime
        self.password_gate, self.peer_password_key = password_gate, peer_password_key
        self.require_peer_password, self.difficulty = require_peer_password, difficulty
        self.max_connections, self.max_pending = max_connections, max_pending
        self.attempts_per_minute, self.monotonic = attempts_per_minute, monotonic
        self.attempts = deque()
        self.tasks, self.reserved = set(), set()
        self.pending = 0
        self.closed = False

    async def handle(self, socket, *, accept=False):
        now = self.monotonic()
        while self.attempts and self.attempts[0] <= now - 60:
            self.attempts.popleft()
        if (self.closed or len(self.tasks) >= self.max_connections
                or self.pending >= self.max_pending
                or len(self.attempts) >= self.attempts_per_minute):
            await self._close(socket, 1013)
            return
        # No await between quota check and reservation.
        self.attempts.append(now)
        task = asyncio.current_task()
        self.tasks.add(task)
        self.pending += 1
        pending = True
        peer = None
        secure = channel = None
        try:
            if accept:
                await socket.accept()
            secure, _ = await accept_secure(socket, self.signing_key, 'NODE', version=4)
            peer = secure.session.peer_id
            if peer in self.reserved or peer in self.runtime.peers:
                peer = None  # Do not release a different connection's reservation.
                raise PermissionError('Duplicate Node connection')
            self.reserved.add(peer)
            channel = await authorize_node_v4(
                secure, self.relationships, password_gate=self.password_gate,
                peer_password_key=self.peer_password_key,
                require_peer_password=self.require_peer_password, difficulty=self.difficulty)
            if self.closed:
                raise ConnectionError('Node listener closed')
            reader = self.runtime.add_peer(peer, channel)
            self.pending -= 1
            pending = False
            await reader
        except asyncio.CancelledError:
            raise
        except Exception:
            # Keep authentication errors out of peer-visible close reasons.
            pass
        finally:
            try:
                if channel:
                    await self._close(channel, None)
                elif secure:
                    await self._close(secure, 1008)
                else:
                    await self._close(socket, 1008)
            finally:
                if pending:
                    self.pending -= 1
                if peer is not None:
                    self.reserved.discard(peer)
                self.tasks.discard(task)

    @staticmethod
    async def _close(target, code):
        try:
            async with asyncio.timeout(5):
                if code is None:
                    await target.close()
                else:
                    await target.close(code=code, reason='Node connection ended')
        except Exception:
            pass

    async def close(self):
        self.closed = True
        tasks = list(self.tasks)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await self.runtime.close()
        self.reserved.clear()
