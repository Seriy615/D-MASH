"""Ownership/quota tests; crypto is exercised by real browser transit."""
import asyncio
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from backend.node_listener_v4 import NodeListenerV4

class Socket:
    def __init__(self): self.codes = []
    async def close(self, code=1000, reason=''): self.codes.append(code)

class ListenerTests(unittest.IsolatedAsyncioTestCase):
    def listener(self, **kwargs):
        return NodeListenerV4(None, None, SimpleNamespace(peers={}, close=AsyncMock()), **kwargs)

    async def test_pending_quota_and_shutdown_cancel_handshake(self):
        listener = self.listener(max_pending=1)
        entered = asyncio.Event()
        async def handshake(*args, **kwargs):
            entered.set()
            await asyncio.Future()
        a, b = Socket(), Socket()
        with patch('backend.node_listener_v4.accept_secure', handshake):
            task = asyncio.create_task(listener.handle(a))
            await entered.wait()
            await listener.handle(b)
            self.assertEqual(b.codes, [1013])
            await listener.close()
            self.assertTrue(task.cancelled())
            self.assertEqual(listener.pending, 0)
            self.assertFalse(listener.tasks)
            self.assertTrue(a.codes)
            c = Socket()
            await listener.handle(c)
            self.assertEqual(c.codes, [1013])

    async def test_failed_handshakes_consume_rolling_attempt_budget(self):
        now = [100.0]
        listener = self.listener(attempts_per_minute=2, monotonic=lambda: now[0])
        with patch('backend.node_listener_v4.accept_secure', AsyncMock(side_effect=ValueError)) as accept:
            for _ in range(2): await listener.handle(Socket())
            rejected = Socket()
            await listener.handle(rejected)
            self.assertEqual(rejected.codes, [1013])
            self.assertEqual(accept.await_count, 2)
            now[0] += 60
            await listener.handle(Socket())
            self.assertEqual(accept.await_count, 3)
            self.assertEqual(listener.pending, 0)
        await listener.close()

    async def test_duplicate_does_not_mine_or_release_first_reservation(self):
        listener = self.listener()
        entered = asyncio.Event()
        async def accept(socket, *args, **kwargs):
            return SimpleNamespace(session=SimpleNamespace(peer_id='peer'), close=socket.close), 'peer'
        async def authorize(*args, **kwargs):
            entered.set()
            await asyncio.Future()
        with patch('backend.node_listener_v4.accept_secure', accept), patch('backend.node_listener_v4.authorize_node_v4', AsyncMock(side_effect=authorize)) as auth:
            first = asyncio.create_task(listener.handle(Socket()))
            await entered.wait()
            await listener.handle(Socket())
            self.assertEqual(auth.await_count, 1)
            self.assertEqual(listener.reserved, {'peer'})
            await listener.close()
            self.assertTrue(first.cancelled())
            self.assertFalse(listener.reserved)

    async def test_admitted_connection_retains_total_slot(self):
        listener = self.listener(max_connections=1, max_pending=1)
        ready = asyncio.Event()
        async def read():
            ready.set()
            await asyncio.Future()
        listener.runtime.add_peer = lambda *_: asyncio.create_task(read())
        socket = Socket()
        secure = SimpleNamespace(session=SimpleNamespace(peer_id='peer'), close=socket.close)
        channel = SimpleNamespace(close=AsyncMock())
        with patch('backend.node_listener_v4.accept_secure', AsyncMock(return_value=(secure, 'peer'))), patch('backend.node_listener_v4.authorize_node_v4', AsyncMock(return_value=channel)):
            first = asyncio.create_task(listener.handle(socket))
            await ready.wait()
            self.assertEqual(listener.pending, 0)
            second = Socket()
            await listener.handle(second)
            self.assertEqual(second.codes, [1013])
            await listener.close()
            self.assertTrue(first.cancelled())
            self.assertFalse(listener.tasks)
            channel.close.assert_awaited_once()

    def test_invalid_limits(self):
        for args in ({'max_pending':True}, {'max_connections':9}, {'max_pending':2,'max_connections':1}, {'attempts_per_minute':0}):
            with self.assertRaises(ValueError): self.listener(**args)
