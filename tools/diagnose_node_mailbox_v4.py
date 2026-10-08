"""Expected-red current v4 contract regressions, outside default test_all.

Uses real routing queue/removal code and a controlled failed transport boundary.
No claim that this models authenticated grant issuance or durable storage.
"""
import asyncio
import base64
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'D-MASH/client/backend'))
from node_routing_v4 import NodeRoutingV4


class FailedSend:
    def __init__(self, during=None):
        self.during = during

    async def send_operation(self, batch):
        if self.during:
            self.during()
        raise ConnectionError('Controlled link loss before completed send')

    async def close(self):
        pass


class RequiredMailboxRetention(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.runtime = NodeRoutingV4(b'b' * 32, clock=lambda: 100)
        self.peer = 'a' * 64
        self.packet = dict(type='DATA', version=4, label='c' * 64,
                           offer='d' * 64, payload=base64.b64encode(b'x' * 72).decode(),
                           expires_at=200)
        self.runtime.peers[self.peer] = FailedSend()

    async def asyncTearDown(self):
        await self.runtime.close()

    async def test_failed_send_retains_original_ciphertext(self):
        self.runtime._enqueue(self.peer, self.packet)
        await self.runtime._flush(self.peer)
        retained = [row[0] for row in self.runtime.queues.get(self.peer, [])]
        self.assertIn(self.packet, retained, 'Failed awaited send discarded accepted ciphertext')

    async def test_failed_send_does_not_drop_concurrent_arrival(self):
        later = {**self.packet, 'payload': base64.b64encode(b'y' * 72).decode()}
        self.runtime.peers[self.peer] = FailedSend(lambda: self.runtime._enqueue(self.peer, later))
        self.runtime._enqueue(self.peer, self.packet)
        await self.runtime._flush(self.peer)
        retained = [row[0] for row in self.runtime.queues.get(self.peer, [])]
        self.assertIn(later, retained, 'Link removal discarded arrival outside the send snapshot')


if __name__ == '__main__':
    unittest.main(verbosity=2)
