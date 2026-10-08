"""Fresh authenticated discovery retries; no socket-authentication claim."""
import asyncio
import unittest
from unittest.mock import patch
from nacl.public import PrivateKey
from nacl.signing import SigningKey
from backend.node_routing_v4 import NodeRoutingV4
from backend.route_discovery_v4 import issue_certificate, answer_query

class DiscoveryReprobeTests(unittest.IsolatedAsyncioTestCase):
    def fixture(self):
        owner,sign=SigningKey.generate(),SigningKey.generate()
        box,recipient=PrivateKey.generate(),PrivateKey.generate()
        cert=issue_certificate(owner,sign.verify_key,box.public_key,recipient.public_key,
                               generation=1,issued_at=90,expires_at=1000)
        runtime=NodeRoutingV4(bytes(32),clock=lambda:100)
        runtime.peers['peer']=object()
        packets=[]
        runtime._enqueue=lambda peer,packet:packets.append(packet)
        return runtime,packets,cert,sign,box

    async def test_later_online_reply_uses_fresh_query_and_retires_old_labels(self):
        runtime,packets,cert,sign,box=self.fixture()
        original=asyncio.wait_for
        async def fast_wait(future,timeout):
            return await original(future,timeout/100)
        with patch('backend.node_routing_v4.asyncio.wait_for',fast_wait):
            pending=asyncio.create_task(runtime.discover(cert))
            while len(packets)<2:await asyncio.sleep(.001)
            first,second=packets
            self.assertNotEqual(first['box'],second['box'])
            self.assertNotEqual(first['return_label'],second['return_label'])
            self.assertEqual(len(runtime.labels),1)
            reply=answer_query(second['box'],cert,sign,box,now=100)
            row=runtime.labels[('peer',second['return_label'])]
            await row['target']('peer',dict(payload=reply,offer='f'*64,expires_at=200))
            route=await pending
        self.assertEqual(route['label'],'f'*64)
        self.assertEqual(runtime.labels,{})
        self.assertEqual(runtime.pending,set())
        self.assertFalse(runtime.closed)

    async def test_deadline_cleans_three_attempts_without_closing_peer(self):
        runtime,packets,cert,*_=self.fixture()
        original=asyncio.wait_for
        delays=[]
        async def fast_wait(future,timeout):
            delays.append(timeout)
            return await original(future,.001)
        with patch('backend.node_routing_v4.asyncio.wait_for',fast_wait):
            with self.assertRaisesRegex(TimeoutError,'discovery expired'):
                await runtime.discover(cert)
        self.assertEqual(delays,[5,10,15])
        self.assertEqual(len({p['box'] for p in packets}),3)
        self.assertEqual(len({p['return_label'] for p in packets}),3)
        self.assertEqual(runtime.labels,{})
        self.assertEqual(runtime.pending,set())
        self.assertIn('peer',runtime.peers)
        self.assertFalse(runtime.closed)

    async def test_cancel_and_rate_limit_leave_no_local_labels(self):
        runtime,packets,cert,*_=self.fixture()
        pending=asyncio.create_task(runtime.discover(cert))
        await asyncio.sleep(0)
        pending.cancel()
        with self.assertRaises(asyncio.CancelledError):await pending
        self.assertEqual(runtime.labels,{})
        self.assertEqual(runtime.pending,set())
        runtime.discovery_rates['peer']=(1,24)
        with self.assertRaisesRegex(BufferError,'rate limit'):await runtime.discover(cert)
        self.assertEqual(runtime.labels,{})
        self.assertEqual(len(packets),1)
