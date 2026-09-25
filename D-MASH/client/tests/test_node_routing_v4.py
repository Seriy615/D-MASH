import asyncio
import time
import unittest
from nacl.public import PrivateKey
from nacl.signing import SigningKey
from backend.node_routing_v4 import NodeRoutingV4
from backend.route_discovery_v4 import issue_certificate,seal,open_box

class Channel:
    """Authorized operation adapter only; crypto/socket coverage is separate."""
    def __init__(self):self.queue=asyncio.Queue();self.closed=False;self.sent=[]
    def require_authorized(self):
        if self.closed:raise ConnectionError()
    async def send_operation(self,value):
        self.require_authorized();self.sent.append(value);await self.other.queue.put(value)
    async def receive_operation(self):
        value=await self.queue.get()
        if value is None:raise ConnectionError()
        return value
    async def close(self):
        if self.closed:return
        self.closed=True;await self.queue.put(None);await self.other.queue.put(None)


def connect(a,aname,b,bname):
    left,right=Channel(),Channel();left.other=right;right.other=left
    a.add_peer(bname,left);b.add_peer(aname,right);return left,right

class NodeRoutingV4Tests(unittest.IsolatedAsyncioTestCase):
    async def test_discovery_installs_labels_and_forwards_opaque_payload(self):
        nodes=[NodeRoutingV4(bytes([value])*32) for value in (1,2,3)]
        a,b,c=nodes
        first=connect(a,'a',b,'b');second=connect(b,'b',c,'c')
        owner,sign=SigningKey.generate(),SigningKey.generate();box,recipient=PrivateKey.generate(),PrivateKey.generate()
        now=int(time.time());cert=issue_certificate(owner,sign.verify_key,box.public_key,recipient.public_key,
            generation=1,issued_at=now,expires_at=now+3600)
        received=asyncio.get_running_loop().create_future()
        async def deliver(peer,packet):received.set_result(open_box(recipient,packet['payload']))
        async def discard(peer,packet):pass
        c.bind_local(cert,sign,box,deliver)
        try:
            route=await asyncio.wait_for(a.discover(cert),10)
            self.assertEqual(route['peer'],'b')
            opaque=seal(bytes(recipient.public_key),{'message':'test transit'})
            a.send(route,opaque,discard)
            self.assertEqual(await asyncio.wait_for(received,5),{'message':'test transit'})
            self.assertEqual(len(b.owned),0)
            self.assertEqual(b.stats['forwarded'],2)
            incoming=next(p for batch in first[0].sent for p in batch['packets'] if p['type']=='DATA')
            outgoing=next(p for batch in second[0].sent for p in batch['packets'] if p['type']=='DATA')
            self.assertNotEqual(incoming['label'],outgoing['label'])
            self.assertEqual(incoming['payload'],outgoing['payload'])
            p1=first[0].sent[0]['packets'][0];p2=second[0].sent[0]['packets'][0]
            self.assertEqual(p1['ttl']-1,p2['ttl']);self.assertNotEqual(p1['ncrh'],p2['ncrh'])
            for packet in (p1,p2,incoming,outgoing):
                self.assertNotIn('route_id',packet);self.assertNotIn('metric',packet);self.assertNotIn('trace',packet)
            await b.close();await asyncio.sleep(.05)
            with self.assertRaises(ConnectionError):a.send(route,opaque,discard)
            replacement=NodeRoutingV4(bytes([4])*32);nodes.append(replacement)
            connect(a,'a',replacement,'b')
            with self.assertRaises(ConnectionError):a.send(route,opaque,discard)
        finally:await asyncio.gather(*(node.close() for node in nodes))

    async def test_unknown_labels_do_not_create_authority(self):
        node=NodeRoutingV4(bytes(32));called=[]
        try:
            await node._receive('ungranted',dict(type='DATA',version=4,label='ab'*32,offer='cd'*32,
                payload='A'*96,expires_at=int(time.time())+100))
            self.assertFalse(node.labels);self.assertFalse(node.queues)
        finally:await node.close()

    async def test_first_arrival_windows_use_monotonic_time(self):
        wall=[time.time()]
        node=NodeRoutingV4(bytes(32),clock=lambda:wall[0]);events=asyncio.Queue()
        class Sink:
            async def send_operation(self,value):await events.put((time.monotonic(),value))
            async def close(self):pass
        node.peers['peer']=Sink()
        try:
            packet=dict(type='DATA',version=4,label='ab'*32,offer='cd'*32,payload='opaque',expires_at=int(wall[0])+100)
            started=time.monotonic();node._enqueue('peer',packet)
            await asyncio.sleep(.1);node._enqueue('peer',packet)
            wall[0]-=3600  # a wall-clock correction must not stretch a tact
            sent,batch=await asyncio.wait_for(events.get(),2)
            self.assertGreaterEqual(sent-started,.45);self.assertEqual(len(batch['packets']),2)
            restarted=time.monotonic();node._enqueue('peer',packet)
            sent,batch=await asyncio.wait_for(events.get(),2)
            self.assertGreaterEqual(sent-restarted,.45);self.assertEqual(len(batch['packets']),1)
        finally:await node.close()

    async def test_outer_expiry_cannot_extend_discovery_grant(self):
        from backend.route_discovery_v4 import create_query
        node=NodeRoutingV4(bytes(32));now=int(time.time())
        class Sink:
            async def send_operation(self,value):pass
            async def close(self):pass
        node.peers['peer']=Sink()
        owner,sign=SigningKey.generate(),SigningKey.generate();box,recipient=PrivateKey.generate(),PrivateKey.generate()
        cert=issue_certificate(owner,sign.verify_key,box.public_key,recipient.public_key,
            generation=1,issued_at=now,expires_at=now+20)
        async def discard(peer,packet):pass
        binding=node.bind_local(cert,sign,box,discard)
        query,_=create_query(cert,now=now)
        try:
            await node._answer_binding('peer',dict(box=query,return_label='ab'*32,expires_at=now+180),binding)
            packet=node.queues['peer'][0][0]
            self.assertEqual(packet['expires_at'],now+20)
            self.assertEqual(node.labels[('peer',packet['offer'])]['expires'],now+20)
        finally:await node.close()

    async def test_cover_uses_existing_grants_and_rolling_budget(self):
        mono=[1000.0];node=NodeRoutingV4(bytes(32),monotonic=lambda:mono[0]);events=asyncio.Queue()
        class Sink:
            def __init__(self,peer):self.peer=peer
            async def send_operation(self,value):await events.put((self.peer,value))
            async def close(self):pass
        now=int(time.time());counts={'left':0,'right':0}
        try:
            self.assertFalse(node.inject_cover_once())
            for peer in counts:
                node.peers[peer]=Sink(peer);node._label('incoming',(peer,'ab'*32),now+120)
            for _ in range(4):
                self.assertTrue(node.inject_cover_once(1024))
                self.assertFalse(node.inject_cover_once(1024),'queued traffic must take priority')
                peer,batch=await asyncio.wait_for(events.get(),2);counts[peer]+=1
                packet=batch['packets'][0]
                self.assertEqual(set(packet),{'type','version','label','offer','payload','expires_at'})
                self.assertEqual(packet['type'],'DATA');self.assertEqual(packet['label'],'ab'*32)
            self.assertEqual(sorted(counts.values()),[2,2]);self.assertFalse(node.inject_cover_once())
            mono[0]+=59.9;self.assertFalse(node.inject_cover_once())
            mono[0]+=.2;self.assertTrue(node.inject_cover_once(16384))
            await asyncio.wait_for(events.get(),2)
            self.assertFalse(node.inject_cover_once(256),'decoded byte budget must also apply')
        finally:await node.close()

    async def test_cover_scheduler_lifecycle_and_no_grant_no_emission(self):
        node=NodeRoutingV4(bytes(32))
        try:
            with self.assertRaises(ValueError):node.start_cover(minimum=14)
            node.start_cover();timer=node.cover_timer
            self.assertIsNotNone(timer);self.assertGreaterEqual(timer.when()-asyncio.get_running_loop().time(),14.9)
            node.stop_cover();self.assertTrue(timer.cancelled());self.assertIsNone(node.cover_timer)
            node.start_cover();timer=node.cover_timer
            self.assertFalse(node.inject_cover_once());self.assertFalse(node.queues)
            await node.close();self.assertTrue(timer.cancelled());self.assertIsNone(node.cover_timer)
            with self.assertRaises(ValueError):node.start_cover()
        finally:await node.close()
