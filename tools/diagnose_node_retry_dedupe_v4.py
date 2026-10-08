"""Routing retry regression; admitted-operation adapters, not socket acceptance."""
import asyncio, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'D-MASH/client'))
from nacl.public import PrivateKey
from nacl.signing import SigningKey
from backend.node_routing_v4 import NodeRoutingV4
from backend.route_discovery_v4 import issue_certificate, seal

class Channel:
    def __init__(self): self.queue=asyncio.Queue();self.closed=False;self.drop=None
    def require_authorized(self):
        if self.closed: raise ConnectionError()
    async def send_operation(self,value):
        self.require_authorized(); packets=[]
        for packet in value['packets']:
            if self.drop is not None and self.drop == packet.get('payload'): self.drop=None
            else: packets.append(packet)
        if packets: await self.other.queue.put({**value,'packets':packets})
    async def receive_operation(self):
        value=await self.queue.get()
        if value is None: raise ConnectionError()
        return value
    async def close(self):
        if self.closed:return
        self.closed=True;await self.queue.put(None);await self.other.queue.put(None)

def connect(left,left_name,right,right_name):
    a,b=Channel(),Channel();a.other=b;b.other=a;left.add_peer(right_name,a);right.add_peer(left_name,b);return a,b

async def main():
    nodes=[NodeRoutingV4(bytes([n])*32) for n in (1,2,3)];a,hub,c=nodes
    connect(a,'a',hub,'hub');outgoing,_=connect(hub,'hub',c,'c')
    owner,sign=SigningKey.generate(),SigningKey.generate();box,recipient=PrivateKey.generate(),PrivateKey.generate();now=int(time.time())
    cert=issue_certificate(owner,sign.verify_key,box.public_key,recipient.public_key,generation=1,issued_at=now,expires_at=now+3600)
    received=asyncio.Queue()
    async def deliver(peer,packet):await received.put(packet['payload'])
    async def discard(peer,packet):pass
    c.bind_local(cert,sign,box,deliver)
    try:
        first=await asyncio.wait_for(a.discover(cert),10);opaque=seal(bytes(recipient.public_key),{'control':'unchanged retry fixture'})
        outgoing.drop=opaque;a.send(first,opaque,discard);await asyncio.sleep(1.3)
        assert received.empty(), 'fault did not drop initial downstream DATA'
        forwarded=hub.stats['forwarded'];a.send(first,opaque,discard);await asyncio.sleep(.8)
        assert hub.stats['forwarded']==forwarded, 'same grant duplicate was not suppressed'
        second=await asyncio.wait_for(a.discover(cert),10);assert second['label']!=first['label']
        a.send(second,opaque,discard)
        try: delivered=await asyncio.wait_for(received.get(),3)
        except asyncio.TimeoutError: raise AssertionError('Fresh certified route must retry identical recipient ciphertext after downstream loss') from None
        assert delivered==opaque
        print('PASS fresh-hop-grant retry delivers exact ciphertext; same-grant duplicate suppressed; no Account metadata')
    finally: await asyncio.gather(*(node.close() for node in nodes))

if __name__=='__main__': asyncio.run(main())
