import unittest
from nacl.signing import SigningKey
from backend.node_service_descriptor_v4 import sign,verify
class ServiceDescriptor(unittest.TestCase):
 def test_context_and_revocation(self):
  key=SigningKey(bytes([9])*32);peer=SigningKey(bytes([10])*32)
  body=dict(version=1,issuer=key.verify_key.encode().hex(),holder=peer.verify_key.encode().hex(),transcript_hash='11'*32,challenge='22'*32,issued_at=100,expires_at=125,signaling_wss='wss://example.test/signal',can_s_turn=True,can_relay_blob=True)
  ctx={k:body[k] for k in ('issuer','holder','transcript_hash','challenge','signaling_wss')};e=sign(body,key)
  self.assertEqual(verify(e,now=101,**ctx),body)
  for field in ('holder','transcript_hash','challenge','signaling_wss'):
   with self.assertRaises(Exception):verify(e,now=101,**{**ctx,field:'wrong'})
  with self.assertRaises(Exception):verify(e,now=125,**ctx)
  revoked=sign({**body,'can_s_turn':False,'can_relay_blob':False},key)
  self.assertFalse(verify(revoked,now=101,**ctx)['can_s_turn'])

class ServiceChannel(unittest.IsolatedAsyncioTestCase):
 async def test_bound_peer_and_revocation_race(self):
  import asyncio
  from backend.node_routing_v4 import NodeRoutingV4
  runtime=NodeRoutingV4(bytes(32),clock=lambda:100)
  class Channel:
   def require_authorized(self):pass
  channel=Channel();runtime.peers['peer']=channel
  ready=asyncio.Event();release=asyncio.Event();sent=[]
  async def provider(peer,actual,challenge):
   self.assertIs(actual,channel);ready.set();await release.wait();return {'test':True}
  runtime.service_provider=provider;runtime._enqueue=lambda peer,packet:sent.append(packet)
  task=asyncio.create_task(runtime._receive('peer',dict(type='SERVICE_QUERY',version=4,challenge='11'*32,expires_at=110)))
  await ready.wait();runtime.peers.pop('peer');release.set();await task;self.assertEqual(sent,[])
  runtime.peers['peer']=channel
  await runtime._receive('peer',dict(type='SERVICE_QUERY',version=4,challenge='22'*32,expires_at=110))
  self.assertEqual(sent[0]['type'],'SERVICE_REPLY')
  self.assertEqual(sent[0]['challenge'],'22'*32)
 async def test_unconfigured_preserves_peer(self):
  from backend.node_routing_v4 import NodeRoutingV4
  runtime=NodeRoutingV4(bytes(32),clock=lambda:100)
  class Channel:
   def require_authorized(self):pass
  channel=Channel();runtime.peers['peer']=channel;sent=[];runtime._enqueue=lambda peer,packet:sent.append(packet)
  await runtime._receive('peer',dict(type='SERVICE_QUERY',version=4,challenge='11'*32,expires_at=110))
  self.assertEqual(sent[0]['type'],'SERVICE_UNAVAILABLE');self.assertIs(runtime.peers['peer'],channel)
