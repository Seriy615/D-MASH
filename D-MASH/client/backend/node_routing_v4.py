"""Bounded v4 discovery/label forwarding over admitted Node channels.

This runtime owns no Account keys. Store/delegate provisioning and production
endpoint mounting are separate and not yet provided by this module.
"""
import asyncio
import base64
import hashlib
import json
import re
import secrets
import time

if __package__:
    from .probe_primitives_v4 import route_ncrh, extend_ncrh, sample_hop_ttl, consume_hop
    from .recipient_payload_v4 import cover_box
    from .route_discovery_v4 import create_query, answer_query, verify_reply, verify_certificate
else:
    from probe_primitives_v4 import route_ncrh, extend_ncrh, sample_hop_ttl, consume_hop
    from recipient_payload_v4 import cover_box
    from route_discovery_v4 import create_query, answer_query, verify_reply, verify_certificate

TOKEN=re.compile('[0-9a-f]{64}')


def _opaque(value):
    if not isinstance(value,str) or not 96<=len(value)<=21848:raise ValueError('Invalid opaque box')
    raw=base64.b64decode(value,validate=True)
    if not 72<=len(raw)<=16384 or base64.b64encode(raw).decode()!=value:raise ValueError('Invalid opaque box')



class NodeRoutingV4:
    def __init__(self,base_ncrh,*,clock=time.time,monotonic=time.monotonic):
        if not isinstance(base_ncrh,bytes) or len(base_ncrh)!=32:raise ValueError('Invalid BaseNCRH')
        self.base=base_ncrh;self.clock=clock;self.monotonic=monotonic;self.peers={};self.owned=[];self.labels={};self.seen={}
        self.queues={};self.timers={};self.senders={};self.tasks=set();self.pending=set();self.rates={};self.probes=[];self.cover_history=[];self.cover_timer=None;self.cover_policy=None
        self.closed=False;self.stats=dict(forwarded=0,received=0,probes=0,batches=0)

    def _prune(self):
        now=self.clock()
        self.probes[:]=[row for row in self.probes if row[1]['expires_at']>now and row[0] in self.peers]
        for table in (self.labels,self.seen):
            for key,row in list(table.items()):
                if row['expires']<=now:del table[key]

    def _label(self,peer,target,expires):
        self._prune()
        if len(self.labels)>=4096:raise BufferError('Node label quota')
        label=secrets.token_hex(32);self.labels[(peer,label)]={'target':target,'expires':expires}
        return label

    def _dedupe(self,kind,blob,expires):
        self._prune();key=(kind,hashlib.sha256(blob.encode()).digest())
        if key in self.seen:return False
        if len(self.seen)>=4096:raise BufferError('Node duplicate quota')
        self.seen[key]={'expires':expires};return True

    def bind_local(self,certificate,discovery_sign,discovery_box,handler):
        verify_certificate(certificate,int(self.clock()))
        if self.closed or len(self.owned)>=32:raise BufferError('Local route quota')
        if any(row['certificate']['route_id']==certificate['route_id'] for row in self.owned):raise ValueError('Route already bound')
        if discovery_sign.verify_key.encode().hex()!=certificate['discovery_sign'] or bytes(discovery_box.public_key).hex()!=certificate['discovery_box']:
            raise ValueError('Discovery key mismatch')
        binding=dict(certificate=dict(certificate),sign=discovery_sign,box=discovery_box,handler=handler)
        self.owned.append(binding)
        task=asyncio.create_task(self._answer_cached(binding));self.tasks.add(task);task.add_done_callback(self.tasks.discard)
        return binding

    async def _answer_cached(self,binding):
        self._prune()
        for peer,packet in list(self.probes):
            try:await self._answer_binding(peer,packet,binding)
            except (BufferError,ConnectionError):pass

    async def _answer_binding(self,peer,packet,binding):
        if self.closed or peer not in self.peers or packet['expires_at']<=self.clock():return
        try:reply,query_expiry=answer_query(packet['box'],binding['certificate'],binding['sign'],binding['box'],now=int(self.clock()),with_context=True)
        except Exception:return
        expires=min(packet['expires_at'],query_expiry)
        offer=self._label(peer,binding['handler'],expires)
        self._enqueue(peer,dict(type='DATA',version=4,label=packet['return_label'],offer=offer,payload=reply,expires_at=expires))

    def add_peer(self,peer,channel):
        if self.closed or peer in self.peers or len(self.peers)>=8:raise ValueError('Node peer unavailable')
        channel.require_authorized()
        self.peers[peer]=channel
        task=asyncio.create_task(self._read(peer,channel));self.tasks.add(task);task.add_done_callback(self.tasks.discard)
        return task

    async def _read(self,peer,channel):
        try:
            while not self.closed:
                batch=await channel.receive_operation()
                if (not isinstance(batch,dict) or set(batch)!={'type','version','packets'} or batch['type']!='MESH_BATCH'
                        or type(batch['version']) is not int or batch['version']!=4 or not isinstance(batch['packets'],list)
                        or not 1<=len(batch['packets'])<=32 or len(json.dumps(batch))>256*1024):
                    raise ValueError('Invalid Node batch')
                for packet in batch['packets']:
                    channel.require_authorized()
                    await self._receive(peer,packet)
        except (Exception,asyncio.CancelledError):
            pass
        finally:
            if self.peers.get(peer) is channel:self._remove_peer(peer)
            await channel.close()

    def _remove_peer(self,peer):
        self.peers.pop(peer,None);self.queues.pop(peer,None);timer=self.timers.pop(peer,None)
        if timer:timer.cancel()
        self.rates.pop(peer,None)
        if not self.peers:
            for future in self.pending:
                if not future.done():future.set_exception(ConnectionError('Node path unavailable'))
        for key,row in list(self.labels.items()):
            target=row['target']
            if key[0]==peer or (isinstance(target,tuple) and target[0]==peer):del self.labels[key]

    def _enqueue(self,peer,packet):
        if self.closed or peer not in self.peers:raise ConnectionError('Node path unavailable')
        queue=self.queues.setdefault(peer,[])
        size=len(json.dumps(packet,separators=(',',':')))
        if size>32768 or len(queue)>=128 or sum(row[1] for q in self.queues.values() for row in q)+size>1024*1024:
            raise BufferError('Node forwarding queue full')
        queue.append((packet,size,self.monotonic()+0.5))
        if peer not in self.timers and peer not in self.senders:self._arm(peer)

    def _arm(self,peer):
        queue=self.queues.get(peer)
        if not queue or self.closed:return
        delay=max(0,queue[0][2]-self.monotonic())
        self.timers[peer]=asyncio.get_running_loop().call_later(delay,self._start_send,peer)

    def _start_send(self,peer):
        self.timers.pop(peer,None)
        task=asyncio.create_task(self._flush(peer));self.senders[peer]=task

    async def _flush(self,peer):
        try:
            queue=self.queues.get(peer,[])
            # Only the first arrival's window is closed, not later windows.
            deadline=queue[0][2] if queue else 0;batch=[];size=0
            while queue and queue[0][2]<deadline+0.5 and len(batch)<32:
                packet,amount,_=queue[0]
                if size+amount>240*1024:break
                queue.pop(0)
                if packet['expires_at']>self.clock():batch.append(packet);size+=amount
            if batch:
                async with asyncio.timeout(10):
                    await self.peers[peer].send_operation(dict(type='MESH_BATCH',version=4,packets=batch))
                self.stats['batches']+=1
        except Exception:
            channel=self.peers.get(peer);self._remove_peer(peer)
            if channel:await channel.close()
        finally:
            self.senders.pop(peer,None);self._arm(peer)

    async def discover(self,certificate):
        if self.closed or not self.peers:raise ConnectionError('Node path unavailable')
        blob,state=create_query(certificate,now=int(self.clock()));expires=state['query']['expires_at']
        future=asyncio.get_running_loop().create_future();self.pending.add(future)
        async def accept(peer,packet):
            if future.done():return
            try:valid=verify_reply(packet['payload'],state,now=int(self.clock()))
            except Exception:return
            if valid:
                future.set_result(dict(peer=peer,label=packet['offer'],expires_at=min(expires,packet['expires_at']),channel=self.peers.get(peer)))
        try:
            self._dedupe('PROBE',blob,expires)
            ncrh=route_ncrh(self.base,bytes.fromhex(certificate['route_id']));ttl=sample_hop_ttl()
            for peer in list(self.peers):
                label=self._label(peer,accept,expires)
                self._enqueue(peer,dict(type='PROBE',version=4,box=blob,return_label=label,ncrh=ncrh,ttl=ttl,expires_at=expires))
            return await asyncio.wait_for(future,max(0.001,expires-self.clock()))
        finally:
            self.pending.discard(future)
            # Late alternate replies may still arrive on issued capabilities.
            # Retain a no-op target until expiry, without retaining query secrets.
            async def retired(peer,packet):pass
            for row in self.labels.values():
                if row['target'] is accept:row['target']=retired

    def send(self,route,payload,reply_handler):
        expires=route['expires_at']
        if expires<=self.clock() or self.peers.get(route['peer']) is not route['channel']:raise ConnectionError('Node route expired or replaced')
        _opaque(payload)
        offer=self._label(route['peer'],reply_handler,expires)
        self._enqueue(route['peer'],dict(type='DATA',version=4,label=route['label'],offer=offer,payload=payload,expires_at=expires))

    def start_cover(self,*,minimum=15,maximum=45):
        if self.closed or type(minimum) is not int or type(maximum) is not int or not 15<=minimum<maximum<=300:
            raise ValueError('Invalid cover scheduling policy')
        self.stop_cover();self.cover_policy=(minimum,maximum);self._schedule_cover()

    def stop_cover(self):
        self.cover_policy=None
        if self.cover_timer:self.cover_timer.cancel()
        self.cover_timer=None

    def _schedule_cover(self):
        if self.closed or self.cover_policy is None:return
        minimum,maximum=self.cover_policy
        delay=(minimum*1000+secrets.randbelow((maximum-minimum)*1000+1))/1000
        self.cover_timer=asyncio.get_running_loop().call_later(delay,self._cover_tick)

    def _cover_tick(self):
        self.cover_timer=None
        if self.closed or self.cover_policy is None:return
        try:self.inject_cover_once()
        except (ValueError,ConnectionError,BufferError):pass
        finally:self._schedule_cover()

    def inject_cover_once(self,size=1024):
        if self.closed or any(self.queues.values()) or self.senders:return False
        now=self.monotonic();self.cover_history[:]=[row for row in self.cover_history if row[0]>now-60]
        if type(size) is not int or not 256<=size<=16384:raise ValueError('Invalid cover size')
        if len(self.cover_history)>=4 or sum(row[2] for row in self.cover_history)+size>16384:return False
        self._prune();candidates=[]
        for row in self.labels.values():
            target=row['target']
            if (isinstance(target,tuple) and target[0] in self.peers and row['expires']>self.clock()+2
                    and sum(row[1]==target[0] for row in self.cover_history)<2):
                candidates.append((target,row['expires']))
        if not candidates:return False
        target,expires=secrets.choice(candidates)
        async def discard(peer,packet):pass
        self.send(dict(peer=target[0],label=target[1],expires_at=expires,channel=self.peers[target[0]]),cover_box(size),discard)
        self.cover_history.append((now,target[0],size))
        return True

    async def _receive(self,peer,packet):
        if not isinstance(packet,dict) or packet.get('version')!=4 or type(packet.get('version')) is not int:raise ValueError('Invalid Node packet')
        expires=packet.get('expires_at')
        if type(expires) is not int or expires>self.clock()+180:raise ValueError('Invalid packet expiry')
        if expires<=self.clock():return
        if packet.get('type')=='PROBE':
            if set(packet)!={'type','version','box','return_label','ncrh','ttl','expires_at'}:raise ValueError('Invalid Probe')
            for key in ('return_label','ncrh'):
                if not isinstance(packet[key],str) or not TOKEN.fullmatch(packet[key]):raise ValueError('Invalid Probe label')
            remaining=consume_hop(packet['ttl']);blob=packet['box']
            _opaque(blob)
            bucket=int(self.clock()//60);rate=self.rates.get(peer,(bucket,0));count=rate[1] if rate[0]==bucket else 0
            if count>=32:raise BufferError('Probe rate limit')
            self.rates[peer]=(bucket,count+1)
            if not self._dedupe('PROBE',blob,expires):return
            self.stats['probes']+=1
            self.probes.append((peer,dict(packet)));self.probes[:]=self.probes[-64:]
            if remaining:
                ncrh=extend_ncrh(self.base,packet['ncrh'])
                for neighbor in list(self.peers):
                    if neighbor==peer:continue
                    label=self._label(neighbor,(peer,packet['return_label']),expires)
                    self._enqueue(neighbor,{**packet,'return_label':label,'ttl':remaining,'ncrh':ncrh})
            for binding in self.owned:await self._answer_binding(peer,packet,binding)
        elif packet.get('type')=='DATA':
            if set(packet)!={'type','version','label','offer','payload','expires_at'}:raise ValueError('Invalid DATA')
            for key in ('label','offer'):
                if not isinstance(packet[key],str) or not TOKEN.fullmatch(packet[key]):raise ValueError('Invalid DATA label')
            _opaque(packet['payload'])
            self._prune();binding=self.labels.get((peer,packet['label']))
            if not binding or expires>binding['expires']:return
            if not self._dedupe('DATA',packet['payload'],expires):return
            target=binding['target'];self.stats['received']+=1
            if isinstance(target,tuple):
                offer=self._label(target[0],(peer,packet['offer']),expires)
                self._enqueue(target[0],{**packet,'label':target[1],'offer':offer})
                self.stats['forwarded']+=1
            else:
                await target(peer,packet)
        else:raise ValueError('Unsupported Node packet')

    async def close(self):
        self.closed=True;self.stop_cover()
        for future in self.pending:
            if not future.done():future.set_exception(ConnectionError('Node runtime closed'))
        for timer in self.timers.values():timer.cancel()
        tasks=list(self.tasks)+list(self.senders.values())
        for task in tasks:task.cancel()
        await asyncio.gather(*tasks,return_exceptions=True)
        self.peers.clear();self.labels.clear();self.queues.clear();self.seen.clear();self.owned.clear();self.rates.clear();self.probes.clear()
