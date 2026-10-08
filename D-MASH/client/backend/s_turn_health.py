"""Bounded real S-TURN allocation/relay and public signaling health.

No Account identifiers, permanent credentials in logs, or special health wire role.
The normal signaling admission path is exercised with ephemeral tickets.
"""
from __future__ import annotations
import asyncio
import hashlib
import json
import secrets
import time
import re
import threading
from urllib.parse import parse_qs, urlparse
from aioice.turn import TurnClientTcpProtocol, TurnClientUdpProtocol
from websockets.client import connect


def parse_turn_url(url):
    parsed=urlparse(url.replace('turn:', 'turn://', 1))
    query=parse_qs(parsed.query)
    if parsed.scheme!='turn' or not parsed.hostname or parsed.username or parsed.password or set(query)-{'transport'}:
        raise ValueError('Unsupported TURN health URL')
    transport=query.get('transport',['udp'])
    if len(transport)!=1 or transport[0] not in ('udp','tcp'):
        raise ValueError('Unsupported TURN health transport')
    return (parsed.hostname,parsed.port or 3478),transport[0]


class _RelayReceiver(asyncio.DatagramProtocol):
    def __init__(self):self.queue=asyncio.Queue(maxsize=8)
    def datagram_received(self,data,addr):
        if data and not self.queue.full():self.queue.put_nowait((data,addr))


async def probe_relay(url,credentials,*,timeout=12):
    """Pinned aioice 0.10.2 adapter: owned sockets/tasks, no detached sends.

    Both peers are actual TURN allocations. ICE/browser acceptance is separate.
    Allocation lifetime is 30 seconds even if deletion cannot reach the server.
    """
    server,transport=parse_turn_url(url);loop=asyncio.get_running_loop();owned=[]
    async def allocate():
        receiver=_RelayReceiver()
        factory=lambda:(TurnClientTcpProtocol if transport=='tcp' else TurnClientUdpProtocol)(
            server,username=credentials['username'],password=credentials['credential'],lifetime=30,channel_refresh_time=20)
        if transport=='tcp':sock,protocol=await loop.create_connection(factory,host=server[0],port=server[1])
        else:sock,protocol=await loop.create_datagram_endpoint(factory,remote_addr=server)
        owned.append((sock,protocol));protocol.receiver=receiver
        address=await protocol.connect()
        return protocol,receiver,address
    try:
        async with asyncio.timeout(timeout):
            left=await allocate();right=await allocate()
            # Open permissions in both directions before sending the nonce.
            await left[0].send_data(b'',right[2]);await right[0].send_data(b'',left[2])
            nonce=secrets.token_bytes(64);await left[0].send_data(nonce,right[2])
            if await right[1].queue.get()!=(nonce,left[2]):raise RuntimeError('Relay integrity failure')
            reply=hashlib.sha256(nonce).digest();await right[0].send_data(reply,left[2])
            if await left[1].queue.get()!=(reply,right[2]):raise RuntimeError('Relay return path failure')
            return True
    finally:
        async def cleanup(sock,protocol):
            refresh=protocol.refresh_task
            if refresh:refresh.cancel()
            try:
                async with asyncio.timeout(2):await protocol.delete()
            except (Exception,asyncio.CancelledError):pass
            finally:
                sock.close()
                if refresh:await asyncio.gather(refresh,return_exceptions=True)
        await asyncio.gather(*(cleanup(*entry) for entry in owned),return_exceptions=True)


def _proof(nonce,call_id,verifier,difficulty,stop):
    if type(difficulty) is not int or not 1<=difficulty<=20:raise ValueError('Signaling work bounds')
    if not isinstance(nonce,str) or not re.fullmatch('[0-9a-f]{64}',nonce):raise ValueError('Signaling nonce bounds')
    deadline=time.monotonic()+8
    prefix=f'{nonce}:{call_id}:{verifier}:';limit=1<<(256-difficulty)
    for counter in range(1<<26):
        if counter%1024==0 and (stop.is_set() or time.monotonic()>deadline):raise RuntimeError('Signaling work cancelled')
        if int.from_bytes(hashlib.sha256((prefix+str(counter)).encode('ascii')).digest(),'big')<limit:return counter
    raise RuntimeError('Signaling work exhausted')


async def probe_signaling(url,*,timeout=12):
    """Use normal CREATE/proof/scoped JOIN; verify both relay directions."""
    if not isinstance(url,str) or not url.startswith('wss://'):raise ValueError('TLS signaling required')
    async with asyncio.timeout(timeout):
        async with connect(url,compression=None,max_size=512*1024,max_queue=8,open_timeout=4,close_timeout=1) as caller:
            call_id,verifier=secrets.token_hex(32),secrets.token_hex(32)
            await caller.send(json.dumps({'type':'CREATE','call_id':call_id,'secret_verifier':verifier}))
            challenge=json.loads(await caller.recv())
            if set(challenge)!={'type','nonce','difficulty'} or challenge['type']!='CHALLENGE':raise RuntimeError('Signaling challenge missing')
            stop=threading.Event()
            try:counter=await asyncio.to_thread(_proof,challenge['nonce'],call_id,verifier,challenge['difficulty'],stop)
            finally:stop.set()
            await caller.send(json.dumps({'type':'PROOF','counter':counter}));created=json.loads(await caller.recv())
            if created.get('type')!='CREATED':raise RuntimeError('Signaling creation failed')
            await caller.send(json.dumps({'type':'JOIN','session_id':created['session_id'],'ticket':created['caller_ticket'],'role':'caller'}))
            if json.loads(await caller.recv()).get('type')!='JOINED':raise RuntimeError('Signaling caller join failed')
            async with connect(url,compression=None,max_size=512*1024,max_queue=8,open_timeout=4,close_timeout=1) as callee:
                await callee.send(json.dumps({'type':'JOIN','session_id':created['session_id'],'ticket':created['callee_ticket'],'role':'callee'}))
                if json.loads(await callee.recv()).get('type')!='JOINED':raise RuntimeError('Signaling callee join failed')
                nonce=secrets.token_hex(32);offer={'type':'offer','payload':nonce}
                await caller.send(json.dumps(offer))
                if json.loads(await callee.recv())!=offer:raise RuntimeError('Signaling forward mismatch')
                answer={'type':'answer','payload':hashlib.sha256(nonce.encode()).hexdigest()};await callee.send(json.dumps(answer))
                if json.loads(await caller.recv())!=answer:raise RuntimeError('Signaling return mismatch')
                return True


class STurnHealthMonitor:
    """One bounded background checker; synchronous readers only inspect freshness."""
    def __init__(self,service,*,clock=time.monotonic,interval=15,freshness=45,
                 relay_probe=probe_relay,signaling_probe=probe_signaling):
        if not 1<=interval<freshness<=120:raise ValueError('Health timing bounds')
        if not 1<=len(service.turn_urls)<=4:raise ValueError('Health TURN URL count')
        for url in service.turn_urls:parse_turn_url(url)
        self.service=service;self.clock=clock;self.interval=interval;self.freshness=freshness
        self.relay_probe=relay_probe;self.signaling_probe=signaling_probe
        self._urls=();self._transport_at=None;self._signaling_at=None;self._task=None;self._closed=False;self._checking=False
    def available_urls(self):
        if self._closed or self._transport_at is None or self.clock()-self._transport_at>self.freshness:return ()
        return self._urls
    def healthy(self):
        return bool(self.available_urls() and self._signaling_at is not None and self.clock()-self._signaling_at<=self.freshness)
    async def check_once(self):
        if self._closed or self._checking:return False
        self._checking=True
        try:
            ready=[];checked_at=[]
            for url in self.service.turn_urls:
                try:
                    credentials=self.service._turn_credentials(ttl=60)
                    if await self.relay_probe(url,credentials):ready.append(url);checked_at.append(self.clock())
                except asyncio.CancelledError:raise
                except Exception:pass
                if self._closed:return False
            self._urls=tuple(ready);self._transport_at=min(checked_at) if ready else None
            if not ready:self._signaling_at=None;return False
            # Transport-ready allows normal admission before advertising ready.
            # This avoids a self-test bootstrap cycle without an auth bypass.
            try:signal_ok=await self.signaling_probe(self.service.signaling_wss)
            except asyncio.CancelledError:raise
            except Exception:signal_ok=False
            if self._closed:return False
            self._signaling_at=self.clock() if signal_ok else None
            return self.healthy()
        finally:self._checking=False
    def start(self):
        if self._closed or self._task is not None:return
        async def run():
            while not self._closed:
                try:await self.check_once()
                except asyncio.CancelledError:raise
                except Exception:self._urls=();self._transport_at=None;self._signaling_at=None
                await asyncio.sleep(self.interval)
        self._task=asyncio.create_task(run())
    def close(self):
        self._closed=True;self._urls=();self._transport_at=None;self._signaling_at=None
        if self._task:self._task.cancel()
    async def wait_closed(self):
        if self._task:await asyncio.gather(self._task,return_exceptions=True)
