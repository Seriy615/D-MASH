import asyncio
import unittest
from backend.s_turn import STurnService
from backend.s_turn_health import STurnHealthMonitor,parse_turn_url

class STurnHealthTests(unittest.IsolatedAsyncioTestCase):
    async def test_transport_then_signaling_truth_freshness_and_partial_url_failure(self):
        now=[100.];calls=[];working={'udp':True,'tcp':True};signal=[True]
        service=STurnService(signaling_wss='wss://example.invalid/signal/v1',turn_urls=('turn:example.invalid:3479?transport=udp','turn:example.invalid:3479?transport=tcp'),shared_secret=b'h'*32)
        async def relay(url,credentials):
            self.assertNotIn('h'*32,str(credentials));self.assertGreater(credentials['expires_at'],0)
            return working[parse_turn_url(url)[1]]
        async def signaling(url):
            self.assertTrue(service.available(),'normal admission must bootstrap without claiming healthy')
            calls.append(url);return signal[0]
        monitor=STurnHealthMonitor(service,clock=lambda:now[0],relay_probe=relay,signaling_probe=signaling);service.health_monitor=monitor
        self.assertFalse(service.healthy());self.assertFalse(service.available())
        self.assertTrue(await monitor.check_once());self.assertTrue(service.healthy());self.assertEqual(len(service.ready_turn_urls()),2)
        working['tcp']=False;self.assertTrue(await monitor.check_once());self.assertEqual(service.descriptor()['turn_urls'],[service.turn_urls[0]])
        signal[0]=False;self.assertFalse(await monitor.check_once());self.assertEqual(service.descriptor(),{'can_s_turn':False});self.assertTrue(service.available())
        signal[0]=True;await monitor.check_once();now[0]+=46;self.assertFalse(service.healthy());self.assertFalse(service.available())
        working['udp']=False;count=len(calls);self.assertFalse(await monitor.check_once());self.assertEqual(len(calls),count)
        service.close();await service.wait_closed()

    async def test_close_cancels_checker_and_late_result_never_advertises(self):
        began=asyncio.Event();cancelled=asyncio.Event()
        service=STurnService(signaling_wss='wss://example.invalid/signal/v1',turn_urls=('turn:example.invalid:3479',),shared_secret=b'h'*32)
        async def relay(*args):
            began.set()
            try:await asyncio.Event().wait()
            finally:cancelled.set()
        monitor=STurnHealthMonitor(service,relay_probe=relay);service.health_monitor=monitor;service.start_health_monitor();await began.wait();service.close();await service.wait_closed();self.assertTrue(cancelled.is_set());self.assertFalse(service.available());self.assertFalse(service.healthy())

    async def test_checker_never_overlaps_and_unknown_profiles_fail_closed(self):
        entered=asyncio.Event();finish=asyncio.Event()
        service=STurnService(signaling_wss='wss://example.invalid/signal/v1',turn_urls=('turn:example.invalid:3479',),shared_secret=b'h'*32)
        async def relay(*args):entered.set();await finish.wait();return False
        monitor=STurnHealthMonitor(service,relay_probe=relay);service.health_monitor=monitor
        first=asyncio.create_task(monitor.check_once());await entered.wait();self.assertFalse(await monitor.check_once());finish.set();await first
        for url in ('turn:example.invalid:3479?transport=quic','turn:example.invalid:3479?transport=udp&transport=tcp','turn:user:password@example.invalid:3479'):
            with self.assertRaises(ValueError):parse_turn_url(url)
        service.close()

    async def test_relay_cancel_during_allocation_closes_socket_and_refresh(self):
        from unittest.mock import patch
        from backend.s_turn_health import probe_relay
        entered=asyncio.Event();closed=[];refresh_ended=asyncio.Event()
        async def refresh():
            try:await asyncio.Event().wait()
            finally:refresh_ended.set()
        class Protocol:
            def __init__(self,*args,**kwargs):
                self.refresh_task=asyncio.create_task(refresh())
                self.receiver=None
                self.kwargs=kwargs
            async def connect(self):entered.set();await asyncio.Event().wait()
            async def delete(self):closed.append('allocation-delete')
        class Socket:
            def close(self):closed.append('socket-close')
        async def endpoint(factory,**kwargs):return Socket(),factory()
        loop=asyncio.get_running_loop()
        with patch('backend.s_turn_health.TurnClientUdpProtocol',Protocol),patch.object(loop,'create_datagram_endpoint',endpoint):
            task=asyncio.create_task(probe_relay('turn:example.invalid:3479',{'username':'temporary','credential':'temporary'}))
            await entered.wait();task.cancel()
            with self.assertRaises(asyncio.CancelledError):await task
        self.assertEqual(closed,['allocation-delete','socket-close']);self.assertTrue(refresh_ended.is_set())

    async def test_relay_failed_delete_is_bounded_and_still_closes_socket(self):
        from unittest.mock import patch
        from backend.s_turn_health import probe_relay
        closed=[]
        class Protocol:
            refresh_task=None
            def __init__(self,*args,**kwargs):self.receiver=None
            async def connect(self):raise RuntimeError('allocation denied')
            async def delete(self):await asyncio.Event().wait()
        class Socket:
            def close(self):closed.append(True)
        async def endpoint(factory,**kwargs):return Socket(),factory()
        loop=asyncio.get_running_loop();started=loop.time()
        with patch('backend.s_turn_health.TurnClientUdpProtocol',Protocol),patch.object(loop,'create_datagram_endpoint',endpoint):
            with self.assertRaises(RuntimeError):await probe_relay('turn:example.invalid:3479',{'username':'temporary','credential':'temporary'})
        self.assertEqual(closed,[True]);self.assertLess(loop.time()-started,3)
