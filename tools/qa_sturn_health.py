"""Candidate health functions against existing EMS; ephemeral credentials only."""
import asyncio,json,sys,secrets,threading
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'D-MASH/client'))
from websockets.client import connect
from backend.s_turn_health import _proof,probe_relay,probe_signaling,parse_turn_url

async def main():
    url='wss://stage-api-ems.d-mash.ru/signal/v1'
    async with connect(url,compression=None,max_size=512*1024,close_timeout=1) as ws:
        call_id,verifier=secrets.token_hex(32),secrets.token_hex(32)
        await ws.send(json.dumps({'type':'CREATE','call_id':call_id,'secret_verifier':verifier}));challenge=json.loads(await ws.recv())
        counter=await asyncio.to_thread(_proof,challenge['nonce'],call_id,verifier,challenge['difficulty'],threading.Event())
        await ws.send(json.dumps({'type':'PROOF','counter':counter}));created=json.loads(await ws.recv())
        await ws.send(json.dumps({'type':'JOIN','session_id':created['session_id'],'ticket':created['caller_ticket'],'role':'caller'}));joined=json.loads(await ws.recv())
        ice=joined['ice_servers'][0]
        for turn_url in ice['urls']:
            before=set(asyncio.all_tasks())
            assert await probe_relay(turn_url,ice)
            await asyncio.sleep(0)
            assert not (set(asyncio.all_tasks())-before), 'relay background task leak'
            print(json.dumps({'stage':'authenticated-allocation-and-two-way-relay','transport':parse_turn_url(turn_url)[1],'result':'PASS'}),flush=True)
    assert await probe_signaling(url)
    print(json.dumps({'stage':'normal-public-WSS-scoped-tickets-and-two-way-signal','result':'PASS'}),flush=True)

if __name__=='__main__':
    try:asyncio.run(main())
    except Exception as error:print('FAIL candidate S-TURN health: '+type(error).__name__ + (' '+str(error) if isinstance(error,RuntimeError) and str(error) in ('Relay candidate required','Relay integrity failure','Relay return path failure') else ''));raise SystemExit(1)
