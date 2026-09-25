"""Loopback-only browser interoperability fixture; never a production entrypoint."""
import asyncio
import base64
import json
from pathlib import Path
import sys
import tempfile
from nacl.signing import SigningKey
from websockets.server import serve
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'D-MASH/client'))
from backend.crypto import NodeCryptoManager
from backend.secure_socket import accept_secure
from backend.node_channel_v4 import authorize_node_v4
from backend.node_admission_v4 import PasswordGate,password_credential,derive_password_key
from backend.node_relationships_v4 import RelationshipStore

async def main():
    while True:
        key=SigningKey.generate()
        if NodeCryptoManager.verify_node_pow(key.verify_key.encode().hex()):break
    gate=PasswordGate(password_credential('loopback-test-password'))
    with tempfile.TemporaryDirectory() as tmp:
        store=RelationshipStore(Path(tmp)/'relations.db',key.verify_key.encode().hex(),bytes([91])*32)
        attempts=0
        async def handle(socket):
            nonlocal attempts
            attempts+=1
            attempt=attempts
            secure=channel=None
            try:
                secure,_=await accept_secure(socket,key,'NODE',version=4)
                async def password_key(peer,challenge):
                    return await asyncio.to_thread(derive_password_key,('wrong-test-password' if attempt==3 else 'browser-loopback-password'),base64.b64decode(challenge['salt']))
                channel=await authorize_node_v4(secure,store,password_gate=gate,difficulty=20,peer_password_key=password_key,require_peer_password=True)
                await channel.send_operation({'type':'TEST_READY','version':4})
                request=await channel.receive_operation()
                if set(request)!={'type','ciphertext'} or request['type']!='TEST_ECHO':raise ValueError()
                await channel.send_operation(request)
                # Wait for intentional peer closure, not an early fixture disconnect.
                await channel.receive_operation()
            except Exception:
                pass
            finally:
                if channel:await channel.close()
                elif secure:await secure.close()
        async with serve(handle,'127.0.0.1',0,max_size=2*1024*1024) as server:
            print(json.dumps({'port':server.sockets[0].getsockname()[1],'nodeId':key.verify_key.encode().hex()}),flush=True)
            stop=asyncio.Event()
            asyncio.get_running_loop().add_reader(sys.stdin.fileno(),stop.set)
            await stop.wait()
            asyncio.get_running_loop().remove_reader(sys.stdin.fileno())
        store.close()

asyncio.run(main())
