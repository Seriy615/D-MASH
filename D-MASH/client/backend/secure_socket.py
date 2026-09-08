"""Async v3 socket adapter. Every send/receive after AUTH is encrypted."""
import asyncio
import json

if __package__:
    from .secure_session import Handshake, MAX_RECORD_BYTES
else:
    from secure_session import Handshake, MAX_RECORD_BYTES

HANDSHAKE_TIMEOUT = 15


class SecureSocket:
    def __init__(self, socket, session):
        self.socket, self.session = socket, session
        self._send_lock = asyncio.Lock()

    async def send_json(self, payload):
        # Sequence allocation and awaited send are one critical section: a
        # mailbox wake and a response must never reorder encrypted records.
        async with self._send_lock:
            try:
                frame = self.session.seal(payload)
                if hasattr(self.socket, "send_json"):
                    await self.socket.send_json(frame)
                else:
                    await self.socket.send(json.dumps(frame))
            except BaseException:
                self.session.close()
                raise

    async def receive_json(self):
        try:
            raw = await (self.socket.receive_text() if hasattr(self.socket, "receive_text") else self.socket.recv())
            if not isinstance(raw, str) or len(raw) > 2 * MAX_RECORD_BYTES:
                raise ValueError("invalid frame size")
            return self.session.open(json.loads(raw))
        except BaseException:
            self.session.close()
            raise

    async def close(self, code=1000, reason=""):
        self.session.close()
        await self.socket.close(code=code, reason=reason)


async def accept_secure(socket, signing_key, expected_role):
    handshake = Handshake(signing_key, "NODE")
    async def receive():
        raw = await (socket.receive_text() if hasattr(socket, "receive_text") else socket.recv())
        if not isinstance(raw, str) or len(raw) > 4096:
            raise ValueError("invalid handshake size")
        return json.loads(raw)
    async def send(value):
        if hasattr(socket, "send_json"): await socket.send_json(value)
        else: await socket.send(json.dumps(value))
    try:
        async with asyncio.timeout(HANDSHAKE_TIMEOUT):
            hello = await receive()
            challenge = handshake.respond(hello, expected_role)
            await send(challenge)
            session = handshake.accept(await receive())
            return SecureSocket(socket, session), hello["public_key"]
    finally:
        handshake.close()


async def connect_secure(socket, signing_key, role, expected_node_id=None):
    handshake = Handshake(signing_key, role)
    session = None
    try:
        async with asyncio.timeout(HANDSHAKE_TIMEOUT):
            await socket.send(json.dumps(handshake.initiate()))
            raw = await socket.recv()
            if not isinstance(raw, str) or len(raw) > 4096:
                raise ValueError("invalid handshake size")
            challenge = json.loads(raw)
            # With no provisioning pin this is first-contact authentication,
            # not proof that the peer is a trusted directory member.
            peer_id = expected_node_id or challenge.get("public_key")
            auth, session = handshake.finish(challenge, peer_id)
            await socket.send(json.dumps(auth))
            return SecureSocket(socket, session), peer_id
    except BaseException:
        if session: session.close()
        raise
    finally:
        handshake.close()
