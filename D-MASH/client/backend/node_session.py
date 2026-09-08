"""Role-NODE authorization over the common v3 cryptographic session."""
import asyncio
import json
import secrets
import time

if __package__:
    from .resource_pow import activation_pow_difficulty, mine_activation_pow, verify_activation_pow
else:
    from resource_pow import activation_pow_difficulty, mine_activation_pow, verify_activation_pow

NODE_OPERATIONS = frozenset({"MESH_PROBE", "MESH_DATA", "MESH_BATCH", "NODE_CONTROL", "PEER_STATUS"})
NODE_POW_DIFFICULTY = activation_pow_difficulty()


def resource(dnss, session_hash):
    if not isinstance(dnss, str) or len(dnss) != 32 or bytes.fromhex(dnss).hex() != dnss:
        raise ValueError("invalid Node DNSS")
    return "D-MASH|NODE-DNSS|V3|" + session_hash.hex() + "|" + dnss


async def authorize_node(secure, local_id, remote_id):
    """Each side mines its own direction; neither trusts the other's success.

    Fresh per-connection NODE DNSS and transcript-bound work cannot be replayed
    into a different socket. DEVICE DNSS persistence is a separate lifecycle.
    """
    if secure.session.local_role != "NODE" or secure.session.peer_role != "NODE":
        raise PermissionError("Node role required")
    local_dnss = secrets.token_hex(16)
    async with asyncio.timeout(180):
        proof = await asyncio.to_thread(
            mine_activation_pow, remote_id, "DNSS", local_id,
            resource(local_dnss, secure.session.transcript_hash), int(time.time()) + 180,
            NODE_POW_DIFFICULTY,
        )
        await secure.send_json({"type": "NODE_REGISTER", "dnss": local_dnss, "pow": proof})
        request = await secure.receive_json()
        if not isinstance(request, dict) or set(request) != {"type", "dnss", "pow"} or request["type"] != "NODE_REGISTER":
            raise PermissionError("Node registration required")
        remote_dnss = request["dnss"]
        work_resource = resource(remote_dnss, secure.session.transcript_hash)
        proof = request["pow"]
        if (remote_dnss == local_dnss or not isinstance(proof, dict)
                or proof.get("v") != 1 or proof.get("type") != "DNSS"
                or proof.get("resource") != work_resource
                or proof.get("difficulty") != NODE_POW_DIFFICULTY
                or not verify_activation_pow(local_id, "DNSS", remote_id, work_resource,
                    proof.get("nonce"), proof.get("expires_at"), NODE_POW_DIFFICULTY, proof.get("digest"))):
            raise PermissionError("Node work rejected")
        await secure.send_json({"type": "NODE_AUTHORIZED"})
        if await secure.receive_json() != {"type": "NODE_AUTHORIZED"}:
            raise PermissionError("Node authorization incomplete")
    return NodeChannel(secure, local_dnss, remote_dnss)


class NodeChannel:
    """Compatibility adapter for existing transport packet handlers.

    The network wire is always a role-NODE encrypted operation. Old REAL/DUMMY
    wrappers are local to the adapter until the tact migration removes them.
    """
    def __init__(self, secure, local_dnss, remote_dnss):
        self.secure = secure
        self.local_dnss, self.remote_dnss = local_dnss, remote_dnss

    async def send(self, value):
        envelope = json.loads(value)
        if envelope.get("t") == "DUMMY":
            await self.secure.send_json({"type": "NODE_CONTROL", "control": "KEEPALIVE"})
            return
        if envelope.get("t") != "REAL":
            raise ValueError("invalid Node envelope")
        packet = json.loads(envelope["d"])
        if packet.get("type") in {"DMP_C_PROBE", "ROUTE_PROBE_V2"}:
            operation = "MESH_PROBE"
        elif packet.get("type") == "DMP_C_DATA":
            operation = "MESH_DATA"
        else:
            raise PermissionError("unsupported Node packet")
        await self.secure.send_json({"type": operation, "packet": packet})

    def __aiter__(self): return self

    async def __anext__(self):
        value = await self.secure.receive_json()
        operation = value.get("type")
        if operation not in NODE_OPERATIONS:
            raise PermissionError("Device operation on Node connection")
        if operation == "NODE_CONTROL" and value == {"type": "NODE_CONTROL", "control": "KEEPALIVE"}:
            return json.dumps({"t": "DUMMY"})
        expected = {"MESH_PROBE": {"DMP_C_PROBE", "ROUTE_PROBE_V2"}, "MESH_DATA": {"DMP_C_DATA"}}
        packet = value.get("packet")
        if operation not in expected or not isinstance(packet, dict) or packet.get("type") not in expected[operation]:
            raise PermissionError("invalid Node operation")
        return json.dumps({"t": "REAL", "d": json.dumps(packet)})

    async def close(self, code=1000, reason=""):
        self.local_dnss = self.remote_dnss = None
        await self.secure.close(code=code, reason=reason)
