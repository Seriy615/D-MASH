"""Opt-in native v4 process lifecycle and protected persistent Node material."""
import base64
import json
import os
from pathlib import Path
import secrets
import stat

if __package__:
    from .capabilities import _bool_env
    from .node_admission_v4 import PasswordGate, PROFILE
    from .node_listener_v4 import NodeListenerV4
    from .node_relationships_v4 import RelationshipStore
    from .node_routing_v4 import NodeRoutingV4
else:
    from capabilities import _bool_env
    from node_admission_v4 import PasswordGate, PROFILE
    from node_listener_v4 import NodeListenerV4
    from node_relationships_v4 import RelationshipStore
    from node_routing_v4 import NodeRoutingV4


def read_private(path, limit=4096):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o077 or info.st_size > limit):
            raise ValueError('Unsafe Node v4 material file')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            return stream.read(limit + 1)
    finally:
        os.close(fd)


def material(path, *, must_exist=False):
    try:
        value = read_private(path, 32)
    except FileNotFoundError:
        if must_exist:
            raise ValueError('Node v4 storage key missing for existing state')
        # O_EXCL prevents concurrent startup from replacing a persisted secret.
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        except FileExistsError:
            value = read_private(path, 32)
        else:
            value = secrets.token_bytes(32)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(value)
                stream.flush()
                os.fsync(stream.fileno())
    if len(value) != 32:
        raise ValueError('Invalid Node v4 material length')
    return value


def load_credential(path):
    value = json.loads(read_private(path))
    if not isinstance(value, dict) or set(value) != {'profile', 'salt', 'epoch', 'key'}:
        raise ValueError('Invalid Node v4 credential')
    if value['profile'] != PROFILE or not isinstance(value['epoch'], str) or len(value['epoch']) != 32:
        raise ValueError('Invalid Node v4 credential profile')
    if any(c not in '0123456789abcdef' for c in value['epoch']):
        raise ValueError('Invalid Node v4 credential epoch')
    for field, length in (('salt', 16), ('key', 32)):
        decoded = base64.b64decode(value[field], validate=True)
        if len(decoded) != length or base64.b64encode(decoded).decode() != value[field]:
            raise ValueError('Invalid Node v4 credential encoding')
        if field == 'key': value[field] = decoded
    return value


class NodeServiceV4:
    @classmethod
    def from_env(cls, signing_key, capabilities):
        if not _bool_env('DMASH_NODE_V4_ENABLED', False):
            return None
        if not capabilities.can_route:
            raise ValueError('Node v4 routing is disabled by Node policy')
        credential_path = os.getenv('DMASH_NODE_V4_CREDENTIAL_FILE')
        if capabilities.visibility == 'private' and not credential_path:
            raise ValueError('Private Node v4 requires a password credential')
        credential = load_credential(credential_path) if credential_path else None
        return cls(signing_key, os.getenv('DMASH_NODE_V4_STATE_DIR', 'node_v4_state'), credential=credential)

    def __init__(self, signing_key, directory, *, credential=None):
        directory = Path(directory)
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = directory.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077):
            raise ValueError('Unsafe Node v4 state directory')
        self.store = self.runtime = self.listener = self.gate = None
        try:
            db = directory / 'relationships.db'
            key = material(directory / 'storage.key', must_exist=db.exists())
            base = material(directory / 'base_ncrh.key', must_exist=db.exists())
            # Directory permissions protect DB and SQLite sidecars as well.
            self.store = RelationshipStore(db, signing_key.verify_key.encode().hex(), key)
            self.runtime = NodeRoutingV4(base)
            self.gate = PasswordGate(credential) if credential else None
            self.listener = NodeListenerV4(signing_key, self.store, self.runtime, password_gate=self.gate)
        except BaseException:
            if self.store: self.store.close()
            raise

    async def close(self):
        try:
            if self.listener: await self.listener.close()
        finally:
            if self.gate: self.gate.revoke_all()
            if self.store: self.store.close()
