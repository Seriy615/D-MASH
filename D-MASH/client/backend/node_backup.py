"""Encrypted Node recovery bundle and blind object storage foundation."""
from __future__ import annotations

import base64
import json
import os
import secrets
import tempfile
from pathlib import Path

from nacl.secret import SecretBox

DOMAIN = b"D-MASH|NODE-RECOVERY|V1\0"


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


class BlindObjectStore:
    async def put(self, object_id: str, opaque: bytes): raise NotImplementedError
    async def get(self, object_id: str) -> bytes | None: raise NotImplementedError
    async def delete(self, object_id: str): raise NotImplementedError


class LocalBlindObjectStore(BlindObjectStore):
    def __init__(self, directory):
        self.directory = Path(directory)
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        try: os.chmod(self.directory, 0o700)
        except OSError: pass

    @staticmethod
    def _check(object_id):
        if not isinstance(object_id, str) or len(object_id) != 43 or any(c not in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=' for c in object_id):
            raise ValueError('invalid blind object id')

    def _path(self, object_id):
        self._check(object_id)
        return self.directory / object_id

    async def put(self, object_id, opaque):
        if not isinstance(opaque, bytes): raise TypeError('opaque bytes required')
        target = self._path(object_id)
        fd, temporary = tempfile.mkstemp(prefix='.backup-', dir=self.directory)
        try:
            os.chmod(temporary, 0o600)
            with os.fdopen(fd, 'wb') as handle: handle.write(opaque)
            os.replace(temporary, target)
            try: os.chmod(target, 0o600)
            except OSError: pass
        finally:
            if os.path.exists(temporary): os.unlink(temporary)

    async def get(self, object_id):
        try: return self._path(object_id).read_bytes()
        except FileNotFoundError: return None

    async def delete(self, object_id):
        try: self._path(object_id).unlink()
        except FileNotFoundError: pass


def encrypt_bundle(signing_key_hex: str, base_ncrh: bytes, *, generation: int, created_at: int | None = None, recovery_key: bytes | None = None):
    if not isinstance(signing_key_hex, str) or len(signing_key_hex) != 64:
        raise ValueError('invalid signing state')
    try: signing_bytes = bytes.fromhex(signing_key_hex)
    except ValueError as error: raise ValueError('invalid signing state') from error
    if len(signing_bytes) != 32: raise ValueError('invalid signing state')
    if not isinstance(base_ncrh, bytes) or len(base_ncrh) != 32: raise ValueError('invalid BaseNCRH')
    if type(generation) is not int or generation < 1: raise ValueError('invalid recovery generation')
    key = recovery_key or secrets.token_bytes(SecretBox.KEY_SIZE)
    if len(key) != SecretBox.KEY_SIZE: raise ValueError('invalid recovery key')
    payload = {'version': 1, 'created_at': int(created_at or __import__('time').time()),
               'recovery_generation': generation,
               'persistent_secret_state': {'signing_key_hex': signing_key_hex, 'base_ncrh_hex': base_ncrh.hex()},
               'integrity': 'D-MASH|NODE-RECOVERY|V1'}
    nonce = secrets.token_bytes(SecretBox.NONCE_SIZE)
    ciphertext = bytes(SecretBox(key).encrypt(_canonical(payload), nonce))
    return {'version': 1, 'object_id': base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip('='),
            'recovery_key': base64.urlsafe_b64encode(key).decode().rstrip('='),
            'ciphertext': ciphertext, 'payload': payload}


def decrypt_bundle(ciphertext: bytes, recovery_key: bytes):
    if not isinstance(ciphertext, bytes) or len(recovery_key) != SecretBox.KEY_SIZE: raise ValueError('invalid recovery object')
    payload = json.loads(SecretBox(recovery_key).decrypt(ciphertext).decode('ascii'))
    if payload.get('version') != 1 or payload.get('integrity') != 'D-MASH|NODE-RECOVERY|V1': raise ValueError('invalid recovery bundle')
    state = payload.get('persistent_secret_state', {})
    try:
        signing = bytes.fromhex(state.get('signing_key_hex', ''))
        base = bytes.fromhex(state.get('base_ncrh_hex', ''))
    except (TypeError, ValueError) as error:
        raise ValueError('invalid persistent state') from error
    if len(signing) != 32 or len(base) != 32: raise ValueError('invalid persistent state')
    return payload


async def backup_node(store: BlindObjectStore, signing_key_hex, base_ncrh, *, generation):
    bundle = encrypt_bundle(signing_key_hex, base_ncrh, generation=generation)
    await store.put(bundle['object_id'], bundle['ciphertext'])
    return bundle['object_id'], bundle['recovery_key']


def restore_node_files(payload, identity_path, base_ncrh_path):
    state = payload['persistent_secret_state']
    signing = state['signing_key_hex']; base = bytes.fromhex(state['base_ncrh_hex'])
    if len(base) != 32: raise ValueError('invalid BaseNCRH')
    paths = [(os.path.abspath(identity_path), signing.encode()),
             (os.path.abspath(base_ncrh_path), base.hex().encode())]
    for path, _ in paths:
        os.makedirs(os.path.dirname(path) or '.', mode=0o700, exist_ok=True)
    # Stage both files before changing either destination. If a replacement
    # fails, restore the exact previous pair (including the absent-file case).
    staged = []
    previous = {path: (os.path.exists(path), Path(path).read_bytes() if os.path.exists(path) else None)
                for path, _ in paths}
    try:
        for path, value in paths:
            fd, temporary = tempfile.mkstemp(prefix='.restore-', dir=os.path.dirname(path) or '.')
            os.chmod(temporary, 0o600)
            with os.fdopen(fd, 'wb') as handle: handle.write(value)
            staged.append((temporary, path))
        for temporary, path in staged: os.replace(temporary, path)
        staged.clear()
        for _, path in paths:
            try: os.chmod(path, 0o600)
            except OSError: pass
    except BaseException:
        for path, _ in paths:
            existed, value = previous[path]
            try:
                if existed:
                    fd, temporary = tempfile.mkstemp(prefix='.rollback-', dir=os.path.dirname(path) or '.')
                    os.chmod(temporary, 0o600)
                    with os.fdopen(fd, 'wb') as handle: handle.write(value)
                    os.replace(temporary, path)
                    if os.path.exists(temporary): os.unlink(temporary)
                else:
                    os.unlink(path)
            except FileNotFoundError:
                pass
        raise
    finally:
        for temporary, _ in staged:
            if os.path.exists(temporary): os.unlink(temporary)
    # Blind aliases are a RAM namespace. A restored process must install this
    # fresh value in NodeCryptoManager instead of deriving or importing it.
    return secrets.token_bytes(32)
