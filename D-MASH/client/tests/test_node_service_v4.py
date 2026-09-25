import asyncio
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch, AsyncMock
from nacl.signing import SigningKey
from backend.node_service_v4 import NodeServiceV4, material, load_credential
from backend.gateway_v4 import node_v4

class ServiceTests(unittest.IsolatedAsyncioTestCase):
    async def test_restart_preserves_material_and_directional_relationship(self):
        with tempfile.TemporaryDirectory() as directory:
            key, peer = SigningKey.generate(), SigningKey.generate().verify_key.encode().hex()
            service = NodeServiceV4(key, directory)
            relation = service.store.relationship(peer)
            base = service.runtime.base
            await service.close()
            service = NodeServiceV4(key, directory)
            self.assertEqual(service.store.relationship(peer), relation)
            self.assertEqual(service.runtime.base, base)
            await service.close()
            Path(directory, 'storage.key').unlink()
            with self.assertRaisesRegex(ValueError, 'missing'):
                NodeServiceV4(key, directory)

    async def test_disabled_and_private_policy_fail_closed(self):
        policy = SimpleNamespace(can_route=True, visibility='private')
        with patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(NodeServiceV4.from_env(None, policy))
        with patch.dict(os.environ, {'DMASH_NODE_V4_ENABLED':'1'}, clear=True):
            with self.assertRaisesRegex(ValueError, 'credential'):
                NodeServiceV4.from_env(None, policy)
            policy.can_route=False
            with self.assertRaisesRegex(ValueError, 'policy'):
                NodeServiceV4.from_env(None, policy)

    async def test_gateway_does_not_accept_disabled_upgrade(self):
        socket = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace()), close=AsyncMock(), accept=AsyncMock())
        await node_v4(socket)
        socket.close.assert_awaited_once_with(code=1008)
        socket.accept.assert_not_awaited()
        listener=SimpleNamespace(handle=AsyncMock())
        socket.app.state.node_v4=SimpleNamespace(listener=listener)
        await node_v4(socket)
        listener.handle.assert_awaited_once_with(socket, accept=True)

    def test_material_refuses_symlinks_permissions_and_corruption(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory,'key')
            material(path)
            path.chmod(0o644)
            with self.assertRaises(ValueError): material(path)
            path.chmod(0o600)
            path.write_bytes(b'bad')
            with self.assertRaises(ValueError): material(path)
            link=Path(directory,'link');link.symlink_to(path)
            with self.assertRaises(OSError): material(link)

    def test_credential_file_is_bounded_and_private(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory,'credential')
            path.write_text(json.dumps({'profile':'ARGON2ID_64M_T3_P1_V1','salt':'AAAAAAAAAAAAAAAAAAAAAA==','epoch':'a'*32,'key':'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='}))
            path.chmod(0o600)
            self.assertEqual(load_credential(path)['key'],bytes(32))
            path.chmod(0o644)
            with self.assertRaises(ValueError): load_credential(path)
