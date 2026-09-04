import base64
import asyncio
from dataclasses import dataclass
import json
import os
import tempfile
import time
import unittest
from unittest.mock import patch

from nacl.encoding import HexEncoder
from nacl.signing import SigningKey
from starlette.websockets import WebSocketDisconnect

import backend.client_gateway as gateway
from backend.client_gateway import (
    auth_transcript,
    device_auth_transcript,
    verify_auth,
    verify_device_auth,
    router,
)
from backend.registration_registry import RegistrationRegistry
from backend.resource_pow import activation_pow_difficulty, mine_activation_pow


class ClientGatewayAuthTests(unittest.TestCase):
    class GatewaySocket:
        """Minimal ASGI WebSocket surface used by the real gateway coroutine."""
        def __init__(self, inbound):
            self.inbound = list(inbound)
            self.sent = []
            self.closed = None

        async def accept(self):
            return None

        async def send_json(self, payload):
            self.sent.append(payload)

        async def receive_text(self):
            if not self.inbound:
                raise RuntimeError("test socket has no more frames")
            frame = self.inbound.pop(0)
            if frame == "__DISCONNECT__":
                raise WebSocketDisconnect()
            return frame(self.sent) if callable(frame) else frame

        async def close(self, code=1000, reason=""):
            self.closed = (code, reason)

    def setUp(self):
        # Keep production difficulty at its safe floor.  Patch only the
        # gateway module's threshold for this unit fixture, so the suite
        # exercises the real verifier without mining several 20+-bit proofs.
        self.assertGreaterEqual(activation_pow_difficulty(), 20)
        self.pow_difficulty = 4
        self.activation_pow_difficulty = patch.object(
            gateway, "ACTIVATION_POW_DIFFICULTY", self.pow_difficulty,
        )
        self.activation_pow_difficulty.start()
        self.node_key = SigningKey.generate()
        self.previous_runtime_state = gateway.runtime_state
        self.previous_registry_factory = gateway.registration_registry_factory
        handle, self.registry_path = tempfile.mkstemp(prefix="dmash-gateway-registration-", suffix=".sqlite")
        os.close(handle)
        gateway.registration_registry_factory = lambda node_crypto: RegistrationRegistry(self.registry_path, node_crypto)
        # Gateway auth needs only NodeID and a capability policy. The test
        # never requests a transport operation, so no routing/session state is
        # fabricated or persisted.
        gateway.runtime_state = lambda: type("State", (), {
            "node_crypto": type("NodeCrypto", (), {
                "node_id": self.node_key.verify_key.encode().hex(),
                "secret_salt": b"g" * 32,
            })(),
            "capabilities": None,
            "node": None,
        })()

    def _activation_pow(self, client_key, activation_type, resource, *, node_id=None,
                        start_nonce=0, expires_at=None):
        """Return the canonical, device- and node-bound activation proof."""
        return mine_activation_pow(
            node_id or self.node_key.verify_key.encode().hex(),
            activation_type,
            client_key.verify_key.encode().hex(),
            resource,
            int(time.time()) + 60 if expires_at is None else expires_at,
            difficulty=self.pow_difficulty,
            start_nonce=start_nonce,
        )

    def test_activation_pow_wire_proof_is_json_safe_and_canonical(self):
        client_key = SigningKey.generate()
        resource = bytes.fromhex("01" * 16)

        proof = self._activation_pow(client_key, "DNSS", resource)

        self.assertEqual(proof["resource"], resource.hex())
        self.assertIsInstance(proof["digest"], str)
        self.assertEqual(json.loads(json.dumps(proof)), proof)

    def tearDown(self):
        self.activation_pow_difficulty.stop()
        gateway.runtime_state = self.previous_runtime_state
        gateway.registration_registry_factory = self.previous_registry_factory
        if os.path.exists(self.registry_path):
            os.unlink(self.registry_path)

    def _authenticated_frames(self, client_key, *requests):
        """Build a DEVICE_AUTH_V1 exchange followed by public DMP-C frames."""
        def valid_auth(sent):
            challenge = sent[0]
            client_nonce = "client-nonce-gateway-tests-01"
            transcript = device_auth_transcript(
                challenge["node_id"], challenge["session_id"], challenge["nonce"],
                client_nonce, challenge["expires_at"],
            )
            return json.dumps({
                "type": "AUTH", "auth_mode": "DEVICE_AUTH_V1",
                "public_key": client_key.verify_key.encode().hex(),
                "client_nonce": client_nonce,
                "signature": base64.b64encode(client_key.sign(transcript).signature).decode("ascii"),
            })
        return [valid_auth, *(json.dumps(request) for request in requests), "__DISCONNECT__"]

    def _install_routing_state(self, transport, operations=None):
        """Install an in-memory, routing-capable Node facade for the gateway."""
        capabilities = type("Capabilities", (), {
            "advertised_operations": lambda self: operations or frozenset({"STATUS", "START_PROBE", "ROUTE_STATUS"}),
        })()
        gateway.runtime_state = lambda: type("State", (), {
            "node_crypto": type("NodeCrypto", (), {
                "node_id": self.node_key.verify_key.encode().hex(),
                "secret_salt": b"g" * 32,
            })(),
            "capabilities": capabilities,
            "node": type("Node", (), {"active_connections": [], "transport": transport})(),
        })()

    def test_v2_websocket_authenticates_only_valid_device_transcript(self):
        client_key = SigningKey.generate()
        def valid_auth(sent):
            challenge = sent[0]
            client_nonce = "client-nonce-0123456789"
            transcript = device_auth_transcript(
                challenge["node_id"], challenge["session_id"], challenge["nonce"],
                client_nonce, challenge["expires_at"],
            )
            return __import__("json").dumps({
                "type": "AUTH", "auth_mode": "DEVICE_AUTH_V1",
                "public_key": client_key.verify_key.encode().hex(), "client_nonce": client_nonce,
                "signature": base64.b64encode(client_key.sign(transcript).signature).decode("ascii"),
            })
        websocket = self.GatewaySocket([valid_auth, "__DISCONNECT__"])
        asyncio.run(gateway.dmp_client(websocket))
        self.assertEqual(websocket.sent[0]["auth_mode"], "DEVICE_AUTH_V1")
        self.assertEqual(websocket.sent[0]["version"], 2)
        self.assertEqual(websocket.sent[0]["node_id"], self.node_key.verify_key.encode().hex())
        self.assertEqual(websocket.sent[1]["type"], "AUTH_OK")
        self.assertEqual(websocket.sent[1]["auth_mode"], "DEVICE_AUTH_V1")

    def test_v2_websocket_keeps_runtime_state_for_post_auth_status(self):
        client_key = SigningKey.generate()

        def valid_auth(sent):
            challenge = sent[0]
            client_nonce = "client-nonce-status-012345"
            transcript = device_auth_transcript(
                challenge["node_id"], challenge["session_id"], challenge["nonce"],
                client_nonce, challenge["expires_at"],
            )
            return __import__("json").dumps({
                "type": "AUTH", "auth_mode": "DEVICE_AUTH_V1",
                "public_key": client_key.verify_key.encode().hex(), "client_nonce": client_nonce,
                "signature": base64.b64encode(client_key.sign(transcript).signature).decode("ascii"),
            })

        websocket = self.GatewaySocket([valid_auth, __import__("json").dumps({"type": "STATUS", "request_id": "status-1"}), "__DISCONNECT__"])
        asyncio.run(gateway.dmp_client(websocket))
        self.assertEqual(websocket.sent[1]["type"], "AUTH_OK")
        self.assertEqual(websocket.sent[2], {
            "type": "STATUS", "request_id": "status-1",
            "node_id": self.node_key.verify_key.encode().hex(), "mesh_peers": 0,
        })

    def test_authenticated_route_status_reports_unknown_and_ready_minimal_topology(self):
        class Transport:
            async def route_status(self, locator):
                if locator == "unknown-route":
                    return {"state": "ROUTE_UNKNOWN"}
                return {
                    "state": "ROUTE_READY", "best_metric": 4,
                    "expires_at": 1_900_000_000,
                }

            def detach_local_delivery_session(self, session):
                pass

        self._install_routing_state(Transport())
        client_key = SigningKey.generate()
        websocket = self.GatewaySocket(self._authenticated_frames(
            client_key,
            {"type": "ROUTE_STATUS", "request_id": "route-unknown", "route_locator": "unknown-route"},
            {"type": "ROUTE_STATUS", "request_id": "route-ready", "route_locator": "ready-route"},
        ))

        asyncio.run(gateway.dmp_client(websocket))

        self.assertEqual(websocket.sent[2], {
            "type": "ROUTE_STATUS_RESULT", "request_id": "route-unknown",
            "state": "ROUTE_UNKNOWN",
        })
        self.assertEqual(websocket.sent[3], {
            "type": "ROUTE_STATUS_RESULT", "request_id": "route-ready",
            "state": "ROUTE_READY", "best_metric": 4, "expires_at": 1_900_000_000,
        })

    def test_registration_operations_are_advertised_only_for_routing_capable_state(self):
        client_key = SigningKey.generate()
        websocket = self.GatewaySocket(self._authenticated_frames(
            client_key,
            {"type": "REGISTER_DNSS", "request_id": "not-route-capable", "dnss": "00" * 16},
        ))

        asyncio.run(gateway.dmp_client(websocket))

        self.assertNotIn("REGISTER_DNSS", websocket.sent[1]["capabilities"])
        self.assertNotIn("REGISTER_ENTRY_GRANT", websocket.sent[1]["capabilities"])
        self.assertEqual(websocket.sent[2], {
            "type": "ERROR", "request_id": "not-route-capable",
            "code": "UNSUPPORTED_OPERATION",
        })

    def test_authenticated_dnss_registration_accepts_128_bit_values_and_returns_blind_handle(self):
        class Transport:
            def detach_local_delivery_session(self, session):
                pass

        self._install_routing_state(Transport())
        client_key = SigningKey.generate()
        dnss_hex = "0123456789abcdef" * 2
        dnss_b64 = base64.urlsafe_b64encode(bytes.fromhex(dnss_hex)).decode("ascii").rstrip("=")
        first_proof = self._activation_pow(client_key, "DNSS", bytes.fromhex(dnss_hex))
        websocket = self.GatewaySocket(self._authenticated_frames(
            client_key,
            {"type": "REGISTER_DNSS", "request_id": "dnss-hex", "dnss": dnss_hex,
             "pow": first_proof},
            {"type": "REGISTER_DNSS", "request_id": "dnss-b64", "dnss": dnss_b64,
             "pow": self._activation_pow(
                 client_key, "DNSS", base64.urlsafe_b64decode(dnss_b64 + "=="),
                 start_nonce=first_proof["nonce"] + 1,
             )},
        ))

        asyncio.run(gateway.dmp_client(websocket))

        self.assertIn("REGISTER_DNSS", websocket.sent[1]["capabilities"])
        for result in websocket.sent[2:]:
            self.assertEqual(result["type"], "REGISTER_DNSS_RESULT")
            self.assertRegex(result["dnss_handle"], r"^[0-9a-f]{64}$")
            self.assertNotIn(dnss_hex, json.dumps(result))
            self.assertNotIn(dnss_b64, json.dumps(result))

    def test_authenticated_dnss_registration_rejects_malformed_values(self):
        class Transport:
            def detach_local_delivery_session(self, session):
                pass

        self._install_routing_state(Transport())
        client_key = SigningKey.generate()
        websocket = self.GatewaySocket(self._authenticated_frames(
            client_key,
            {"type": "REGISTER_DNSS", "request_id": "empty", "dnss": ""},
            {"type": "REGISTER_DNSS", "request_id": "short", "dnss": "00" * 15},
            {"type": "REGISTER_DNSS", "request_id": "bad-hex", "dnss": "gg" * 16},
            {"type": "REGISTER_DNSS", "request_id": "bad-b64", "dnss": "not-base64!"},
        ))

        asyncio.run(gateway.dmp_client(websocket))

        self.assertEqual(websocket.sent[2:], [
            {"type": "ERROR", "request_id": "empty", "code": "INVALID_DNSS"},
            {"type": "ERROR", "request_id": "short", "code": "INVALID_DNSS"},
            {"type": "ERROR", "request_id": "bad-hex", "code": "INVALID_DNSS"},
            {"type": "ERROR", "request_id": "bad-b64", "code": "INVALID_DNSS"},
        ])

    def test_authenticated_entry_grant_accepts_node_bound_grant_and_rejects_wrong_node(self):
        class Transport:
            def detach_local_delivery_session(self, session):
                pass

        self._install_routing_state(Transport())
        client_key = SigningKey.generate()
        route_key = SigningKey.generate()
        route_public_key = route_key.verify_key.encode(encoder=HexEncoder).decode("ascii")
        valid_grant = gateway.EntryGrantV1.issue(self.node_key, route_public_key, int(time.time()) + 60)
        wrong_node = SigningKey.generate()
        wrong_grant = gateway.EntryGrantV1.issue(wrong_node, route_public_key, int(time.time()) + 60)
        websocket = self.GatewaySocket(self._authenticated_frames(
            client_key,
            {"type": "REGISTER_ENTRY_GRANT", "request_id": "grant-valid", "entry_grant": valid_grant.to_dict(),
             "pow": self._activation_pow(client_key, "ENTRY_GRANT", valid_grant.route_id)},
            {"type": "REGISTER_ENTRY_GRANT", "request_id": "grant-wrong-node", "entry_grant": wrong_grant.to_dict()},
        ))

        asyncio.run(gateway.dmp_client(websocket))

        self.assertEqual(websocket.sent[2], {
            "type": "REGISTER_ENTRY_GRANT_RESULT", "request_id": "grant-valid",
            "route_id": valid_grant.route_id, "expires_at": valid_grant.expires_at,
        })
        self.assertEqual(websocket.sent[3], {
            "type": "ERROR", "request_id": "grant-wrong-node", "code": "INVALID_ENTRY_GRANT",
        })

    def test_entry_grant_coerces_ascii_byte_fields_and_raw_runtime_node_id(self):
        """ASGI adapters may retain JSON text as bytes; canonical signing remains unchanged."""
        class Transport:
            def detach_local_delivery_session(self, session):
                pass

        self._install_routing_state(Transport())
        gateway.runtime_state = lambda: type("State", (), {
            "node_crypto": type("NodeCrypto", (), {
                "node_id": self.node_key.verify_key.encode(),
                "secret_salt": b"g" * 32,
            })(),
            "capabilities": type("Capabilities", (), {
                "advertised_operations": lambda self: frozenset({"STATUS", "START_PROBE", "ROUTE_STATUS"}),
            })(),
            "node": type("Node", (), {"active_connections": [], "transport": Transport()})(),
        })()
        client_key = SigningKey.generate()
        route_key = SigningKey.generate()
        grant = gateway.EntryGrantV1.issue(
            self.node_key, route_key.verify_key.encode(encoder=HexEncoder).decode("ascii"), int(time.time()) + 60,
        )
        # Byte keys/values are an adapter/parser concern, not a JSON wire
        # representation. Exercise that coercion directly because json.dumps
        # cannot encode byte keys (or byte values).
        byte_field_grant = {
            key.encode("ascii") if isinstance(key, str) else key:
            value.encode("ascii") if isinstance(value, str) else value
            for key, value in grant.to_dict().items()
        }
        self.assertEqual(gateway._verify_entry_grant(
            byte_field_grant, self.node_key.verify_key.encode().hex(),
        ).to_dict(), grant.to_dict())
        # The actual WebSocket request must remain a JSON-compatible wire
        # object; dmp_client canonicalizes the raw byte runtime node ID above.
        websocket_request = {
            "type": "REGISTER_ENTRY_GRANT", "request_id": "byte-wire-grant",
            "entry_grant": grant.to_dict(),
            "pow": self._activation_pow(client_key, "ENTRY_GRANT", grant.route_id),
        }
        self.assertEqual(json.loads(json.dumps(websocket_request)), websocket_request)
        websocket = self.GatewaySocket(self._authenticated_frames(
            client_key,
            websocket_request,
        ))

        asyncio.run(gateway.dmp_client(websocket))

        self.assertEqual(websocket.sent[2], {
            "type": "REGISTER_ENTRY_GRANT_RESULT", "request_id": "byte-wire-grant",
            "route_id": grant.route_id, "expires_at": grant.expires_at,
        })

    def test_registration_persists_only_when_dnss_and_verified_grant_are_both_present(self):
        class Transport:
            def detach_local_delivery_session(self, session):
                pass

        self._install_routing_state(Transport())
        client_key = SigningKey.generate()
        route_key = SigningKey.generate()
        route_public_key = route_key.verify_key.encode(encoder=HexEncoder).decode("ascii")
        grant = gateway.EntryGrantV1.issue(self.node_key, route_public_key, int(time.time()) + 60)
        dnss = "ab" * 16
        websocket = self.GatewaySocket(self._authenticated_frames(
            client_key,
            {"type": "REGISTER_DNSS", "request_id": "dnss", "dnss": dnss,
             "pow": self._activation_pow(client_key, "DNSS", bytes.fromhex(dnss))},
            {"type": "REGISTER_ENTRY_GRANT", "request_id": "grant", "entry_grant": grant.to_dict(),
             "pow": self._activation_pow(client_key, "ENTRY_GRANT", grant.route_id)},
        ))

        asyncio.run(gateway.dmp_client(websocket))

        self.assertEqual(websocket.sent[2]["type"], "REGISTER_DNSS_RESULT")
        self.assertEqual(websocket.sent[3]["type"], "REGISTER_ENTRY_GRANT_RESULT")
        registry = RegistrationRegistry(self.registry_path, type("Node", (), {
            "node_id": self.node_key.verify_key.encode().hex(), "secret_salt": b"g" * 32,
        })())
        try:
            record = registry.lookup(bytes.fromhex(dnss))
            self.assertIsNotNone(record)
            self.assertEqual(record.grant.to_dict(), grant.to_dict())
            with open(self.registry_path, "rb") as database:
                self.assertNotIn(bytes.fromhex(dnss), database.read())
        finally:
            registry.close()

    def test_new_registration_requires_node_bound_single_use_canonical_pow(self):
        class Transport:
            def detach_local_delivery_session(self, session):
                pass

        self._install_routing_state(Transport())
        client_key = SigningKey.generate()
        dnss = "cd" * 16
        wrong_node_proof = self._activation_pow(
            client_key, "DNSS", bytes.fromhex(dnss),
            node_id=SigningKey.generate().verify_key.encode().hex(),
        )
        valid_proof = self._activation_pow(client_key, "DNSS", bytes.fromhex(dnss))
        websocket = self.GatewaySocket(self._authenticated_frames(
            client_key,
            {"type": "REGISTER_DNSS", "request_id": "wrong-node", "dnss": dnss, "pow": wrong_node_proof},
            {"type": "REGISTER_DNSS", "request_id": "valid-once", "dnss": dnss, "pow": valid_proof},
            {"type": "REGISTER_DNSS", "request_id": "replayed", "dnss": dnss, "pow": valid_proof},
        ))

        asyncio.run(gateway.dmp_client(websocket))

        self.assertEqual(websocket.sent[2], {
            "type": "ERROR", "request_id": "wrong-node", "code": "INVALID_RESOURCE_POW",
        })
        self.assertEqual(websocket.sent[3]["type"], "REGISTER_DNSS_RESULT")
        self.assertEqual(websocket.sent[4], {
            "type": "ERROR", "request_id": "replayed", "code": "INVALID_RESOURCE_POW",
        })

    def test_new_dnss_registration_rejects_an_expired_activation_proof(self):
        class Transport:
            def detach_local_delivery_session(self, session):
                pass

        self._install_routing_state(Transport())
        client_key = SigningKey.generate()
        dnss = "de" * 16
        expired_proof = self._activation_pow(
            client_key, "DNSS", bytes.fromhex(dnss), expires_at=int(time.time()) - 1,
        )
        websocket = self.GatewaySocket(self._authenticated_frames(
            client_key,
            {"type": "REGISTER_DNSS", "request_id": "expired", "dnss": dnss, "pow": expired_proof},
        ))

        asyncio.run(gateway.dmp_client(websocket))

        self.assertEqual(websocket.sent[2], {
            "type": "ERROR", "request_id": "expired", "code": "INVALID_RESOURCE_POW",
        })

    def test_new_entry_grant_activation_rejects_a_replayed_proof(self):
        class Transport:
            def detach_local_delivery_session(self, session):
                pass

        self._install_routing_state(Transport())
        client_key = SigningKey.generate()
        route_key = SigningKey.generate()
        grant = gateway.EntryGrantV1.issue(
            self.node_key, route_key.verify_key.encode(encoder=HexEncoder).decode("ascii"), int(time.time()) + 60,
        )
        proof = self._activation_pow(client_key, "ENTRY_GRANT", grant.route_id)
        request = {"type": "REGISTER_ENTRY_GRANT", "entry_grant": grant.to_dict(), "pow": proof}
        websocket = self.GatewaySocket(self._authenticated_frames(
            client_key,
            {**request, "request_id": "grant-once"},
            {**request, "request_id": "grant-replayed"},
        ))

        asyncio.run(gateway.dmp_client(websocket))

        self.assertEqual(websocket.sent[2]["type"], "REGISTER_ENTRY_GRANT_RESULT")
        self.assertEqual(websocket.sent[3], {
            "type": "ERROR", "request_id": "grant-replayed", "code": "INVALID_RESOURCE_POW",
        })

    def test_new_entry_grant_activation_rejects_an_expired_proof(self):
        class Transport:
            def detach_local_delivery_session(self, session):
                pass

        self._install_routing_state(Transport())
        client_key = SigningKey.generate()
        route_key = SigningKey.generate()
        grant = gateway.EntryGrantV1.issue(
            self.node_key, route_key.verify_key.encode(encoder=HexEncoder).decode("ascii"), int(time.time()) + 60,
        )
        expired_proof = self._activation_pow(
            client_key, "ENTRY_GRANT", grant.route_id, expires_at=int(time.time()) - 1,
        )
        websocket = self.GatewaySocket(self._authenticated_frames(
            client_key,
            {"type": "REGISTER_ENTRY_GRANT", "request_id": "grant-expired",
             "entry_grant": grant.to_dict(), "pow": expired_proof},
        ))

        asyncio.run(gateway.dmp_client(websocket))

        self.assertEqual(websocket.sent[2], {
            "type": "ERROR", "request_id": "grant-expired", "code": "INVALID_RESOURCE_POW",
        })

    def test_activation_pow_cache_rejects_new_proof_without_evicting_live_proof(self):
        """Saturation must not turn an earlier live proof into a replay."""
        client_key = SigningKey.generate()
        node_id = self.node_key.verify_key.encode().hex()
        device_key = client_key.verify_key.encode().hex()
        first_resource = bytes.fromhex("01" * 16)
        second_resource = bytes.fromhex("02" * 16)
        first_proof = self._activation_pow(client_key, "DNSS", first_resource)
        second_proof = self._activation_pow(client_key, "DNSS", second_resource)

        with (patch.object(gateway, "ACTIVATION_POW_REPLAY_CAPACITY", 1),
              patch.dict(gateway._USED_ACTIVATION_POW, {}, clear=True)):
            self.assertTrue(gateway._activation_pow_ok(
                {"pow": first_proof}, node_id, device_key, "DNSS", first_resource,
            ))
            self.assertFalse(gateway._activation_pow_ok(
                {"pow": second_proof}, node_id, device_key, "DNSS", second_resource,
            ))
            # If saturation evicted the first live record, this would wrongly
            # succeed and demonstrate the replay vulnerability.
            self.assertFalse(gateway._activation_pow_ok(
                {"pow": first_proof}, node_id, device_key, "DNSS", first_resource,
            ))

    def test_new_registration_rejects_proof_below_gateway_minimum_difficulty(self):
        class Transport:
            def detach_local_delivery_session(self, session):
                pass

        self._install_routing_state(Transport())
        client_key = SigningKey.generate()
        dnss = "ce" * 16
        proof = self._activation_pow(client_key, "DNSS", bytes.fromhex(dnss))
        proof["difficulty"] = gateway.ACTIVATION_POW_DIFFICULTY - 1
        websocket = self.GatewaySocket(self._authenticated_frames(
            client_key,
            {"type": "REGISTER_DNSS", "request_id": "low-difficulty", "dnss": dnss, "pow": proof},
        ))

        asyncio.run(gateway.dmp_client(websocket))

        self.assertEqual(websocket.sent[2], {
            "type": "ERROR", "request_id": "low-difficulty", "code": "INVALID_RESOURCE_POW",
        })

    def test_existing_valid_registration_bypasses_activation_pow(self):
        class Transport:
            def detach_local_delivery_session(self, session):
                pass

        self._install_routing_state(Transport())
        dnss = bytes.fromhex("ef" * 16)
        route_key = SigningKey.generate()
        grant = gateway.EntryGrantV1.issue(
            self.node_key, route_key.verify_key.encode(encoder=HexEncoder).decode("ascii"), int(time.time()) + 60,
        )
        with RegistrationRegistry(self.registry_path, gateway.runtime_state().node_crypto) as registry:
            registry.register(dnss, grant.to_dict())

        client_key = SigningKey.generate()
        websocket = self.GatewaySocket(self._authenticated_frames(
            client_key,
            {"type": "REGISTER_DNSS", "request_id": "existing", "dnss": dnss.hex()},
        ))
        asyncio.run(gateway.dmp_client(websocket))

        self.assertEqual(websocket.sent[2]["type"], "REGISTER_DNSS_RESULT")

    def test_data_ack_and_pull_do_not_require_registration_pow(self):
        class Transport:
            async def register_inbound_locator(self, locator):
                return "locator-handle"

            def attach_local_delivery_session(self, handle, session):
                self.attached = (handle, session)

            async def pull(self, handle):
                return [{"opaque": "packet"}]

            async def ack(self, delivery_id, *, allowed_locator_handles):
                return delivery_id == "delivery-1" and allowed_locator_handles == {"locator-handle"}

            def detach_local_delivery_session(self, session):
                pass

        self._install_routing_state(Transport(), frozenset({
            "STATUS", "START_PROBE", "ROUTE_STATUS", "REGISTER_INBOUND_LOCATOR", "PULL", "ACK",
        }))
        client_key = SigningKey.generate()
        websocket = self.GatewaySocket(self._authenticated_frames(
            client_key,
            {"type": "REGISTER_INBOUND_LOCATOR", "request_id": "locator", "locator": "inbound"},
            {"type": "PULL", "request_id": "pull", "locator_handle": "locator-handle", "pow": {"invalid": True}},
            {"type": "ACK", "request_id": "ack", "delivery_id": "delivery-1", "pow": {"invalid": True}},
            {"type": "DATA", "request_id": "data", "pow": {"invalid": True}},
        ))
        asyncio.run(gateway.dmp_client(websocket))

        self.assertEqual(websocket.sent[3], {
            "type": "PULL_RESULT", "request_id": "pull", "packets": [{"opaque": "packet"}],
        })
        self.assertEqual(websocket.sent[4], {
            "type": "ACK_RESULT", "request_id": "ack", "acknowledged": True,
        })
        self.assertEqual(websocket.sent[5], {
            "type": "ERROR", "request_id": "data", "code": "UNSUPPORTED_OPERATION",
        })
        self.assertNotIn("INVALID_RESOURCE_POW", json.dumps(websocket.sent))

    def test_authenticated_start_probe_propagates_metric_and_clamps_hop_limit(self):
        @dataclass
        class Submission:
            delivery_id: str
            state: str
            packet: dict

        class Transport:
            def __init__(self):
                self.calls = []

            async def start_probe(self, route_locator, back_route_locator, *, hops, ttl):
                self.calls.append((route_locator, back_route_locator, hops, ttl))
                return Submission("probe-id", "SUBMITTED_TO_ENTRY", {
                    "type": "ROUTE_PROBE_V2", "metric": hops, "hop_limit": ttl,
                })

            def detach_local_delivery_session(self, session):
                pass

        transport = Transport()
        self._install_routing_state(transport)
        client_key = SigningKey.generate()
        websocket = self.GatewaySocket(self._authenticated_frames(
            client_key,
            {"type": "START_PROBE", "request_id": "probe-high", "route_locator": "out", "back_route_locator": "back", "metric": 7, "hop_limit": 99},
            {"type": "START_PROBE", "request_id": "probe-low", "route_locator": "out-2", "back_route_locator": "back-2", "metric": 8, "hop_limit": -3},
        ))

        asyncio.run(gateway.dmp_client(websocket))

        self.assertEqual(transport.calls, [("out", "back", 7, 15), ("out-2", "back-2", 8, 1)])
        self.assertEqual(websocket.sent[2], {
            "type": "START_PROBE_RESULT", "request_id": "probe-high",
            "delivery_id": "probe-id", "state": "SUBMITTED_TO_ENTRY",
            "packet": {"type": "ROUTE_PROBE_V2", "metric": 7, "hop_limit": 15},
        })
        self.assertEqual(websocket.sent[3]["request_id"], "probe-low")
        self.assertEqual(websocket.sent[3]["packet"]["hop_limit"], 1)

    def test_authenticated_probe_and_route_status_reject_invalid_v2_values(self):
        class Transport:
            async def start_probe(self, *args, **kwargs):
                # The gateway coerces/clamps hop_limit while the transport owns
                # metric validation; both invalid V2 fields surface uniformly.
                raise ValueError("invalid probe metric or hop limit")

            async def route_status(self, *args):
                raise AssertionError("invalid route frame reached transport")

            def detach_local_delivery_session(self, session):
                pass

        self._install_routing_state(Transport())
        client_key = SigningKey.generate()
        websocket = self.GatewaySocket(self._authenticated_frames(
            client_key,
            {"type": "ROUTE_STATUS", "request_id": "bad-route", "route_locator": ""},
            {"type": "START_PROBE", "request_id": "bad-back-route", "route_locator": "route", "back_route_locator": None},
            {"type": "START_PROBE", "request_id": "bad-limit", "route_locator": "route", "back_route_locator": "back", "metric": 3, "hop_limit": "not-an-int"},
            {"type": "START_PROBE", "request_id": "bad-metric", "route_locator": "route", "back_route_locator": "back", "metric": "not-an-int", "hop_limit": 4},
        ))

        asyncio.run(gateway.dmp_client(websocket))

        self.assertEqual(websocket.sent[2:], [
            {"type": "ERROR", "request_id": "bad-route", "code": "INVALID_ROUTE_HANDLE"},
            {"type": "ERROR", "request_id": "bad-back-route", "code": "INVALID_ROUTE_HANDLE"},
            {"type": "ERROR", "request_id": "bad-limit", "code": "NODE_OPERATION_FAILED"},
            {"type": "ERROR", "request_id": "bad-metric", "code": "NODE_OPERATION_FAILED"},
        ])

    def test_v2_rejects_legacy_or_replayed_challenge_signature(self):
        client_key = SigningKey.generate()
        def replayed_auth(sent):
            challenge = sent[0]
            # Signing a captured transcript with a changed fresh client nonce
            # must be rejected by the session rather than falling back.
            captured_nonce = "client-nonce-captured-1"
            transcript = device_auth_transcript(challenge["node_id"], challenge["session_id"], challenge["nonce"], captured_nonce, challenge["expires_at"])
            return __import__("json").dumps({
                "type": "AUTH", "auth_mode": "DEVICE_AUTH_V1",
                "public_key": client_key.verify_key.encode().hex(), "client_nonce": "client-nonce-fresh-222",
                "signature": base64.b64encode(client_key.sign(transcript).signature).decode("ascii"),
            })
        websocket = self.GatewaySocket([replayed_auth])
        asyncio.run(gateway.dmp_client(websocket))
        self.assertEqual(websocket.closed, (1008, "authentication failed"))

    def test_legacy_compatibility_is_explicit_not_a_v2_fallback(self):
        paths = {route.path for route in router.routes}
        self.assertIn("/dmp-c/v1", paths)
        self.assertIn("/dmp-c/legacy-v1", paths)

    def test_legacy_transcript_helper_remains_verifiable_but_is_not_device_auth(self):
        signing_key = SigningKey.generate()
        public_key = signing_key.verify_key.encode().hex()
        signature = base64.b64encode(signing_key.sign(auth_transcript("session-test", "nonce-test")).signature).decode("ascii")
        self.assertTrue(verify_auth(public_key, signature, "session-test", "nonce-test"))

    def test_device_auth_binds_challenge_node_and_client_nonce(self):
        signing_key = SigningKey.generate()
        public_key = signing_key.verify_key.encode().hex()
        fields = dict(node_id="ab" * 32, session_id="session-test", server_nonce="server-nonce", client_nonce="client-nonce-012345", expires_at=1_900_000_000)
        signature = base64.b64encode(signing_key.sign(device_auth_transcript(**fields)).signature).decode("ascii")
        self.assertTrue(verify_device_auth(public_key, signature, **fields))
        # Capture/replay cannot authenticate a fresh challenge/session.
        self.assertFalse(verify_device_auth(public_key, signature, **{**fields, "server_nonce": "fresh-nonce"}))
        self.assertFalse(verify_device_auth(public_key, signature, **{**fields, "session_id": "fresh-session"}))
        self.assertFalse(verify_device_auth(public_key, signature, **{**fields, "node_id": "cd" * 32}))
        self.assertFalse(verify_device_auth(public_key, signature, **{**fields, "expires_at": fields["expires_at"] + 1}))
        self.assertFalse(verify_device_auth("cd" * 32, signature, **fields))


if __name__ == "__main__":
    unittest.main()
