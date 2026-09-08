import copy
import unittest
import pathlib
import subprocess
import json

from nacl.signing import SigningKey

from backend.secure_session import Handshake, hkdf, MAX_SEQUENCE


class SecureSessionTests(unittest.TestCase):
    def test_browser_python_interoperability(self):
        harness = pathlib.Path(__file__).resolve().parents[3] / "D-MASH PWA/not_messenger/tests/secure_session_peer.cjs"
        def browser(value):
            result = subprocess.run(["node", str(harness)], input=json.dumps(value),
                                    capture_output=True, text=True, check=True)
            return json.loads(result.stdout)
        for role in ("DEVICE", "NODE"):
            hello = browser({"role": role})
            key = SigningKey.generate()
            responder = Handshake(key, "NODE")
            challenge = responder.respond(hello, role, now=100)
            args = {"hello": hello, "challenge": challenge, "role": role, "nodeId": key.verify_key.encode().hex()}
            result = browser(args)
            server = responder.accept(result["auth"], now=100)
            self.assertEqual(server.open(result["frame"]), {"type": "PING", "text": "Привет 🌐", "number": 17})
            self.assertTrue(result["erased"])
            reply = {"type": "READY", "text": "Ответ 🌐"}
            result = browser({**args, "frame": server.seal(reply)})
            self.assertEqual(result["opened"], reply)

    def exchange(self, role="DEVICE"):
        a, b = SigningKey.generate(), SigningKey.generate()
        initiator, responder = Handshake(a, role), Handshake(b, "NODE")
        hello = initiator.initiate()
        challenge = responder.respond(hello, role, now=100)
        auth, client = initiator.finish(challenge, b.verify_key.encode().hex(), now=100)
        server = responder.accept(auth, now=100)
        return initiator, responder, client, server

    def test_rfc5869_vector(self):
        result = hkdf(bytes.fromhex("0b" * 22), bytes.fromhex("000102030405060708090a0b0c"),
                      bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"), 42)
        self.assertEqual(result.hex(), "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")

    def test_mutual_device_and_node_auth_encrypted_both_directions(self):
        for role in ("DEVICE", "NODE"):
            with self.subTest(role=role):
                a, b, client, server = self.exchange(role)
                self.assertEqual(server.peer_role, role)
                self.assertNotEqual(client.send_key, client.receive_key)
                self.assertEqual(client.send_key, server.receive_key)
                self.assertFalse(any(a.private))
                self.assertFalse(any(b.private))
                self.assertIsNone(a.signing_key)
                payload = {"type": "SUBMIT", "opaque": "secret test content"}
                frame = client.seal(payload)
                self.assertNotIn("secret test content", str(frame))
                self.assertEqual(server.open(frame), payload)
                self.assertEqual(client.open(server.seal({"type": "READY"})), {"type": "READY"})

    def test_role_tampering_rejected(self):
        a, b = SigningKey.generate(), SigningKey.generate()
        initiator, responder = Handshake(a, "NODE"), Handshake(b, "NODE")
        hello = initiator.initiate()
        with self.assertRaises(ValueError):
            responder.respond(hello, "DEVICE", now=100)
        challenge = responder.respond(hello, "NODE", now=100)
        challenge["peer_role"] = "DEVICE"
        with self.assertRaises(Exception):
            initiator.finish(challenge, b.verify_key.encode().hex(), now=100)
        self.assertFalse(any(initiator.private))

    def test_wrong_node_and_signature_and_expiry(self):
        for mutation in ("node", "signature", "expiry", "ephemeral"):
            a, b = SigningKey.generate(), SigningKey.generate()
            i, r = Handshake(a, "DEVICE"), Handshake(b, "NODE")
            challenge = r.respond(i.initiate(), "DEVICE", now=100)
            expected = b.verify_key.encode().hex()
            if mutation == "node": expected = a.verify_key.encode().hex()
            if mutation == "signature": challenge["signature"] = "A" * 88
            if mutation == "ephemeral": challenge["ephemeral"] = "A" * 44
            with self.subTest(mutation=mutation), self.assertRaises(Exception):
                i.finish(challenge, expected, now=116 if mutation == "expiry" else 100)

    def test_initiator_must_prove_possession(self):
        a, b = SigningKey.generate(), SigningKey.generate()
        i, r = Handshake(a, "NODE"), Handshake(b, "NODE")
        challenge = r.respond(i.initiate(), "NODE", now=100)
        auth, _ = i.finish(challenge, b.verify_key.encode().hex(), now=100)
        auth["signature"] = "A" * 88
        with self.assertRaises(Exception): r.accept(auth, now=100)
        self.assertFalse(any(r.private))

    def test_replayed_challenge_and_auth_new_connection(self):
        a, b = SigningKey.generate(), SigningKey.generate()
        i, r = Handshake(a, "DEVICE"), Handshake(b, "NODE")
        challenge = r.respond(i.initiate(), "DEVICE", now=100)
        auth, _ = i.finish(challenge, b.verify_key.encode().hex(), now=100)
        i2, r2 = Handshake(a, "DEVICE"), Handshake(b, "NODE")
        r2.respond(i2.initiate(), "DEVICE", now=100)
        with self.assertRaises(Exception): i2.finish(challenge, b.verify_key.encode().hex(), now=100)
        with self.assertRaises(Exception): r2.accept(auth, now=100)

    def test_record_tamper_replay_reflection_fail_closed(self):
        for mutation in ("ciphertext", "sequence", "extra", "reflection", "replay"):
            _, _, client, server = self.exchange()
            frame = client.seal({"type": "PULL"})
            if mutation == "ciphertext": frame["ciphertext"] = "AAAA"
            if mutation == "sequence": frame["sequence"] = True
            if mutation == "extra": frame["extra"] = 1
            if mutation == "replay": server.open(copy.deepcopy(frame))
            if mutation == "reflection": server = client
            with self.subTest(mutation=mutation), self.assertRaises(Exception): server.open(frame)
            self.assertTrue(server.closed)
            self.assertFalse(any(server.send_key))
            self.assertFalse(any(server.receive_key))

    def test_reconnect_has_fresh_keys_and_cannot_open_previous_session(self):
        _, _, client, _ = self.exchange()
        _, _, next_client, next_server = self.exchange()
        self.assertNotEqual(client.send_key, next_client.send_key)
        with self.assertRaises(Exception): next_server.open(client.seal({"type": "PING"}))

    def test_close_and_sequence_exhaustion(self):
        _, _, client, server = self.exchange()
        client.send_sequence = MAX_SEQUENCE + 1
        with self.assertRaises(ValueError): client.seal({})
        server.close()
        with self.assertRaises(ValueError): server.seal({})
        with self.assertRaises(ValueError): server.open({})


if __name__ == "__main__":
    unittest.main()
