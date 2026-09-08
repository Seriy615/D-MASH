"""DMP-C v3 shared role-bound handshake and encrypted record primitives.

No permissions or network fallback are implicit in a cryptographic session.
Callers must authenticate the expected peer key and authorize its role/resources.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time

from nacl.bindings import crypto_scalarmult, crypto_scalarmult_base
from nacl.secret import SecretBox
from nacl.signing import VerifyKey

VERSION = 3
SUITE = "X25519-HKDF-SHA256-XSALSA20POLY1305"
ROLES = frozenset({"DEVICE", "NODE"})
MAX_RECORD_BYTES = 1024 * 1024
MAX_SEQUENCE = 2**32 - 1
DOMAIN = b"D-MASH|DMP-C|3|"


def canonical(value):
    def validate(item, depth=0):
        if depth > 32:
            raise ValueError("payload nesting limit")
        if item is None or isinstance(item, (str, bool)):
            return
        if type(item) is int and abs(item) <= 2**53 - 1:
            return
        if isinstance(item, list):
            for child in item: validate(child, depth + 1)
            return
        if isinstance(item, dict):
            for key, child in item.items():
                if not isinstance(key, str) or not key.isascii():
                    raise ValueError("ASCII object keys required")
                validate(child, depth + 1)
            return
        raise ValueError("unsupported canonical value")
    validate(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def b64(value):
    return base64.b64encode(value).decode("ascii")


def unb64(value, length=None):
    if not isinstance(value, str):
        raise ValueError("invalid encoding")
    raw = base64.b64decode(value, validate=True)
    if b64(raw) != value or (length is not None and len(raw) != length):
        raise ValueError("invalid encoding")
    return raw


def hkdf(ikm, salt, info, length=32):
    """RFC 5869 HKDF-SHA256 (extract and expand)."""
    if not 1 <= length <= 255 * 32:
        raise ValueError("invalid output length")
    prk = hmac.digest(salt, ikm, "sha256")
    result, previous = b"", b""
    for counter in range(1, (length + 31) // 32 + 1):
        previous = hmac.digest(prk, previous + info + bytes([counter]), "sha256")
        result += previous
    return result[:length]


def _public_hex(value):
    if not isinstance(value, str) or len(value) != 64 or bytes.fromhex(value).hex() != value:
        raise ValueError("invalid identity")
    return value


def validate_hello(hello, expected_role):
    if (not isinstance(hello, dict) or set(hello) != {
            "type", "protocol", "version", "suite", "role", "public_key", "ephemeral", "nonce"}
            or hello["type"] != "HELLO" or hello["protocol"] != "DMP-C"
            or hello["version"] != VERSION or hello["suite"] != SUITE
            or expected_role not in ROLES or hello["role"] != expected_role):
        raise ValueError("invalid hello or role")
    _public_hex(hello["public_key"])
    unb64(hello["ephemeral"], 32)
    unb64(hello["nonce"], 32)


def transcript(hello, challenge):
    return DOMAIN + b"HANDSHAKE\x00" + canonical([hello, challenge])


class Handshake:
    """One-shot ephemeral state. Long-lived signing keys belong to the caller."""
    def __init__(self, signing_key, role):
        if role not in ROLES:
            raise ValueError("invalid role")
        self.signing_key = signing_key
        self.role = role
        self.private = bytearray(secrets.token_bytes(32))
        self.hello = None
        self.challenge = None
        self.done = False

    def initiate(self):
        if self.done or self.hello is not None:
            raise ValueError("handshake already used")
        self.hello = {
            "type": "HELLO", "protocol": "DMP-C", "version": VERSION,
            "suite": SUITE, "role": self.role,
            "public_key": self.signing_key.verify_key.encode().hex(),
            "ephemeral": b64(crypto_scalarmult_base(bytes(self.private))),
            "nonce": b64(secrets.token_bytes(32)),
        }
        return dict(self.hello)

    def respond(self, hello, expected_role, *, now=None):
        if self.done or self.hello is not None or self.role != "NODE":
            raise ValueError("invalid responder state")
        validate_hello(hello, expected_role)
        self.hello = dict(hello)
        self.challenge = {
            "type": "CHALLENGE", "protocol": "DMP-C", "version": VERSION,
            "suite": SUITE, "role": "NODE", "peer_role": expected_role,
            "public_key": self.signing_key.verify_key.encode().hex(),
            "ephemeral": b64(crypto_scalarmult_base(bytes(self.private))),
            "nonce": b64(secrets.token_bytes(32)),
            "expires_at": (int(time.time()) if now is None else now) + 15,
        }
        digest = hashlib.sha256(transcript(self.hello, self.challenge)).digest()
        return {**self.challenge, "signature": b64(self.signing_key.sign(DOMAIN + b"RESPONDER\x00" + digest).signature)}

    def finish(self, response, expected_node_id, *, now=None):
        if self.done or self.hello is None or self.challenge is not None:
            raise ValueError("invalid initiator state")
        try:
            challenge = dict(response)
            signature = unb64(challenge.pop("signature"), 64)
            current = int(time.time()) if now is None else now
            if (set(challenge) != {"type", "protocol", "version", "suite", "role", "peer_role",
                                  "public_key", "ephemeral", "nonce", "expires_at"}
                    or challenge["type"] != "CHALLENGE" or challenge["protocol"] != "DMP-C"
                    or challenge["version"] != VERSION or challenge["suite"] != SUITE
                    or challenge["role"] != "NODE" or challenge["peer_role"] != self.role
                    or challenge["public_key"] != _public_hex(expected_node_id)
                    or type(challenge["expires_at"]) is not int
                    or not current < challenge["expires_at"] <= current + 15):
                raise ValueError("invalid challenge")
            unb64(challenge["nonce"], 32)
            unb64(challenge["ephemeral"], 32)
            digest = hashlib.sha256(transcript(self.hello, challenge)).digest()
            VerifyKey(bytes.fromhex(expected_node_id)).verify(DOMAIN + b"RESPONDER\x00" + digest, signature)
            auth = {"type": "AUTH", "version": VERSION,
                    "signature": b64(self.signing_key.sign(DOMAIN + b"INITIATOR\x00" + digest).signature)}
            session = self._session(challenge["ephemeral"], digest, True, "NODE")
            return auth, session
        finally:
            self.close()

    def accept(self, auth, *, now=None):
        if self.done or self.challenge is None:
            raise ValueError("invalid responder state")
        try:
            if (not isinstance(auth, dict) or set(auth) != {"type", "version", "signature"}
                    or auth["type"] != "AUTH" or auth["version"] != VERSION
                    or (int(time.time()) if now is None else now) >= self.challenge["expires_at"]):
                raise ValueError("invalid authentication")
            digest = hashlib.sha256(transcript(self.hello, self.challenge)).digest()
            VerifyKey(bytes.fromhex(self.hello["public_key"])).verify(
                DOMAIN + b"INITIATOR\x00" + digest, unb64(auth["signature"], 64))
            return self._session(self.hello["ephemeral"], digest, False, self.hello["role"])
        finally:
            self.close()

    def _session(self, ephemeral, digest, initiator, peer_role):
        shared = crypto_scalarmult(bytes(self.private), unb64(ephemeral, 32))
        # Suite-tagged, length-delimited combiner. Future hybrid suites must
        # authenticate their distinct suite and additional inputs; no implicit
        # empty ML-KEM value or downgrade is accepted by this suite.
        ikm = b"X25519\x00" + len(shared).to_bytes(4, "big") + shared
        keys = hkdf(ikm, digest, DOMAIN + SUITE.encode("ascii"), 64)
        send, receive = (keys[:32], keys[32:]) if initiator else (keys[32:], keys[:32])
        return SecureSession(send, receive, digest, self.role, peer_role)

    def close(self):
        self.private[:] = bytes(len(self.private))
        self.signing_key = None
        self.done = True


class SecureSession:
    def __init__(self, send_key, receive_key, transcript_hash, local_role, peer_role):
        self.send_key = bytearray(send_key)
        self.receive_key = bytearray(receive_key)
        self.transcript_hash = transcript_hash
        self.local_role, self.peer_role = local_role, peer_role
        self.send_sequence = self.receive_sequence = 0
        self.closed = False

    def seal(self, payload):
        if self.closed or self.send_sequence > MAX_SEQUENCE:
            raise ValueError("session closed or exhausted")
        if not isinstance(payload, dict):
            raise ValueError("object payload required")
        raw = canonical(payload)
        if len(raw) > MAX_RECORD_BYTES:
            raise ValueError("record too large")
        sequence = self.send_sequence
        nonce = bytes(16) + sequence.to_bytes(8, "big")
        ciphertext = SecretBox(bytes(self.send_key)).encrypt(raw, nonce).ciphertext
        self.send_sequence += 1
        return {"type": "SECURE", "version": VERSION, "sequence": sequence, "ciphertext": b64(ciphertext)}

    def open(self, frame):
        if self.closed:
            raise ValueError("session closed")
        try:
            if (not isinstance(frame, dict) or set(frame) != {"type", "version", "sequence", "ciphertext"}
                    or frame["type"] != "SECURE" or frame["version"] != VERSION
                    or type(frame["sequence"]) is not int
                    or frame["sequence"] != self.receive_sequence or self.receive_sequence > MAX_SEQUENCE
                    or not isinstance(frame["ciphertext"], str)
                    or len(frame["ciphertext"]) > ((MAX_RECORD_BYTES + 18) // 3) * 4):
                raise ValueError("invalid record")
            nonce = bytes(16) + self.receive_sequence.to_bytes(8, "big")
            raw = SecretBox(bytes(self.receive_key)).decrypt(unb64(frame["ciphertext"]), nonce)
            if len(raw) > MAX_RECORD_BYTES:
                raise ValueError("record too large")
            payload = json.loads(raw)
            if not isinstance(payload, dict) or canonical(payload) != raw:
                raise ValueError("invalid record payload")
            self.receive_sequence += 1
            return payload
        except Exception:
            self.close()
            raise

    def close(self):
        self.send_key[:] = bytes(len(self.send_key))
        self.receive_key[:] = bytes(len(self.receive_key))
        self.closed = True
