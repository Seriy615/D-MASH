"""Runtime Device/DNSS and route authority, separate from durable mailbox."""
from dataclasses import dataclass, field
import hashlib
import hmac
import secrets
import time

from nacl.signing import VerifyKey

if __package__:
    from .entry_grant import EntryGrantV1
    from .resource_pow import activation_pow_difficulty, verify_activation_pow
    from .secure_session import canonical, unb64
else:
    from entry_grant import EntryGrantV1
    from resource_pow import activation_pow_difficulty, verify_activation_pow
    from secure_session import canonical, unb64

MAX_REGISTRATIONS = 10000
MAX_PROOFS = 4096
MAX_LIFETIME = 86400
AUTH_DOMAIN = b"D-MASH|ROUTE-AUTH|V3\x00"


class RegistrationError(PermissionError):
    pass


@dataclass
class DeviceSession:
    public_key: str
    transcript_hash: str
    dnss: bytes | None = None
    blind_dnss: str | None = None
    proofs: set = field(default_factory=set)


@dataclass
class RouteRegistration:
    blind_dnss: str
    generation: int
    expires_at: int
    kind: str
    public_key: str


def private_locator(public_key):
    """Private locator commits to a direction-specific root-derived verify key.

    The signing seed is derived from the pairing root at the Device; the Node
    receives only the verifying capability, never a pairing/root secret.
    """
    key = unb64(public_key, 32)
    return hashlib.sha256(b"D-MASH|PRIVATE-LOCATOR|V3\x00" + key).hexdigest()


def authority_transcript(node_id, session, operation, request_id, auth):
    if session.dnss is None:
        raise RegistrationError("DNSS_NOT_AUTHENTICATED")
    return AUTH_DOMAIN + canonical({
        "node_id": node_id, "session": session.transcript_hash,
        "dnss": session.dnss.hex(), "operation": operation, "request_id": request_id,
        "kind": auth["kind"], "route_id": auth["route_id"],
        "public_key": auth["public_key"], "generation": auth["generation"],
        "expires_at": auth["expires_at"],
    })


class DeviceRegistration:
    def __init__(self, node_id, durable_alias_key, *, clock=time.time):
        self.node_id, self.clock = node_id, clock
        self._mailbox_key = hmac.digest(durable_alias_key, b"D-MASH|MAILBOX-ALIAS|V3", "sha256")
        self._runtime_key = secrets.token_bytes(32)
        self._dnss = {}
        self.routes = {}
        self.used_work = {}
        self.difficulty = activation_pow_difficulty()

    def _prune(self):
        now = int(self.clock())
        self._dnss = {k: v for k, v in self._dnss.items() if v[1] > now}
        self.routes = {k: v for k, v in self.routes.items() if v.expires_at > now}
        self.used_work = {k: expiry for k, expiry in self.used_work.items() if expiry > now}

    def route_alias(self, route_id):
        if not isinstance(route_id, str) or not 1 <= len(route_id) <= 256:
            raise RegistrationError("INVALID_ROUTE")
        return hmac.digest(self._runtime_key, route_id.encode(), "sha256").hex()

    def _work(self, session, proof, kind, resource):
        canonical_resource = resource.hex() if isinstance(resource, bytes) else resource
        try:
            if (not isinstance(proof, dict) or proof.get("v") != 1 or proof.get("type") != kind
                    or proof.get("resource") != canonical_resource
                    or type(proof.get("difficulty")) is not int
                    or not self.difficulty <= proof["difficulty"] <= 24
                    or not verify_activation_pow(self.node_id, kind, session.public_key, resource,
                        proof.get("nonce"), proof.get("expires_at"), proof["difficulty"],
                        proof.get("digest"), now=int(self.clock()))):
                raise RegistrationError("INVALID_RESOURCE_POW")
            digest = proof["digest"].lower()
            if digest in self.used_work or len(self.used_work) >= MAX_PROOFS:
                raise RegistrationError("REPLAYED_RESOURCE_POW")
            self.used_work[digest] = proof["expires_at"]
        except (KeyError, TypeError, ValueError, AttributeError) as error:
            raise RegistrationError("INVALID_RESOURCE_POW") from error

    def bind_dnss(self, session, dnss_hex, proof=None):
        self._prune()
        try:
            if not isinstance(dnss_hex, str) or len(dnss_hex) != 32:
                raise ValueError()
            dnss = bytes.fromhex(dnss_hex)
            if dnss.hex() != dnss_hex: raise ValueError()
        except ValueError as error:
            raise RegistrationError("INVALID_DNSS") from error
        if session.dnss is not None and session.dnss != dnss:
            raise RegistrationError("SESSION_DNSS_ALREADY_BOUND")
        alias = hmac.digest(self._runtime_key, dnss, "sha256").hex()
        registered = self._dnss.get(alias)
        if registered and registered[0] != session.public_key:
            raise RegistrationError("DNSS_OWNER_MISMATCH")
        if not registered:
            if proof is None: raise RegistrationError("DNSS_NOT_REGISTERED")
            if len(self._dnss) >= MAX_REGISTRATIONS: raise RegistrationError("REGISTRATION_QUOTA")
            self._work(session, proof, "DNSS", dnss)
        # Including the authenticated Device key in the durable alias prevents
        # a different key from draining old mail by claiming DNSS after restart.
        blind_dnss = hmac.digest(self._mailbox_key, dnss + bytes.fromhex(session.public_key), "sha256").hex()
        self._dnss[alias] = (session.public_key, int(self.clock()) + MAX_LIFETIME)
        session.dnss, session.blind_dnss = dnss, blind_dnss
        return blind_dnss

    def require_dnss(self, session):
        self._prune()
        if session.dnss is None: raise RegistrationError("DNSS_NOT_AUTHENTICATED")
        alias = hmac.digest(self._runtime_key, session.dnss, "sha256").hex()
        if self._dnss.get(alias, (None,))[0] != session.public_key:
            raise RegistrationError("DNSS_NOT_REGISTERED")
        return session.blind_dnss

    def authorize_route(self, session, operation, request_id, auth, *, grant=None, proof=None):
        self.require_dnss(session)
        if (not isinstance(request_id, str) or not 16 <= len(request_id) <= 128
                or request_id in session.proofs or len(session.proofs) >= MAX_PROOFS):
            raise RegistrationError("INVALID_OR_REPLAYED_PROOF")
        if operation not in {"REGISTER_ROUTE", "START_PROBE", "UNREGISTER_ROUTE"}:
            raise RegistrationError("INVALID_ROUTE_OPERATION")
        try:
            if not isinstance(auth, dict) or set(auth) != {"kind", "route_id", "public_key", "generation", "expires_at", "signature"}:
                raise ValueError()
            now = int(self.clock())
            if (type(auth["generation"]) is not int or auth["generation"] < 1
                    or type(auth["expires_at"]) is not int
                    or not now < auth["expires_at"] <= now + MAX_LIFETIME): raise ValueError()
            if auth["kind"] == "PUBLIC":
                # Public RouteID is canonical base64url while capability keys
                # in this new proof use standard base64, like v3 signatures.
                import base64
                key = unb64(auth["public_key"], 32)
                if base64.urlsafe_b64encode(key).decode().rstrip("=") != auth["route_id"]: raise ValueError()
            elif auth["kind"] == "PRIVATE":
                if private_locator(auth["public_key"]) != auth["route_id"]: raise ValueError()
                key = unb64(auth["public_key"], 32)
            else: raise ValueError()
            VerifyKey(key).verify(authority_transcript(self.node_id, session, operation, request_id, auth), unb64(auth["signature"], 64))
        except Exception as error:
            raise RegistrationError("INVALID_ROUTE_AUTHORITY") from error
        route_alias = self.route_alias(auth["route_id"])
        existing = self.routes.get(route_alias)
        if existing and existing.blind_dnss != session.blind_dnss:
            raise RegistrationError("ROUTE_OWNER_MISMATCH")
        if operation == "REGISTER_ROUTE":
            if auth["kind"] == "PUBLIC":
                try:
                    parsed = EntryGrantV1.from_dict(grant)
                    if (not parsed.verify(expected_node_id=self.node_id, now=now)
                            or parsed.route_id != auth["route_id"] or parsed.generation != auth["generation"]
                            or parsed.expires_at != auth["expires_at"]): raise ValueError()
                except Exception as error: raise RegistrationError("INVALID_ENTRY_GRANT") from error
            candidate = RouteRegistration(session.blind_dnss, auth["generation"], auth["expires_at"], auth["kind"], auth["public_key"])
            if existing != candidate:
                if existing and existing.generation > candidate.generation:
                    raise RegistrationError("STALE_GENERATION")
                if not existing and len(self.routes) >= MAX_REGISTRATIONS:
                    raise RegistrationError("ROUTE_QUOTA")
                self._work(session, proof, "ENTRY_GRANT" if auth["kind"] == "PUBLIC" else "PRIVATE_ROUTE", auth["route_id"])
            self.routes[route_alias] = candidate
        else:
            if (not existing or existing.generation != auth["generation"] or existing.expires_at != auth["expires_at"]
                    or existing.kind != auth["kind"] or existing.public_key != auth["public_key"]):
                raise RegistrationError("ROUTE_NOT_REGISTERED")
            if operation == "UNREGISTER_ROUTE": del self.routes[route_alias]
        session.proofs.add(request_id)
        return self.routes.get(route_alias, existing)
