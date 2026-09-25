"""Shared v4 directional registration transcript and proof validation.

No network endpoint is enabled by this module. Admission (including Node identity
work/password policy), durable relationship storage and grant issuance are separate
steps; passing this proof never grants mailbox or route ownership.
"""
import re
import time

if __package__:
    from .resource_pow import MIN_ACTIVATION_DIFFICULTY, MAX_ACTIVATION_DIFFICULTY, verify_activation_pow
else:
    from resource_pow import MIN_ACTIVATION_DIFFICULTY, MAX_ACTIVATION_DIFFICULTY, verify_activation_pow


def _hex(value, length):
    if not isinstance(value, str) or not re.fullmatch('[0-9a-f]{' + str(length) + '}', value):
        raise ValueError('invalid registration field')
    return value


def resource(issuer, recipient, dnss, transcript_hash):
    """Issuer pays for its outbound relationship at recipient, independently of reverse."""
    _hex(issuer, 64); _hex(recipient, 64); _hex(dnss, 32)
    if issuer == recipient:
        raise ValueError('self relationship forbidden')
    if not isinstance(transcript_hash, bytes) or len(transcript_hash) != 32:
        raise ValueError('invalid session transcript')
    return '|'.join(('D-MASH', 'NODE-DNSS', 'V4', issuer, recipient, dnss, transcript_hash.hex()))


def verify_registration(session, request, difficulty, *, now=None, expected_dnss=None):
    """Verify ONLY inbound work, using identities authenticated by the handshake.

    The caller must persist/compare the DNSS before sending acceptance, then bind
    the accepted direction to this exact session. Never reuse acceptance on reconnect.
    """
    current = int(time.time()) if now is None else now
    if (session.version != 4 or session.closed or session.local_role != 'NODE'
            or session.peer_role != 'NODE' or type(difficulty) is not int
            or not MIN_ACTIVATION_DIFFICULTY <= difficulty <= MAX_ACTIVATION_DIFFICULTY
            or type(current) is not int):
        return False
    try:
        if not isinstance(request, dict) or set(request) != {'type', 'dnss', 'pow'} or request['type'] != 'NODE_REGISTER':
            return False
        dnss = _hex(request['dnss'], 32)
        if expected_dnss is not None and dnss != _hex(expected_dnss, 32):
            return False
        work = resource(session.peer_id, session.local_id, dnss, session.transcript_hash)
        proof = request['pow']
        if not isinstance(proof, dict) or set(proof) != {'v', 'type', 'resource', 'nonce', 'expires_at', 'difficulty', 'digest'}:
            return False
        if (type(proof['v']) is not int or proof['v'] != 1 or proof['type'] != 'DNSS'
                or proof['resource'] != work or type(proof['difficulty']) is not int
                or proof['difficulty'] != difficulty or type(proof['expires_at']) is not int
                or not current < proof['expires_at'] <= current + 180
                or type(proof['nonce']) is not int or not 0 <= proof['nonce'] <= 2**53-1):
            return False
        _hex(proof['digest'], 64)
        return verify_activation_pow(session.local_id, 'DNSS', session.peer_id, work,
                                     proof['nonce'], proof['expires_at'], difficulty, proof['digest'], now=current)
    except (ValueError, TypeError, AttributeError):
        return False
