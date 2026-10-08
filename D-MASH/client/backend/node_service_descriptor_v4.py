"""Explicit service-v1 neighbor descriptor; signatures do not replace live channel checks."""
from urllib.parse import urlsplit
from nacl.signing import VerifyKey
if __package__:
    from .secure_session import canonical
    from .route_discovery_v4 import _ed_encoding, _signature_encoding, _hex
else:
    from secure_session import canonical
    from route_discovery_v4 import _ed_encoding, _signature_encoding, _hex
DOMAIN=b'D-MASH|NODE-SERVICE|V4|SERVICE_V1\0'
FIELDS=set('version issuer holder transcript_hash challenge issued_at expires_at signaling_wss can_s_turn can_relay_blob'.split())

def body_bytes(body):
    if type(body) is not dict or set(body)!=FIELDS or type(body['version']) is not int or body['version']!=1: raise ValueError('SERVICE_SCHEMA')
    for key in ('issuer','holder','transcript_hash','challenge'): _hex(body[key])
    for key in ('issuer','holder'): _ed_encoding(body[key])
    if body['issuer']==body['holder']: raise ValueError('SERVICE_OWNER')
    for key in ('issued_at','expires_at'):
        if type(body[key]) is not int or not 0<=body[key]<=2**53-1: raise ValueError('SERVICE_TIME')
    if not body['issued_at']<body['expires_at']<=body['issued_at']+30: raise ValueError('SERVICE_EXPIRY')
    for key in ('can_s_turn','can_relay_blob'):
        if type(body[key]) is not bool: raise ValueError('SERVICE_CAPABILITY')
    if body['can_relay_blob'] and not body['can_s_turn']: raise ValueError('SERVICE_CAPABILITY')
    endpoint=body['signaling_wss']
    if type(endpoint) is not str or len(endpoint)>2048: raise ValueError('SERVICE_URL')
    url=urlsplit(endpoint)
    if url.scheme!='wss' or not url.hostname or url.username or url.password or url.fragment or any(ord(c)<33 or ord(c)>126 for c in endpoint): raise ValueError('SERVICE_URL')
    return DOMAIN+canonical(body)

def sign(body,key):
    if key.verify_key.encode().hex()!=body['issuer']: raise ValueError('SERVICE_SIGNER')
    return {'body':dict(body),'signature':key.sign(body_bytes(body)).signature.hex()}

def verify(envelope,*,now,issuer,holder,transcript_hash,challenge,signaling_wss):
    if type(envelope) is not dict or set(envelope)!={'body','signature'}: raise ValueError('SERVICE_ENVELOPE')
    body=envelope['body'];message=body_bytes(body)
    expected=dict(issuer=issuer,holder=holder,transcript_hash=transcript_hash,challenge=challenge,signaling_wss=signaling_wss)
    if any(body[k]!=v for k,v in expected.items()): raise ValueError('SERVICE_CONTEXT')
    if not body['issued_at']<=now<body['expires_at']: raise ValueError('SERVICE_EXPIRED')
    signature=envelope['signature'];_signature_encoding(signature)
    VerifyKey(bytes.fromhex(issuer)).verify(message,bytes.fromhex(signature))
    return dict(body)
