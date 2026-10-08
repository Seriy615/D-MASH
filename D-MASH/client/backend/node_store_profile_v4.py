"""Inactive Node-signed profile codec. No issuance, route authority or replay ledger."""
import base64
import json
from nacl.signing import VerifyKey
if __package__:
    from .secure_session import canonical
    from .route_discovery_v4 import _ed_encoding, _signature_encoding, _hex
else:
    from secure_session import canonical
    from route_discovery_v4 import _ed_encoding, _signature_encoding, _hex
PROFILE='STORE_FORWARD_V1'
DOMAIN=b'D-MASH|NODE-STORE|V4|STORE_FORWARD_V1|'
SCHEMAS={
 'GRANT':'version issuer recipient grant_id generation direction issued_at expires_at policy max_records max_bytes',
 'BIND':'version issuer recipient grant_hash direction transcript_hash challenge expires_at',
 'ROUTE_GRANT':'version issuer holder binding_id binding_generation route_authority_commitment store_grant_hash expires_at',
 'ROUTE_REBIND':'version issuer holder route_grant_hash store_grant_hash transcript_hash challenge expires_at',
 'MIGRATION':'version issuer recipient migration_id source_grant_hash target_grant_hash transcript_hash challenge expires_at',
}
INTS={'version','generation','binding_generation','issued_at','expires_at','max_records','max_bytes'}


def negotiate(policy):
    if type(policy) is not dict or set(policy)!={'profiles','required_profiles'}:
        raise ValueError('PROFILE_UPGRADE_REQUIRED')
    for key in policy:
        values=policy[key]
        if type(values) is not list or not 1<=len(values)<=8 or any(type(v) is not str or not v.isascii() or not 1<=len(v)<=64 for v in values) or sorted(set(values))!=values:
            raise ValueError('Invalid profile list')
    if PROFILE not in policy['profiles'] or PROFILE not in policy['required_profiles'] or any(v!=PROFILE for v in policy['required_profiles']):
        raise ValueError('PROFILE_UPGRADE_REQUIRED')
    return PROFILE


def body_bytes(kind, body):
    if kind not in SCHEMAS or type(body) is not dict or set(body)!=set(SCHEMAS[kind].split()):
        raise ValueError('Invalid profile schema')
    for key,value in body.items():
        if key in INTS:
            if type(value) is not int or not 0<=value<=2**53-1:
                raise ValueError('Invalid integer')
        elif key=='policy':
            if value!='store-forward-v4':raise ValueError('Invalid policy')
        else:_hex(value)
    if body['version']!=1:raise ValueError('PROFILE_UPGRADE_REQUIRED')
    peer=body.get('recipient',body.get('holder'))
    if body['issuer']==peer:raise ValueError('Self grant')
    _ed_encoding(body['issuer']);_ed_encoding(peer)
    if kind=='GRANT' and (not 1<=body['max_records']<=128 or not 1<=body['max_bytes']<=524288 or body['issued_at']>=body['expires_at']):
        raise ValueError('Invalid grant bounds')
    return DOMAIN+kind.encode()+b'\0'+canonical(body)


def sign(kind, body, signing_key):
    expected=body['issuer'] if kind in ('GRANT','ROUTE_GRANT') else body.get('recipient',body.get('holder'))
    if signing_key.verify_key.encode().hex()!=expected:raise ValueError('Signer mismatch')
    raw=body_bytes(kind,body)
    return {'kind':kind,'body':dict(body),'signature':base64.b64encode(signing_key.sign(raw).signature).decode()}


def verify(envelope, *, now, expected):
    if type(envelope) is not dict or set(envelope)!={'kind','body','signature'} or len(canonical(envelope))>4096:
        raise ValueError('Invalid envelope')
    kind,body=envelope['kind'],envelope['body']
    raw=body_bytes(kind,body)
    if type(now) is not int or not 0<=now<=2**53-1 or body['expires_at']<=now:raise ValueError('Expired')
    if body.get('issued_at',now)>now:raise ValueError('Future grant')
    if type(expected) is not dict or not expected or any(key not in body or body[key]!=value or type(body[key]) is not type(value) for key,value in expected.items()):
        raise ValueError('Context mismatch')
    if not {'issuer', 'recipient' if 'recipient' in body else 'holder'} <= set(expected):
        raise ValueError('Expected authenticated peer identities required')
    if kind in ('BIND','ROUTE_REBIND','MIGRATION'):
        if not (set(body)-{'version','expires_at'})<=set(expected) or body['expires_at']>now+90:
            raise ValueError('Fresh binding context required')
    signature=base64.b64decode(envelope['signature'],validate=True)
    if len(signature)!=64 or base64.b64encode(signature).decode()!=envelope['signature']:raise ValueError('Invalid signature encoding')
    _signature_encoding(signature.hex())
    signer=body['issuer'] if kind in ('GRANT','ROUTE_GRANT') else body.get('recipient',body.get('holder'))
    VerifyKey(bytes.fromhex(signer)).verify(raw,signature)
    return json.loads(canonical(body))


def parse(serialized, **kwargs):
    if type(serialized) is not str or len(serialized)>4096:raise ValueError('Invalid envelope size')
    value=json.loads(serialized)
    if canonical(value).decode()!=serialized:raise ValueError('Noncanonical envelope')
    return verify(value,**kwargs)
