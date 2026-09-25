"""Opaque route discovery proofs with independent delegated discovery keys.

Callers pin certificates via authenticated route descriptors; this module neither
provisions delegation nor grants mailbox/Account authority.
"""
import base64
import hashlib
import json
import re
import secrets
import struct
import time

from nacl.public import Box, PrivateKey, PublicKey
from nacl.signing import VerifyKey

CERT_FIELDS = {'version','route_id','discovery_sign','discovery_box','recipient_box','generation','issued_at','expires_at','signature'}
MAX_LIFETIME = 30 * 86400
MAX_BLOB = 16384


def _hex(value, size=32):
    if not isinstance(value,str) or not re.fullmatch('[0-9a-f]{%d}' % (size*2), value):
        raise ValueError('Invalid discovery encoding')
    return bytes.fromhex(value)


def _integer(value):
    if type(value) is not int or not 0 <= value <= 2**53-1:
        raise ValueError('Invalid discovery integer')
    return struct.pack('>Q',value)


def certificate_transcript(cert):
    if not isinstance(cert,dict) or set(cert)!=CERT_FIELDS or type(cert['version']) is not int or cert['version']!=4:
        raise ValueError('Invalid discovery certificate')
    keys=b''.join(_hex(cert[name]) for name in ('route_id','discovery_sign','discovery_box','recipient_box'))
    dates=b''.join(_integer(cert[name]) for name in ('generation','issued_at','expires_at'))
    if cert['generation']<1 or not 0<cert['expires_at']-cert['issued_at']<=MAX_LIFETIME:
        raise ValueError('Invalid discovery validity')
    return b'D-MASH|DISCOVERY-CERT|V4\0'+keys+dates


def verify_certificate(cert,now=None):
    now=int(time.time()) if now is None else now
    transcript=certificate_transcript(cert)
    if not cert['issued_at']<=now+60 or cert['expires_at']<=now:
        raise ValueError('Discovery certificate expired')
    VerifyKey(_hex(cert['route_id'])).verify(transcript,_hex(cert['signature'],64))
    return transcript


def issue_certificate(route_sign,discovery_sign,discovery_box,recipient_box,*,generation,issued_at,expires_at):
    cert=dict(version=4,route_id=route_sign.verify_key.encode().hex(),discovery_sign=bytes(discovery_sign).hex(),
              discovery_box=bytes(discovery_box).hex(),recipient_box=bytes(recipient_box).hex(),
              generation=generation,issued_at=issued_at,expires_at=expires_at,signature='')
    cert['signature']=route_sign.sign(certificate_transcript(cert)).signature.hex()
    return cert


def seal(public_key,value):
    raw=json.dumps(value,separators=(',',':'),ensure_ascii=True).encode()
    if len(raw)>MAX_BLOB-72:raise ValueError('Discovery payload too large')
    ephemeral=PrivateKey.generate();nonce=secrets.token_bytes(24)
    cipher=Box(ephemeral,PublicKey(public_key)).encrypt(raw,nonce).ciphertext
    return base64.b64encode(bytes(ephemeral.public_key)+nonce+cipher).decode()


def open_box(private_key,value):
    if not isinstance(value,str) or len(value)>((MAX_BLOB+2)//3)*4:raise ValueError('Invalid discovery box')
    raw=base64.b64decode(value,validate=True)
    if not 72<=len(raw)<=MAX_BLOB or base64.b64encode(raw).decode()!=value:raise ValueError('Invalid discovery box')
    plain=Box(PrivateKey(bytes(private_key)),PublicKey(raw[:32])).decrypt(raw[56:],raw[32:56])
    return json.loads(plain)


def _query(query,cert,now):
    if not isinstance(query,dict) or set(query)!={'type','version','route_id','challenge','reply_key','expires_at'}:
        raise ValueError('Invalid discovery query')
    if query['type']!='ROUTE_QUERY' or type(query['version']) is not int or query['version']!=4 or query['route_id']!=cert['route_id']:
        raise ValueError('Invalid discovery context')
    _hex(query['challenge']);_hex(query['reply_key']);_integer(query['expires_at'])
    if not now<query['expires_at']<=min(now+180,cert['expires_at']):raise ValueError('Discovery query expired')
    return query


def _reply_transcript(query,cert):
    digest=hashlib.sha256(certificate_transcript(cert)+_hex(cert['signature'],64)).digest()
    return b'D-MASH|DISCOVERY-REPLY|V4\0'+_hex(query['challenge'])+_hex(query['reply_key'])+_integer(query['expires_at'])+digest


def create_query(cert,*,now=None):
    now=int(time.time()) if now is None else now
    verify_certificate(cert,now);reply=PrivateKey.generate()
    query=dict(type='ROUTE_QUERY',version=4,route_id=cert['route_id'],challenge=secrets.token_hex(32),
               reply_key=bytes(reply.public_key).hex(),expires_at=min(now+180,cert['expires_at']))
    return seal(_hex(cert['discovery_box']),query),dict(query=query,certificate=dict(cert),reply_private=reply)


def answer_query(blob,cert,discovery_sign,discovery_box,*,now=None,with_context=False):
    now=int(time.time()) if now is None else now
    verify_certificate(cert,now)
    if discovery_sign.verify_key.encode().hex()!=cert['discovery_sign'] or bytes(discovery_box.public_key).hex()!=cert['discovery_box']:
        raise ValueError('Discovery key mismatch')
    query=_query(open_box(discovery_box,blob),cert,now)
    response=dict(type='ROUTE_REPLY',version=4,challenge=query['challenge'],expires_at=query['expires_at'],
                  certificate=cert,signature=discovery_sign.sign(_reply_transcript(query,cert)).signature.hex())
    reply=seal(_hex(query['reply_key']),response)
    return (reply,query['expires_at']) if with_context else reply


def verify_reply(blob,state,*,now=None):
    now=int(time.time()) if now is None else now
    cert=state['certificate'];verify_certificate(cert,now);query=_query(state['query'],cert,now)
    response=open_box(state['reply_private'],blob)
    if not isinstance(response,dict) or set(response)!={'type','version','challenge','expires_at','certificate','signature'}:
        raise ValueError('Invalid discovery reply')
    if (response['type']!='ROUTE_REPLY' or type(response['version']) is not int or response['version']!=4
            or response['certificate']!=cert or response['challenge']!=query['challenge']
            or type(response['expires_at']) is not int or response['expires_at']!=query['expires_at']):
        raise ValueError('Discovery reply context mismatch')
    verify_certificate(response['certificate'],now)
    VerifyKey(_hex(cert['discovery_sign'])).verify(_reply_transcript(query,cert),_hex(response['signature'],64))
    return True
