"""RecipientEnvelopeV2 and indistinguishable-at-the-schema-level cover boxes."""
import base64
import re
import secrets
from nacl.exceptions import CryptoError
from nacl.public import PrivateKey
from .route_discovery_v4 import seal,open_box


def seal_payload(recipient_public,payload):
    if not isinstance(payload,str):raise ValueError('Opaque Account payload must be a string')
    return seal(bytes(recipient_public),dict(type='RECIPIENT_PAYLOAD',version=2,
        packet_id=secrets.token_hex(32),payload=payload))


def open_payload(private_keys,blob):
    # Missing keys may mean lock/migration, never evidence of invalid ciphertext.
    if private_keys is None or (isinstance(private_keys,(tuple,list)) and not private_keys):return {'status':'deferred'}
    if not isinstance(private_keys,(tuple,list)) or len(private_keys)>2:raise ValueError('Invalid recipient key set')
    keys=[]
    for key in private_keys:
        if not isinstance(key,(bytes,bytearray,PrivateKey)):raise ValueError('Invalid recipient key')
        raw=bytes(key)
        if len(raw)!=32:raise ValueError('Invalid recipient key')
        keys.append(raw)
    for key in keys:
        try:value=open_box(key,blob)
        except (ValueError,CryptoError):continue
        if (isinstance(value,dict) and set(value)=={'type','version','packet_id','payload'}
                and value['type']=='RECIPIENT_PAYLOAD' and type(value['version']) is int and value['version']==2
                and isinstance(value['packet_id'],str) and re.fullmatch('[0-9a-f]{64}',value['packet_id'])
                and isinstance(value['payload'],str)):
            return {'status':'accepted','packet_id':value['packet_id'],'payload':value['payload']}
    return {'status':'discard'}


def cover_box(size=1024):
    if type(size) is not int or not 256<=size<=16384:raise ValueError('Invalid cover size')
    # Random raw 32-byte strings could have a distinguishable X25519 encoding.
    ephemeral=PrivateKey.generate()
    raw=bytes(ephemeral.public_key)+secrets.token_bytes(24)+secrets.token_bytes(size-56)
    return base64.b64encode(raw).decode()
