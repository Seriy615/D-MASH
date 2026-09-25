"""Opt-in Node v4 admission proofs. Kpwd is password-equivalent, NOT a PAKE.

Only encrypted v4 NODE sessions may use this gate. Routing, registration and
mailbox grants must remain inaccessible until their directional gate completes.
The endpoint/runtime integration and credential provisioning are separate.
"""
import base64
import hmac
import secrets
import time
from nacl.pwhash import argon2id

from .node_registration_v4 import _hex
from .crypto import NodeCryptoManager

PROFILE = 'ARGON2ID_64M_T3_P1_V1'
DOMAIN = b'D-MASH|NODE-ADMISSION|V4\0'


def derive_password_key(password, salt):
    if not isinstance(password, str) or not password or len(password.encode()) > 1024:
        raise ValueError('invalid Node password length')
    if not isinstance(salt, bytes) or len(salt) != 16:
        raise ValueError('invalid Node password salt')
    return argon2id.kdf(32, password.encode(), salt, opslimit=3, memlimit=64 * 1024 * 1024)


def password_credential(password):
    salt = secrets.token_bytes(16)
    return {'profile':PROFILE, 'salt':base64.b64encode(salt).decode(),
            'epoch':secrets.token_hex(16), 'key':derive_password_key(password,salt)}


def _context(session):
    if (session.version != 4 or session.closed or session.local_role != 'NODE'
            or session.peer_role != 'NODE' or not isinstance(session.transcript_hash,bytes)
            or len(session.transcript_hash) != 32):
        raise PermissionError('v4 Node session required')
    _hex(session.local_id,64); _hex(session.peer_id,64)
    if session.local_id == session.peer_id:
        raise PermissionError('self peering refused')
    if not all(NodeCryptoManager.verify_node_pow(value) for value in (session.local_id,session.peer_id)):
        raise PermissionError('Node identity work required')


def proof_bytes(challenge, issuer, applicant, transcript_hash):
    if not isinstance(challenge,dict) or set(challenge) != {'type','version','profile','salt','epoch','nonce','expires_at'}:
        raise ValueError('invalid Node admission challenge')
    if challenge['type'] != 'NODE_PASSWORD_CHALLENGE' or type(challenge['version']) is not int or challenge['version'] != 4 or challenge['profile'] != PROFILE:
        raise ValueError('unsupported Node password profile')
    salt=base64.b64decode(challenge['salt'],validate=True)
    if len(salt)!=16 or base64.b64encode(salt).decode()!=challenge['salt']:
        raise ValueError('invalid Node password salt')
    _hex(challenge['epoch'],32); _hex(challenge['nonce'],64)
    _hex(issuer,64); _hex(applicant,64)
    if issuer==applicant or not isinstance(transcript_hash,bytes) or len(transcript_hash)!=32:
        raise ValueError('invalid admission context')
    if type(challenge['expires_at']) is not int or not 0 <= challenge['expires_at'] <= 2**53-1:
        raise ValueError('invalid admission expiry')
    return DOMAIN + '|'.join((issuer,applicant,transcript_hash.hex(),PROFILE,
                              challenge['salt'],challenge['epoch'],challenge['nonce'],str(challenge['expires_at']))).encode()


def password_proof(key, challenge, session, *, now=None):
    _context(session)
    current=int(time.time()) if now is None else now
    if type(current) is not int or not current < challenge.get('expires_at',0) <= current+90:
        raise PermissionError('Node password challenge expired')
    if not isinstance(key,bytes) or len(key)!=32:
        raise ValueError('invalid Node password key')
    message=proof_bytes(challenge,session.peer_id,session.local_id,session.transcript_hash)
    return {'type':'NODE_PASSWORD_PROOF','version':4,'proof':hmac.digest(key,message,'sha256').hex()}


class PasswordGate:
    def __init__(self, credential, *, clock=time.time):
        self.clock=clock
        self.credential=dict(credential)
        if credential.get('profile')!=PROFILE or not isinstance(credential.get('key'),bytes) or len(credential['key'])!=32:
            raise ValueError('invalid Node password credential')
        self.pending={}
        self.authorized=set()
        self.attempted=set()
        self.failures={}
        self.overload_until=0

    def challenge(self, session):
        _context(session)
        now=int(self.clock())
        self.failures={peer:row for peer,row in self.failures.items() if row['expires']>now}
        if now<self.overload_until:
            raise PermissionError('Node admission cooldown')
        failure=self.failures.get(session.peer_id)
        if failure and failure['until']>now:
            raise PermissionError('Node admission cooldown')
        if not failure and len(self.failures)>=4096:
            raise PermissionError('Node admission failure quota exceeded')
        if session in self.attempted:
            raise PermissionError('Node admission already attempted')
        if len(self.attempted)>=256:
            raise PermissionError('Node admission quota exceeded')
        value={'type':'NODE_PASSWORD_CHALLENGE','version':4,'profile':PROFILE,
               'salt':self.credential['salt'],'epoch':self.credential['epoch'],
               'nonce':secrets.token_hex(32),'expires_at':int(self.clock())+90}
        proof_bytes(value,session.local_id,session.peer_id,session.transcript_hash)
        self.attempted.add(session)
        self.pending[session]=value
        return dict(value)

    def verify(self, session, response):
        _context(session)
        # Consume before verification: no repeated guesses against one challenge.
        challenge=self.pending.pop(session,None)
        if challenge is None:return False
        def failed():
            now=int(self.clock())
            if session.peer_id not in self.failures and len(self.failures)>=4096:
                self.overload_until=now+60
                return False
            count=min(7,self.failures.get(session.peer_id,{}).get('count',0)+1)
            self.failures[session.peer_id]={'count':count,'until':now+min(60,2**(count-1)),'expires':now+600}
            return False
        if int(self.clock())>=challenge['expires_at']:return failed()
        if not isinstance(response,dict) or set(response)!={'type','version','proof'} or response['type']!='NODE_PASSWORD_PROOF' or type(response['version']) is not int or response['version']!=4:
            return failed()
        try:
            _hex(response['proof'],64)
            expected=hmac.digest(self.credential['key'],proof_bytes(challenge,session.local_id,session.peer_id,session.transcript_hash),'sha256').hex()
            if not hmac.compare_digest(expected,response['proof']):return failed()
            self.failures.pop(session.peer_id,None)
            self.authorized.add(session)
            return True
        except (ValueError,TypeError):return failed()

    def require(self,session):
        _context(session)
        if session not in self.authorized:raise PermissionError('Node password admission required')

    def forget(self,session):
        self.pending.pop(session,None);self.authorized.discard(session);self.attempted.discard(session)

    def revoke_all(self):
        self.pending.clear();self.authorized.clear();self.attempted.clear()
