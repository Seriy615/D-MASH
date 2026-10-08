"""Inactive encrypted v4 store. Trusted verifier injection is NOT wire auth.

Verifier contract: bind(evidence)->Grant; current(grant)->None or raise;
migration(old_grant,new_grant,evidence)->None or raise, verifying BOTH owners.
route(grant,evidence)->(commitment,generation,expiry); rebind(grant,binding)
checks exact current route authority. ALL send(snapshot,guard) must call guard
immediately before each fragment; this is a trusted adapter requirement.
Only these trusted callbacks mint/revalidate capabilities; public methods never
accept caller claims as authority. No runtime imports this module yet.
"""
import asyncio
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import hmac
import json
import math
import os
import secrets
import sqlite3
import stat
import time
from nacl.secret import SecretBox


@dataclass(frozen=True)
class Grant:
    recipient: str
    direction: str
    grant_id: str
    expires: float
    session: object
    generation: int = 0
    policy: str = "store-forward-v4"
    max_records: int = 128
    max_bytes: int = 524288


def _hex(value):
    if type(value) is not str or len(value) != 64 or any(c not in '0123456789abcdef' for c in value):
        raise ValueError('Invalid commitment')
    return value


class MailboxStore:
    MAX_CAPS = 256
    MAX_OWNERS = 4096
    MAX_MIGRATIONS = 4096

    def __init__(self, path, node_id, key, verifier, *, clock=time.time):
        self.node = _hex(node_id)
        if type(key) is not bytes or len(key) != 32:
            raise ValueError('Invalid storage key')
        self.verifier, self.clock = verifier, clock
        self.caps = {}
        self.box = SecretBox(hmac.digest(key, b'DMASH|V4|MAILBOX|ENCRYPT', 'sha256'))
        self.alias_key = hmac.digest(key, b'DMASH|V4|MAILBOX|LOOKUP', 'sha256')
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        info = os.fstat(fd)
        os.close(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise PermissionError('Mailbox path must be private and owned')
        self.db = sqlite3.connect(path, isolation_level=None, timeout=5)
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.executescript('''
        CREATE TABLE IF NOT EXISTS metadata (id INTEGER PRIMARY KEY, box BLOB NOT NULL);
        CREATE TABLE IF NOT EXISTS owners (alias TEXT PRIMARY KEY, box BLOB NOT NULL, retired INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS records (id INTEGER PRIMARY KEY AUTOINCREMENT, owner TEXT NOT NULL, dedupe TEXT NOT NULL, box BLOB NOT NULL, size INTEGER NOT NULL, expires REAL NOT NULL, lease TEXT, lease_until REAL, UNIQUE(owner,dedupe));
        CREATE TABLE IF NOT EXISTS migrations (alias TEXT PRIMARY KEY, box BLOB NOT NULL);
        ''')
        try:
            with self.transaction():
                row = self.db.execute('SELECT box FROM metadata WHERE id=1').fetchone()
                if row:
                    if self.decode(row[0]) != {'node': self.node, 'version': 4}:
                        raise ValueError('Mailbox Node identity mismatch')
                else:
                    if any(self.db.execute('SELECT 1 FROM '+table+' LIMIT 1').fetchone() for table in ('owners','records','migrations')):
                        raise ValueError('Mailbox binding missing')
                    self.db.execute('INSERT INTO metadata VALUES(1,?)', (self.encode({'node':self.node,'version':4}),))
        except BaseException:
            self.close()
            raise

    @contextmanager
    def transaction(self):
        self.db.execute('BEGIN IMMEDIATE')
        try:
            yield
            self.db.execute('COMMIT')
        except BaseException:
            self.db.execute('ROLLBACK')
            raise

    def encode(self, value):
        return bytes(self.box.encrypt(json.dumps(value, sort_keys=True, separators=(',',':')).encode()))

    def decode(self, value):
        return json.loads(self.box.decrypt(value))

    def alias(self, domain, value):
        return hmac.digest(self.alias_key, json.dumps([domain,self.node,value], separators=(',',':')).encode(), 'sha256').hex()

    def bind(self, evidence):
        grant = self.verifier.bind(evidence)
        if type(grant) is not Grant or not math.isfinite(grant.expires) or grant.expires <= self.clock():
            raise PermissionError('Invalid or expired grant')
        for value in (grant.recipient, grant.direction, grant.grant_id):
            _hex(value)
        if (type(grant.generation) is not int or not 0 <= grant.generation < 2**53
                or grant.policy != 'store-forward-v4'
                or type(grant.max_records) is not int or not 1 <= grant.max_records <= 128
                or type(grant.max_bytes) is not int or not 1 <= grant.max_bytes <= 524288):
            raise PermissionError('Invalid immutable grant policy')
        self.verifier.current(grant)
        if len(self.caps) >= self.MAX_CAPS:
            raise BufferError('Capability quota; release unused handles')
        # Full immutable grant commitment excludes only fresh session identity.
        identity = [self.node,grant.recipient,grant.direction,grant.grant_id,
                    grant.generation,grant.policy,grant.max_records,grant.max_bytes,grant.expires]
        commitment = hashlib.sha256(json.dumps(identity,separators=(',',':')).encode()).hexdigest()
        identity.append(commitment)
        owner = self.alias('owner', identity)
        with self.transaction():
            row = self.db.execute('SELECT box,retired FROM owners WHERE alias=?',(owner,)).fetchone()
            if row:
                if self.decode(row[0]) != identity:
                    raise PermissionError('Invalid owner')
                # Rebinding a retired owner grants no reads/writes/drain. It
                # permits only verified idempotent migration journal replay.
            else:
                if self.db.execute('SELECT count(*) FROM owners').fetchone()[0] >= self.MAX_OWNERS:
                    raise BufferError('Owner metadata quota')
                self.db.execute('INSERT INTO owners(alias,box) VALUES(?,?)',(owner,self.encode(identity)))
        cap = object()
        self.caps[cap] = (grant, owner)
        return cap

    def authority(self, cap, *, retired=False):
        try:
            grant, owner = self.caps[cap]
        except (KeyError,TypeError):
            raise PermissionError('Unknown capability') from None
        self.verifier.current(grant)
        if grant.expires <= self.clock():
            raise PermissionError('Expired grant')
        row = self.db.execute('SELECT retired FROM owners WHERE alias=?',(owner,)).fetchone()
        if not row or (row[0] and not retired):
            raise PermissionError('Retired owner')
        return grant, owner

    def release(self, cap):
        self.caps.pop(cap, None)

    def put(self, cap, delivery_id, ciphertext, expires, route_evidence):
        grant, owner = self.authority(cap)
        # Trusted verifier returns immutable (commitment,generation,expiry),
        # verified against route authority, never a socket-era label.
        binding = self.verifier.route(grant, route_evidence)
        if (type(binding) is not tuple or len(binding) != 3
                or type(binding[1]) is not int or not 0 <= binding[1] < 2**53
                or not math.isfinite(binding[2])):
            raise PermissionError('Invalid route binding')
        _hex(binding[0])
        if expires > min(grant.expires,binding[2]):
            raise PermissionError('Record outlives grant or route binding')
        _hex(delivery_id)
        if type(ciphertext) is not bytes or not 1 <= len(ciphertext) <= 65536 or not math.isfinite(expires) or expires <= self.clock():
            raise ValueError('Invalid record')
        dedupe = self.alias('delivery',[owner,delivery_id])
        value = {'owner':owner,'delivery':delivery_id,'ciphertext':ciphertext.hex(),'binding':list(binding),'expires':expires,'size':len(ciphertext),'dedupe':dedupe}
        with self.transaction():
            row = self.db.execute('SELECT box,expires FROM records WHERE owner=? AND dedupe=?',(owner,dedupe)).fetchone()
            if row:
                if self.decode(row[0]) != value or row[1] != expires:
                    raise ValueError('Conflicting delivery')
                return False
            count, size = self.db.execute('SELECT count(*),coalesce(sum(size),0) FROM records WHERE owner=?',(owner,)).fetchone()
            total = self.db.execute('SELECT coalesce(sum(size),0) FROM records').fetchone()[0]
            if count >= grant.max_records or size + len(ciphertext) > grant.max_bytes or total + len(ciphertext) > 67108864:
                raise BufferError('Mailbox quota')
            self.db.execute('INSERT INTO records(owner,dedupe,box,size,expires) VALUES(?,?,?,?,?)',(owner,dedupe,self.encode(value),len(ciphertext),expires))
        return True

    async def drain(self, cap, send):
        _, owner = self.authority(cap)
        now, lease = self.clock(), secrets.token_hex(32)
        with self.transaction():
            self.db.execute('UPDATE records SET lease=NULL,lease_until=NULL WHERE owner=? AND lease_until<=?',(owner,now))
            if self.db.execute('SELECT 1 FROM records WHERE owner=? AND lease IS NOT NULL',(owner,)).fetchone():
                raise BlockingIOError('Mailbox already leased')
            candidates = self.db.execute('SELECT id,box,expires,size,dedupe FROM records WHERE owner=? ORDER BY id',(owner,)).fetchall()
            rows = []
            self.last_blocked = 0
            grant, _ = self.authority(cap)
            for row_id, box, expires, size, dedupe in candidates:
                value = self.decode(box)
                if (value.get('owner') != owner or value.get('expires') != expires
                        or value.get('size') != size or value.get('dedupe') != dedupe
                        or len(bytes.fromhex(value['ciphertext'])) != size
                        or self.alias('delivery',[owner,value['delivery']]) != dedupe):
                    raise ValueError('Authenticated record metadata mismatch')
                if expires <= now:
                    self.db.execute('DELETE FROM records WHERE id=?',(row_id,))
                    continue
                try:
                    self.verifier.rebind(grant,tuple(value['binding']))
                except PermissionError:
                    self.last_blocked += 1
                    continue
                rows.append((row_id,box,expires))
                self.db.execute('UPDATE records SET lease=?,lease_until=? WHERE id=?',(lease,now+30,row_id))
        if not rows:
            return 0
        try:
            self.authority(cap)
            # This bounded logical ALL snapshot must be framed by the eventual
            # adapter; it is deliberately not an invented endpoint wire operation.
            snapshot = []
            for _, box, expires in rows:
                value = self.decode(box)
                if value.pop('owner', None) != owner:
                    raise ValueError('Encrypted record owner mismatch')
                snapshot.append({**value, 'expires':expires})
            def guard():
                grant, _ = self.authority(cap)
                for value in snapshot:
                    if value['expires'] <= self.clock():
                        raise PermissionError('Snapshot expired')
                    self.verifier.rebind(grant,tuple(value['binding']))
            guard()
            # Trusted adapter MUST call guard immediately before EVERY fragment
            # and must not buffer fragments for later unchecked transmission.
            result = await asyncio.wait_for(send(snapshot, guard), 10)
            if result is False:
                raise ConnectionError('Send reported failure')
            guard()
            with self.transaction():
                self.db.execute('DELETE FROM records WHERE owner=? AND lease=?',(owner,lease))
            return len(rows)
        except BaseException:
            # Synchronous transaction has no cancellation point; cleanup finishes
            # before cancellation propagates, including CancelledError.
            with self.transaction():
                self.db.execute('UPDATE records SET lease=NULL,lease_until=NULL WHERE owner=? AND lease=?',(owner,lease))
            raise

    def migrate(self, old_cap, new_cap, migration_id, evidence):
        old, source = self.authority(old_cap, retired=True)
        new, target = self.authority(new_cap)
        self.verifier.migration(old,new,evidence)
        _hex(migration_id)
        if source == target:
            raise ValueError('Migration owners identical')
        alias = self.alias('migration',migration_id)
        record = {'source':source,'target':target}
        with self.transaction():
            previous = self.db.execute('SELECT box FROM migrations WHERE alias=?',(alias,)).fetchone()
            if previous:
                if self.decode(previous[0]) != record:
                    raise ValueError('Migration ID conflict')
                return False
            self.authority(old_cap)
            if self.db.execute('SELECT count(*) FROM migrations').fetchone()[0] >= self.MAX_MIGRATIONS:
                raise BufferError('Migration metadata quota')
            if self.db.execute('SELECT 1 FROM records WHERE owner IN (?,?) AND lease IS NOT NULL',(source,target)).fetchone():
                raise BlockingIOError('Cannot migrate leased mailbox')
            # Require an empty destination: never merge ambiguous duplicate IDs.
            if self.db.execute('SELECT 1 FROM records WHERE owner=?',(target,)).fetchone():
                raise ValueError('Destination mailbox not empty')
            rows = self.db.execute('SELECT id,box FROM records WHERE owner=?',(source,)).fetchall()
            amount = self.db.execute('SELECT coalesce(sum(size),0) FROM records WHERE owner=?',(source,)).fetchone()[0]
            if len(rows) > new.max_records or amount > new.max_bytes:
                raise BufferError('Destination grant quota')
            for row_id, box in rows:
                value = self.decode(box)
                if value.get('owner') != source:
                    raise ValueError('Encrypted record owner mismatch')
                if value.get('binding') is None or self.db.execute('SELECT expires FROM records WHERE id=?',(row_id,)).fetchone()[0] > new.expires:
                    raise PermissionError('Destination grant cannot retain record lifetime')
                self.verifier.rebind(new,tuple(value['binding']))
                delivery = value['delivery']
                value['owner'] = target
                value['dedupe'] = self.alias('delivery',[target,delivery])
                self.db.execute('UPDATE records SET owner=?,dedupe=?,box=? WHERE id=?',(target,self.alias('delivery',[target,delivery]),self.encode(value),row_id))
            self.db.execute('UPDATE owners SET retired=1 WHERE alias=?',(source,))
            self.db.execute('INSERT INTO migrations VALUES(?,?)',(alias,self.encode(record)))
        return True

    def close(self):
        self.caps.clear()
        self.db.close()
