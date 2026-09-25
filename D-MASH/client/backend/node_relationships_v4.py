"""Encrypted directional relationship persistence for the opt-in Node v4 runtime.

This store contains relationships, never per-socket authorization. A successful
lookup does not waive fresh password admission or transcript-bound resource work.
"""
import hmac
import json
import secrets
import sqlite3
from pathlib import Path
from nacl.secret import SecretBox

from .node_registration_v4 import _hex


class RelationshipStore:
    def __init__(self, path, local_id, storage_key, *, max_relationships=4096):
        self.local_id = _hex(local_id, 64)
        if type(max_relationships) is not int or not 1 <= max_relationships <= 65536:
            raise ValueError("invalid relationship quota")
        self.max_relationships = max_relationships
        if not isinstance(storage_key, bytes) or len(storage_key) != SecretBox.KEY_SIZE:
            raise ValueError('Node storage key must be 32 bytes')
        # Independent keys, so persistent lookups are not encryption-key reuse.
        self._alias_key = hmac.digest(storage_key, b'D-MASH|NODE-RELATIONSHIP-ALIAS|V4', 'sha256')
        self._box = SecretBox(hmac.digest(storage_key, b'D-MASH|NODE-RELATIONSHIP-STORAGE|V4', 'sha256'))
        self.db = sqlite3.connect(Path(path), isolation_level=None, timeout=5)
        self.db.execute('PRAGMA busy_timeout=5000')
        self.db.execute('CREATE TABLE IF NOT EXISTS node_relationship_v4 (alias TEXT PRIMARY KEY, ciphertext BLOB NOT NULL)')
        self.db.execute('CREATE TABLE IF NOT EXISTS node_relationship_metadata_v4 (id INTEGER PRIMARY KEY CHECK(id=1), ciphertext BLOB NOT NULL)')
        self.db.execute('BEGIN IMMEDIATE')
        try:
            binding = ('D-MASH|NODE-RELATIONSHIP-STORE|V4|' + self.local_id).encode()
            row = self.db.execute('SELECT ciphertext FROM node_relationship_metadata_v4 WHERE id=1').fetchone()
            if row:
                if not hmac.compare_digest(self._box.decrypt(row[0]), binding):
                    raise ValueError('Node relationship store identity changed')
            else:
                if self.db.execute('SELECT 1 FROM node_relationship_v4 LIMIT 1').fetchone():
                    raise ValueError('Node relationship store binding missing')
                self.db.execute('INSERT INTO node_relationship_metadata_v4 VALUES (1, ?)', (bytes(self._box.encrypt(binding)),))
            self.db.execute('COMMIT')
        except BaseException:
            self.db.execute('ROLLBACK')
            self.close()
            raise


    def _alias(self, peer):
        _hex(peer, 64)
        if peer == self.local_id:
            raise ValueError('self relationship forbidden')
        return hmac.digest(self._alias_key, bytes.fromhex(self.local_id + peer), 'sha256').hex()

    def _decode(self, row, peer):
        # Wrong keys/corruption fail closed. Never regenerate an unreadable row.
        try:
            record = json.loads(self._box.decrypt(row[0]))
            if (set(record) != {'version', 'local_id', 'peer_id', 'outbound', 'inbound'}
                    or type(record['version']) is not int or record['version'] != 4
                    or record['local_id'] != self.local_id or record['peer_id'] != peer):
                raise ValueError('invalid relationship binding')
            _hex(record['outbound'], 32)
            if record['inbound'] is not None:
                _hex(record['inbound'], 32)
                if record['inbound'] == record['outbound']:
                    raise ValueError('direction collision')
            return record
        except Exception as error:
            raise ValueError('Node relationship storage is unreadable; recovery required') from error

    def _load(self, alias, peer):
        row = self.db.execute('SELECT ciphertext FROM node_relationship_v4 WHERE alias=?', (alias,)).fetchone()
        if row:
            return self._decode(row, peer)
        if self.db.execute('SELECT COUNT(*) FROM node_relationship_v4').fetchone()[0] >= self.max_relationships:
            raise PermissionError('Node relationship quota exhausted')
        return {
            'version':4, 'local_id':self.local_id, 'peer_id':peer,
            'outbound':secrets.token_hex(16), 'inbound':None}

    def _save(self, alias, record):
        ciphertext = bytes(self._box.encrypt(json.dumps(record, sort_keys=True, separators=(',', ':')).encode()))
        self.db.execute('INSERT INTO node_relationship_v4 VALUES (?, ?) ON CONFLICT(alias) DO UPDATE SET ciphertext=excluded.ciphertext', (alias, ciphertext))

    def relationship(self, peer, *, inbound=None):
        """Atomically obtain local direction and optionally pin VERIFIED peer direction.

        Only call with inbound after authenticated session/resource verification.
        A changed peer direction requires explicit recovery/migration; do not silently
        replace it and thereby abandon or transfer a durable mailbox.
        """
        alias = self._alias(peer)
        if inbound is not None:
            _hex(inbound, 32)
        self.db.execute('BEGIN IMMEDIATE')
        try:
            record = self._load(alias, peer)
            if inbound is not None:
                if record['inbound'] not in (None, inbound) or record['outbound'] == inbound:
                    raise PermissionError('Node relationship changed; explicit recovery required')
                record['inbound'] = inbound
            self._save(alias, record)
            self.db.execute('COMMIT')
            return {'outbound':record['outbound'], 'inbound':record['inbound']}
        except BaseException:
            self.db.execute('ROLLBACK')
            raise

    def close(self):
        self.db.close()
        self._box = None
        self._alias_key = None
