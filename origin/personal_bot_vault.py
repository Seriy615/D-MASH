"""Encrypted-at-rest storage primitive for a user's private Telegram bot token.

This module intentionally has no HTTP routes. The caller must first authenticate a
fresh signed user request and complete a product-approved chat-binding flow.
"""

from __future__ import annotations

import base64
import hashlib
import sqlite3
import time
from dataclasses import dataclass

from nacl import secret, utils


KEY_VERSION = 1


def owner_alias(owner_handle: str) -> str:
    if not isinstance(owner_handle, str) or not owner_handle or len(owner_handle) > 256:
        raise ValueError("invalid owner handle")
    return hashlib.sha256(f"dmash-personal-bot-owner-v1:{owner_handle}".encode()).hexdigest()


@dataclass(frozen=True)
class StoredBot:
    enabled: bool
    token_suffix: str
    updated_at: int


class PersonalBotVault:
    """SecretBox vault. Raw token is never returned by status/list methods."""

    def __init__(self, encoded_key: str):
        try:
            key = base64.urlsafe_b64decode(encoded_key.encode("ascii"))
        except Exception as exc:
            raise ValueError("invalid notification vault key encoding") from exc
        if len(key) != secret.SecretBox.KEY_SIZE:
            raise ValueError("notification vault key must decode to 32 bytes")
        self._box = secret.SecretBox(key)

    @staticmethod
    def ensure_schema(db: sqlite3.Connection) -> None:
        db.execute("""
            CREATE TABLE IF NOT EXISTS personal_bots (
                owner_alias TEXT PRIMARY KEY,
                token_ciphertext TEXT NOT NULL,
                token_suffix TEXT NOT NULL,
                key_version INTEGER NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                updated_at INTEGER NOT NULL
            )
        """)

    def save(self, db: sqlite3.Connection, owner_handle: str, bot_token: str) -> StoredBot:
        if not isinstance(bot_token, str) or not bot_token or len(bot_token) > 512:
            raise ValueError("invalid bot token")
        now = int(time.time())
        encrypted = self._box.encrypt(bot_token.encode("utf-8"), utils.random(secret.SecretBox.NONCE_SIZE))
        ciphertext = base64.urlsafe_b64encode(encrypted).decode("ascii")
        suffix = bot_token[-4:]
        db.execute("""
            INSERT INTO personal_bots (owner_alias, token_ciphertext, token_suffix, key_version, enabled, updated_at)
            VALUES (?, ?, ?, ?, 1, ?)
            ON CONFLICT(owner_alias) DO UPDATE SET
                token_ciphertext=excluded.token_ciphertext,
                token_suffix=excluded.token_suffix,
                key_version=excluded.key_version,
                enabled=1,
                updated_at=excluded.updated_at
        """, (owner_alias(owner_handle), ciphertext, suffix, KEY_VERSION, now))
        return StoredBot(enabled=True, token_suffix=suffix, updated_at=now)

    def status(self, db: sqlite3.Connection, owner_handle: str) -> StoredBot | None:
        row = db.execute("SELECT enabled, token_suffix, updated_at FROM personal_bots WHERE owner_alias = ?", (owner_alias(owner_handle),)).fetchone()
        return None if row is None else StoredBot(enabled=bool(row[0]), token_suffix=row[1], updated_at=int(row[2]))

    def decrypt_for_delivery(self, db: sqlite3.Connection, owner_handle: str) -> str | None:
        row = db.execute("SELECT token_ciphertext FROM personal_bots WHERE owner_alias = ? AND enabled = 1", (owner_alias(owner_handle),)).fetchone()
        if row is None:
            return None
        try:
            return self._box.decrypt(base64.urlsafe_b64decode(row[0].encode("ascii"))).decode("utf-8")
        except Exception as exc:
            raise ValueError("stored bot token cannot be decrypted") from exc

    def disable(self, db: sqlite3.Connection, owner_handle: str) -> bool:
        result = db.execute("UPDATE personal_bots SET enabled = 0, updated_at = ? WHERE owner_alias = ?", (int(time.time()), owner_alias(owner_handle)))
        return result.rowcount == 1

    def remove(self, db: sqlite3.Connection, owner_handle: str) -> bool:
        result = db.execute("DELETE FROM personal_bots WHERE owner_alias = ?", (owner_alias(owner_handle),))
        return result.rowcount == 1
