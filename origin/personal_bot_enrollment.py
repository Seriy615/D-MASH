"""One-time Telegram deep-link and webhook-secret enrollment primitives."""
import hashlib
import hmac
import secrets
import sqlite3
import time
from dataclasses import dataclass

from personal_bot_vault import owner_alias


TTL_SECONDS = 600


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


@dataclass(frozen=True)
class EnrollmentSecrets:
    start_code: str
    webhook_secret: str
    expires_at: int


class EnrollmentStore:
    def ensure_schema(self, db: sqlite3.Connection) -> None:
        db.execute("""CREATE TABLE IF NOT EXISTS bot_enrollments (
            owner_alias TEXT PRIMARY KEY, start_code_hash TEXT NOT NULL,
            webhook_secret_hash TEXT NOT NULL UNIQUE, expires_at INTEGER NOT NULL,
            chat_id TEXT, consumed_at INTEGER
        )""")

    def create(self, db: sqlite3.Connection, owner_handle: str, ttl_seconds: int = TTL_SECONDS) -> EnrollmentSecrets:
        now = int(time.time())
        start_code, webhook_secret = secrets.token_urlsafe(24), secrets.token_urlsafe(32)
        expires_at = now + ttl_seconds
        db.execute("""INSERT INTO bot_enrollments (owner_alias,start_code_hash,webhook_secret_hash,expires_at,chat_id,consumed_at)
            VALUES (?, ?, ?, ?, NULL, NULL)
            ON CONFLICT(owner_alias) DO UPDATE SET start_code_hash=excluded.start_code_hash,
            webhook_secret_hash=excluded.webhook_secret_hash, expires_at=excluded.expires_at, chat_id=NULL, consumed_at=NULL
        """, (owner_alias(owner_handle), _digest(start_code), _digest(webhook_secret), expires_at))
        return EnrollmentSecrets(start_code, webhook_secret, expires_at)

    def bind_from_webhook(self, db: sqlite3.Connection, webhook_secret: str, chat_id: str, command: str) -> str | None:
        row = db.execute("SELECT owner_alias,start_code_hash,expires_at,consumed_at FROM bot_enrollments WHERE webhook_secret_hash = ?", (_digest(webhook_secret),)).fetchone()
        if row is None:
            return None
        if row[3] is not None or int(time.time()) >= int(row[2]) or not command.startswith('/start '):
            return None
        if not hmac.compare_digest(row[1], _digest(command.removeprefix('/start ').strip())):
            return None
        db.execute("UPDATE bot_enrollments SET chat_id=?, consumed_at=? WHERE owner_alias=?", (str(chat_id), int(time.time()), row[0]))
        return row[0]
