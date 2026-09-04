"""One-time Telegram deep-link and webhook-secret enrollment primitives."""
import hashlib
import hmac
import secrets
import sqlite3
import time
import base64
from dataclasses import dataclass

from personal_bot_vault import owner_alias
from nacl import secret


TTL_SECONDS = 600


def _chat_box(vault_key: str):
    return secret.SecretBox(base64.urlsafe_b64decode(vault_key.encode("ascii")))


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

    def has_webhook_secret(self, db: sqlite3.Connection, webhook_secret: str) -> bool:
        if not isinstance(webhook_secret, str) or not webhook_secret:
            return False
        row = db.execute("SELECT 1 FROM bot_enrollments WHERE webhook_secret_hash = ?", (_digest(webhook_secret),)).fetchone()
        return row is not None

    def bind_from_webhook(self, db: sqlite3.Connection, webhook_secret: str, chat_id: str, command: str, vault_key: str | None = None) -> str | None:
        row = db.execute("SELECT owner_alias,start_code_hash,expires_at,consumed_at FROM bot_enrollments WHERE webhook_secret_hash = ?", (_digest(webhook_secret),)).fetchone()
        if row is None:
            return None
        if row[3] is not None or int(time.time()) >= int(row[2]) or not command.startswith('/start '):
            return None
        if not hmac.compare_digest(row[1], _digest(command.removeprefix('/start ').strip())):
            return None
        stored_chat_id = base64.urlsafe_b64encode(_chat_box(vault_key).encrypt(str(chat_id).encode())).decode("ascii") if vault_key else str(chat_id)
        db.execute("UPDATE bot_enrollments SET chat_id=?, consumed_at=? WHERE owner_alias=?", (stored_chat_id, int(time.time()), row[0]))
        return row[0]

    def status_for_start(self, db: sqlite3.Connection, webhook_secret: str, command: str) -> str:
        """Classify a valid deep-link as new, already bound, or invalid."""
        row = db.execute("SELECT owner_alias,start_code_hash,expires_at,consumed_at FROM bot_enrollments WHERE webhook_secret_hash = ?", (_digest(webhook_secret),)).fetchone()
        if row is None or not command.startswith('/start '): return "invalid"
        if not hmac.compare_digest(row[1], _digest(command.removeprefix('/start ').strip())): return "invalid"
        if row[3] is not None: return "already_bound"
        if int(time.time()) >= int(row[2]): return "invalid"
        return "ready"

    def stop_from_webhook(self, db: sqlite3.Connection, webhook_secret: str, chat_id: str, command: str, vault_key: str | None = None) -> str | None:
        """Delete a bound enrollment only when /stop comes from its webhook."""
        if command.strip() != "/stop": return None
        row = db.execute("SELECT owner_alias,chat_id,consumed_at FROM bot_enrollments WHERE webhook_secret_hash = ?", (_digest(webhook_secret),)).fetchone()
        if row is None or row[2] is None: return None
        try:
            stored_chat = _chat_box(vault_key).decrypt(base64.urlsafe_b64decode(row[1].encode())).decode() if vault_key else str(row[1])
        except Exception:
            return None
        if stored_chat != str(chat_id): return None
        db.execute("DELETE FROM bot_enrollments WHERE owner_alias=?", (row[0],))
        return row[0]

    def chat_id_for_owner(self, db: sqlite3.Connection, owner_handle: str, vault_key: str | None = None) -> str | None:
        """Return only the already-bound Telegram destination for this owner."""
        row = db.execute(
            "SELECT chat_id FROM bot_enrollments WHERE owner_alias=? AND consumed_at IS NOT NULL",
            (owner_alias(owner_handle),),
        ).fetchone()
        if row is None or row[0] is None: return None
        return _chat_box(vault_key).decrypt(base64.urlsafe_b64decode(row[0].encode())).decode() if vault_key else str(row[0])

    def remove_for_owner(self, db: sqlite3.Connection, owner_handle: str) -> bool:
        result = db.execute("DELETE FROM bot_enrollments WHERE owner_alias=?", (owner_alias(owner_handle),))
        return result.rowcount == 1
