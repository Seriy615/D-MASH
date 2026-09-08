"""Durable, quota-bounded DNSS mailbox with send-then-delete drain leases."""
import asyncio
import secrets
import time
import os

import aiosqlite

if __package__:
    from .secure_session import unb64
else:
    from secure_session import unb64

MAX_ENTRIES = 128
MAX_MAILBOX_BYTES = 512 * 1024
MAX_CIPHERTEXT_BYTES = 64 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
LEASE_SECONDS = 30
SEND_TIMEOUT = 10


class MailboxError(RuntimeError):
    pass


class DnssMailbox:
    def __init__(self, path, *, clock=time.time):
        self.path, self.clock = str(path), clock
        self.conn = None
        self.lock = asyncio.Lock()

    async def connect(self):
        if self.path != ":memory:":
            try:
                descriptor = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                os.close(descriptor)
            except FileExistsError:
                os.chmod(self.path, 0o600)
        self.conn = await aiosqlite.connect(self.path, isolation_level=None)
        self.conn.row_factory = aiosqlite.Row
        await self.conn.execute("PRAGMA journal_mode=WAL")
        await self.conn.execute("PRAGMA synchronous=FULL")
        await self.conn.execute("PRAGMA busy_timeout=5000")
        await self.conn.execute("""CREATE TABLE IF NOT EXISTS dnss_mailbox (
            row_id INTEGER PRIMARY KEY AUTOINCREMENT,
            delivery_id TEXT NOT NULL,
            blind_dnss TEXT NOT NULL,
            ciphertext TEXT NOT NULL,
            size INTEGER NOT NULL,
            received_at INTEGER NOT NULL,
            lease TEXT,
            lease_until INTEGER,
            UNIQUE(blind_dnss, delivery_id)
        )""")
        await self.conn.execute("CREATE INDEX IF NOT EXISTS dnss_mailbox_owner ON dnss_mailbox(blind_dnss)")

    async def close(self):
        if self.conn: await self.conn.close()

    @staticmethod
    def _alias(value):
        if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
            raise MailboxError("INVALID_MAILBOX_ALIAS")

    async def put(self, blind_dnss, delivery_id, ciphertext):
        self._alias(blind_dnss)
        if not isinstance(delivery_id, str) or not 1 <= len(delivery_id) <= 128 or not delivery_id.isascii():
            raise MailboxError("INVALID_DELIVERY_ID")
        if not isinstance(ciphertext, str) or not 1 <= len(ciphertext) <= MAX_CIPHERTEXT_BYTES:
            raise MailboxError("CIPHERTEXT_LIMIT")
        try: unb64(ciphertext)
        except Exception as error: raise MailboxError("INVALID_CIPHERTEXT") from error
        size = len(ciphertext)
        async with self.lock:
            await self.conn.execute("BEGIN IMMEDIATE")
            try:
                row = await (await self.conn.execute(
                    "SELECT ciphertext FROM dnss_mailbox WHERE blind_dnss=? AND delivery_id=?", (blind_dnss, delivery_id))).fetchone()
                if row:
                    if row["ciphertext"] != ciphertext: raise MailboxError("DELIVERY_ID_CONFLICT")
                    await self.conn.execute("COMMIT")
                    return False
                quota = await (await self.conn.execute(
                    "SELECT count(*) AS n, coalesce(sum(size),0) AS bytes FROM dnss_mailbox WHERE blind_dnss=?", (blind_dnss,))).fetchone()
                total = await (await self.conn.execute("SELECT coalesce(sum(size),0) AS bytes FROM dnss_mailbox")).fetchone()
                if quota["n"] >= MAX_ENTRIES or quota["bytes"] + size > MAX_MAILBOX_BYTES or total["bytes"] + size > MAX_TOTAL_BYTES:
                    raise MailboxError("MAILBOX_QUOTA")
                await self.conn.execute(
                    "INSERT INTO dnss_mailbox(delivery_id,blind_dnss,ciphertext,size,received_at) VALUES(?,?,?,?,?)",
                    (delivery_id, blind_dnss, ciphertext, size, int(self.clock())))
                await self.conn.execute("COMMIT")
                return True
            except BaseException:
                await self.conn.execute("ROLLBACK")
                raise

    async def _reserve(self, blind_dnss):
        self._alias(blind_dnss)
        token = secrets.token_hex(32)
        async with self.lock:
            await self.conn.execute("BEGIN IMMEDIATE")
            try:
                now = int(self.clock())
                await self.conn.execute("UPDATE dnss_mailbox SET lease=NULL,lease_until=NULL WHERE blind_dnss=? AND lease_until<=?", (blind_dnss, now))
                active = await (await self.conn.execute("SELECT 1 FROM dnss_mailbox WHERE blind_dnss=? AND lease IS NOT NULL LIMIT 1", (blind_dnss,))).fetchone()
                if active: raise MailboxError("DRAIN_BUSY")
                rows = await (await self.conn.execute(
                    "SELECT delivery_id,ciphertext FROM dnss_mailbox WHERE blind_dnss=? ORDER BY row_id", (blind_dnss,))).fetchall()
                await self.conn.execute("UPDATE dnss_mailbox SET lease=?,lease_until=? WHERE blind_dnss=?", (token, now + LEASE_SECONDS, blind_dnss))
                await self.conn.execute("COMMIT")
                return token, [dict(row) for row in rows]
            except BaseException:
                await self.conn.execute("ROLLBACK")
                raise

    async def _finish(self, blind_dnss, token, sent):
        async with self.lock:
            await self.conn.execute("BEGIN IMMEDIATE")
            try:
                if sent:
                    await self.conn.execute("DELETE FROM dnss_mailbox WHERE blind_dnss=? AND lease=?", (blind_dnss, token))
                else:
                    await self.conn.execute("UPDATE dnss_mailbox SET lease=NULL,lease_until=NULL WHERE blind_dnss=? AND lease=?", (blind_dnss, token))
                await self.conn.execute("COMMIT")
            except BaseException:
                await self.conn.execute("ROLLBACK")
                raise

    async def drain(self, blind_dnss, send, request_id=None):
        """Exactly one logical result; never select a client-supplied locator.

        The caller must pass the alias of its authenticated DNSS session. New
        arrivals during send are unleased and survive the subsequent delete.
        """
        token, entries = await self._reserve(blind_dnss)
        try:
            await asyncio.wait_for(send({"type": "MAILBOX_DRAIN_RESULT", "request_id": request_id, "entries": entries}), SEND_TIMEOUT)
        except BaseException:
            await asyncio.shield(self._finish(blind_dnss, token, False))
            raise
        await self._finish(blind_dnss, token, True)
        return len(entries)
