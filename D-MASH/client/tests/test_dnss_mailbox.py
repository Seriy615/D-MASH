import asyncio
import base64
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from backend.dnss_mailbox import DnssMailbox, MailboxError


class DnssMailboxTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.now = 1000
        self.path = Path(self.tmp.name) / "mail.db"
        self.mailbox = DnssMailbox(self.path, clock=lambda: self.now)
        await self.mailbox.connect()
        self.alias, self.other = "ab" * 32, "cd" * 32
        self.ciphertext = base64.b64encode(b"opaque encrypted packet").decode()

    async def asyncTearDown(self):
        await self.mailbox.close()
        self.tmp.cleanup()

    async def count(self, alias=None):
        row = await (await self.mailbox.conn.execute("SELECT count(*) AS n FROM dnss_mailbox WHERE blind_dnss=?", (alias or self.alias,))).fetchone()
        return row["n"]

    async def test_all_in_one_result_delete_after_send_only(self):
        for i in range(20): await self.mailbox.put(self.alias, str(i), self.ciphertext)
        await self.mailbox.put(self.other, "other", self.ciphertext)
        sent = []
        async def send(result):
            self.assertEqual(await self.count(), 20)
            sent.append(result)
        self.assertEqual(await self.mailbox.drain(self.alias, send, "request"), 20)
        self.assertEqual(len(sent), 1)
        self.assertEqual(len(sent[0]["entries"]), 20)
        self.assertEqual(await self.count(), 0)
        self.assertEqual(await self.count(self.other), 1)

    async def test_failed_send_retains_all_and_releases_lease(self):
        await self.mailbox.put(self.alias, "1", self.ciphertext)
        async def fail(result): raise OSError("connection lost")
        with self.assertRaises(OSError): await self.mailbox.drain(self.alias, fail)
        self.assertEqual(await self.count(), 1)
        self.assertEqual(await self.mailbox.drain(self.alias, lambda result: asyncio.sleep(0)), 1)

    async def test_concurrent_drain_busy_and_arrivals_during_send_survive(self):
        await self.mailbox.put(self.alias, "1", self.ciphertext)
        entered, release = asyncio.Event(), asyncio.Event()
        async def send(result): entered.set(); await release.wait()
        task = asyncio.create_task(self.mailbox.drain(self.alias, send))
        await entered.wait()
        try:
            await self.mailbox.put(self.alias, "2", self.ciphertext)
            with self.assertRaisesRegex(MailboxError, "DRAIN_BUSY"):
                await self.mailbox.drain(self.alias, lambda result: asyncio.sleep(0))
        finally:
            release.set()
            await task
        self.assertEqual(await self.count(), 1)

    async def test_crash_reservation_expires_and_durable_mail_survives(self):
        await self.mailbox.put(self.alias, "1", self.ciphertext)
        await self.mailbox._reserve(self.alias)
        await self.mailbox.close()
        self.mailbox = DnssMailbox(self.path, clock=lambda: self.now)
        await self.mailbox.connect()
        self.now += 31
        self.assertEqual(await self.mailbox.drain(self.alias, lambda result: asyncio.sleep(0)), 1)

    async def test_duplicate_id_and_collision_and_quota(self):
        self.assertTrue(await self.mailbox.put(self.alias, "1", self.ciphertext))
        self.assertFalse(await self.mailbox.put(self.alias, "1", self.ciphertext))
        with self.assertRaisesRegex(MailboxError, "CONFLICT"):
            await self.mailbox.put(self.alias, "1", "YWJj")
        with patch("backend.dnss_mailbox.MAX_ENTRIES", 1):
            with self.assertRaisesRegex(MailboxError, "QUOTA"): await self.mailbox.put(self.alias, "2", self.ciphertext)
        self.assertEqual(await self.count(), 1)

    async def test_cancel_send_keeps_data(self):
        await self.mailbox.put(self.alias, "1", self.ciphertext)
        entered = asyncio.Event()
        async def send(result): entered.set(); await asyncio.Future()
        task = asyncio.create_task(self.mailbox.drain(self.alias, send))
        await entered.wait()
        task.cancel()
        with self.assertRaises(asyncio.CancelledError): await task
        self.assertEqual(await self.count(), 1)
        self.assertEqual(await self.mailbox.drain(self.alias, lambda result: asyncio.sleep(0)), 1)

    async def test_schema_has_no_route_id_or_raw_dnss(self):
        await self.mailbox.put(self.alias, "1", self.ciphertext)
        columns = await (await self.mailbox.conn.execute("PRAGMA table_info(dnss_mailbox)")).fetchall()
        names = {row["name"] for row in columns}
        self.assertNotIn("route_id", names)
        self.assertNotIn("dnss", names)
