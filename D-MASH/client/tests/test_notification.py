import asyncio
import hashlib
import os
import tempfile
import unittest

from backend.database import DatabaseManager
from backend.notification import NotificationTrigger


class NotificationTriggerTests(unittest.IsolatedAsyncioTestCase):
    async def test_pickup_before_deadline_cancels_notification(self):
        calls = []
        async def sender(payload): calls.append(payload); return True
        trigger = NotificationTrigger(sender, delay_seconds=0.05)
        pending_id = trigger.schedule("opaque-handle")
        self.assertTrue(trigger.cancel(pending_id))
        await asyncio.sleep(0.08)
        self.assertEqual(calls, [])

    async def test_one_pending_state_notifies_once(self):
        calls = []
        async def sender(payload): calls.append(payload); return True
        trigger = NotificationTrigger(sender, delay_seconds=0.01)
        first = trigger.schedule("opaque-handle", "stable-pending")
        second = trigger.schedule("opaque-handle", "stable-pending")
        self.assertEqual(first, second)
        await asyncio.sleep(0.05)
        self.assertEqual(len(calls), 1)
        self.assertNotIn("sender", calls[0])
        self.assertNotIn("message", calls[0])

    async def test_retry_is_bounded_and_idempotency_is_stable(self):
        calls = []
        async def sender(payload): calls.append(payload.copy()); return len(calls) == 3
        trigger = NotificationTrigger(sender, delay_seconds=0, max_attempts=3)
        trigger.schedule("opaque-handle", "retry-pending")
        await asyncio.sleep(3.2)
        self.assertEqual(len(calls), 3)
        self.assertEqual(len({call["idempotency_key"] for call in calls}), 1)

    async def test_rehydrated_pending_state_notifies_without_second_delay(self):
        calls = []
        async def sender(payload): calls.append(payload); return True
        trigger = NotificationTrigger(sender, delay_seconds=60)
        trigger.schedule("opaque-handle", "restored-pending", created_at=0, expires_at=4_000_000_000)
        await asyncio.sleep(0.02)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["idempotency_key"], hashlib.sha256(b"dmash-notify-v1:restored-pending").hexdigest())

    async def test_mailbox_schedules_then_cancels_after_pickup(self):
        class Trigger:
            def __init__(self):
                self.scheduled = []
                self.cancelled = []

            def schedule(self, handle, pending_id):
                self.scheduled.append((handle, pending_id))
                return pending_id

            def cancel(self, pending_id):
                self.cancelled.append(pending_id)
                return True

        fd, path = tempfile.mkstemp(prefix="dmash-mailbox-", suffix=".db")
        os.close(fd)
        db = DatabaseManager(path)
        trigger = Trigger()
        try:
            await db.connect()
            db.set_notification_trigger(trigger)
            await db.save_to_mailbox('{"type":"DATA","content":"opaque"}')
            self.assertEqual(len(trigger.scheduled), 1)

            async def delivered(_packet, sender_id_hint=None):
                return True

            await db.process_mailbox(delivered)
            self.assertEqual([item[1] for item in trigger.scheduled], trigger.cancelled)
            async with db.conn.execute("SELECT count(*) FROM offline_mailbox") as cursor:
                self.assertEqual((await cursor.fetchone())[0], 0)
        finally:
            await db.close()
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
