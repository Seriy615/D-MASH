"""Isolated Origin notification service. Telegram secrets never reach nodes."""

import hashlib
import hmac
import json
import os
import sqlite3
import time
import urllib.parse
import urllib.request
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Request


DB_PATH = Path(os.getenv("NOTIFICATION_DB_PATH", "/var/lib/dmash-notify/notifications.db"))
TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
HMAC_KEY = os.getenv("DMASH_NOTIFICATION_HMAC_KEY", "").encode()
MESSAGE = "У вас новое сообщение в D-MASH"

app = FastAPI(title="D-MASH Origin Notifications", docs_url=None, redoc_url=None)


def connect_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DB_PATH)
    db.execute("CREATE TABLE IF NOT EXISTS bindings (handle_hash TEXT PRIMARY KEY, chat_id TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1)")
    db.execute("CREATE TABLE IF NOT EXISTS delivered (idempotency_key TEXT PRIMARY KEY, delivered_at INTEGER NOT NULL, expires_at INTEGER NOT NULL)")
    db.commit()
    return db


def handle_hash(handle: str) -> str:
    return hashlib.sha256(("dmash-notify-handle-v1:" + handle).encode()).hexdigest()


def verify_node_request(body: bytes, signature: str):
    if len(HMAC_KEY) < 32:
        raise HTTPException(503, "notification service not configured")
    expected = hmac.new(HMAC_KEY, body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature or ""):
        raise HTTPException(403, "invalid node authentication")


def telegram_send(chat_id: str) -> bool:
    if not TOKEN:
        raise HTTPException(503, "telegram integration not configured")
    body = urllib.parse.urlencode({"chat_id": chat_id, "text": MESSAGE}).encode()
    request = urllib.request.Request(f"https://api.telegram.org/bot{TOKEN}/sendMessage", data=body, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            result = json.load(response)
            return bool(result.get("ok"))
    except Exception:
        return False


@app.get("/health")
async def health():
    return {"status": "ok", "telegram_configured": bool(TOKEN), "node_auth_configured": len(HMAC_KEY) >= 32}


@app.post("/v1/notify")
async def notify(request: Request, x_dmash_signature: str = Header(default="")):
    body = await request.body()
    verify_node_request(body, x_dmash_signature)
    try:
        payload = json.loads(body)
        handle = payload["notification_handle"]
        key = payload["idempotency_key"]
        expires_at = int(payload["expires_at"])
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        raise HTTPException(400, "invalid notification request")
    if int(time.time()) >= expires_at:
        raise HTTPException(410, "notification expired")
    with connect_db() as db:
        if db.execute("SELECT 1 FROM delivered WHERE idempotency_key = ?", (key,)).fetchone():
            return {"status": "already_processed"}
        row = db.execute("SELECT chat_id FROM bindings WHERE handle_hash = ? AND enabled = 1", (handle_hash(handle),)).fetchone()
        if not row:
            return {"status": "no_binding"}
        if not telegram_send(row[0]):
            raise HTTPException(502, "notification provider unavailable")
        db.execute("INSERT INTO delivered (idempotency_key, delivered_at, expires_at) VALUES (?, ?, ?)", (key, int(time.time()), expires_at))
        db.execute("DELETE FROM delivered WHERE expires_at < ?", (int(time.time()),))
        db.commit()
    return {"status": "notified"}
