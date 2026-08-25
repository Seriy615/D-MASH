"""Isolated Origin notification service. Telegram secrets never reach nodes."""

import base64
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
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from personal_bot_enrollment import EnrollmentStore
from personal_bot_vault import PersonalBotVault

DB_PATH = Path(os.getenv("NOTIFICATION_DB_PATH", "/var/lib/dmash-notify/notifications.db"))
TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
HMAC_KEY = os.getenv("DMASH_NOTIFICATION_HMAC_KEY", "").encode()
VAULT_KEY = os.getenv("NOTIFICATION_VAULT_KEY", "")
PERSONAL_WEBHOOK_URL = os.getenv("PERSONAL_BOT_WEBHOOK_URL", "")
MESSAGE = "У вас новое сообщение в D-MASH"

app = FastAPI(title="D-MASH Origin Notifications", docs_url=None, redoc_url=None)


def connect_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DB_PATH)
    db.execute("CREATE TABLE IF NOT EXISTS bindings (handle_hash TEXT PRIMARY KEY, chat_id TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1)")
    db.execute("CREATE TABLE IF NOT EXISTS delivered (idempotency_key TEXT PRIMARY KEY, delivered_at INTEGER NOT NULL, expires_at INTEGER NOT NULL)")
    EnrollmentStore().ensure_schema(db)
    if VAULT_KEY:
        PersonalBotVault(VAULT_KEY).ensure_schema(db)
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


def telegram_call(token: str, method: str, fields: dict) -> dict | None:
    body = urllib.parse.urlencode(fields).encode()
    request = urllib.request.Request(f"https://api.telegram.org/bot{token}/{method}", data=body, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            result = json.load(response)
        return result.get("result") if result.get("ok") else None
    except Exception:
        return None


def telegram_send(chat_id: str) -> bool:
    if not TOKEN:
        raise HTTPException(503, "telegram integration not configured")
    return bool(telegram_call(TOKEN, "sendMessage", {"chat_id": chat_id, "text": MESSAGE}))


def personal_delivery_target(db: sqlite3.Connection, owner: str) -> tuple[str, str] | None:
    """Resolve a user's own encrypted bot and bound chat only inside Origin.

    The return value is deliberately local to this process. It is never sent to
    a D-MASH node, included in a mesh packet, or returned by an HTTP response.
    """
    if not VAULT_KEY:
        return None
    chat_id = EnrollmentStore().chat_id_for_owner(db, owner)
    if not chat_id:
        return None
    token = PersonalBotVault(VAULT_KEY).decrypt_for_delivery(db, owner)
    return None if not token else (token, chat_id)


def send_personal_test(db: sqlite3.Connection, owner: str) -> bool | None:
    target = personal_delivery_target(db, owner)
    if target is None:
        return None
    token, chat_id = target
    return bool(telegram_call(token, "sendMessage", {"chat_id": chat_id, "text": MESSAGE}))


def verify_personal_request(db: sqlite3.Connection, payload: dict, action: str) -> str:
    auth = payload.pop("auth", None)
    if not isinstance(auth, dict):
        raise HTTPException(401, "missing user authentication")
    try:
        public_key = bytes.fromhex(auth["public_key"])
        timestamp = int(auth["timestamp"])
        nonce = auth["nonce"]
        signature = base64.b64decode(auth["signature"], validate=True)
        if len(public_key) != 32 or len(signature) != 64 or not isinstance(nonce, str) or not nonce or len(nonce) > 128:
            raise ValueError
    except (KeyError, TypeError, ValueError):
        raise HTTPException(401, "invalid user authentication")
    if abs(int(time.time()) - timestamp) > 300:
        raise HTTPException(401, "expired user authentication")
    transcript = f"DMP-ORIGIN|1|{action}|{timestamp}|{nonce}|".encode() + json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    try:
        VerifyKey(public_key).verify(transcript, signature)
    except BadSignatureError:
        raise HTTPException(401, "invalid user signature")
    db.execute("CREATE TABLE IF NOT EXISTS personal_auth_nonces (nonce_hash TEXT PRIMARY KEY, expires_at INTEGER NOT NULL)")
    nonce_hash = hashlib.sha256(f"dmash-origin-nonce-v1:{auth['public_key']}:{nonce}".encode()).hexdigest()
    try:
        db.execute("INSERT INTO personal_auth_nonces (nonce_hash, expires_at) VALUES (?, ?)", (nonce_hash, timestamp + 300))
    except sqlite3.IntegrityError:
        raise HTTPException(409, "replayed user authentication")
    db.execute("DELETE FROM personal_auth_nonces WHERE expires_at < ?", (int(time.time()),))
    # A valid signed request must consume its nonce even if a later provider
    # call rejects the bot token or times out. Otherwise a captured request
    # could be replayed while the surrounding transaction rolls back.
    db.commit()
    return auth["public_key"]


@app.get("/health")
async def health():
    return {"status": "ok", "telegram_configured": bool(TOKEN), "node_auth_configured": len(HMAC_KEY) >= 32, "personal_bot_enrollment_configured": bool(VAULT_KEY and PERSONAL_WEBHOOK_URL.startswith("https://"))}


@app.post("/v1/personal-bots/enroll")
async def enroll_personal_bot(request: Request):
    try:
        payload = await request.json()
    except json.JSONDecodeError:
        raise HTTPException(400, "invalid JSON")
    token = payload.get("bot_token") if isinstance(payload, dict) else None
    if not VAULT_KEY or not PERSONAL_WEBHOOK_URL.startswith("https://"):
        raise HTTPException(503, "personal bot enrollment not configured")
    if not isinstance(token, str):
        raise HTTPException(400, "invalid bot token")
    with connect_db() as db:
        owner = verify_personal_request(db, payload, "PERSONAL_BOT_ENROLL")
        bot = telegram_call(token, "getMe", {})
        if not bot or not bot.get("username"):
            raise HTTPException(400, "Telegram bot token rejected")
        vault = PersonalBotVault(VAULT_KEY)
        stored = vault.save(db, owner, token)
        enrollment = EnrollmentStore().create(db, owner)
        webhook_ok = telegram_call(token, "setWebhook", {"url": PERSONAL_WEBHOOK_URL, "secret_token": enrollment.webhook_secret, "allowed_updates": json.dumps(["message"]), "drop_pending_updates": "true"})
        if not webhook_ok:
            vault.disable(db, owner)
            raise HTTPException(502, "Telegram webhook setup failed")
        db.commit()
    return {"status": "awaiting_start", "bot_username": bot["username"], "start_link": f"https://t.me/{bot['username']}?start={enrollment.start_code}", "token_suffix": stored.token_suffix, "expires_at": enrollment.expires_at}


async def signed_personal_action(request: Request, action: str) -> tuple[sqlite3.Connection, str]:
    """Parse one fresh signed PWA request. Callers must close the returned DB."""
    try:
        payload = await request.json()
    except json.JSONDecodeError:
        raise HTTPException(400, "invalid JSON")
    if not isinstance(payload, dict):
        raise HTTPException(400, "invalid request")
    db = connect_db()
    try:
        owner = verify_personal_request(db, payload, action)
    except Exception:
        db.close()
        raise
    return db, owner


@app.post("/v1/personal-bots/status")
async def personal_bot_status(request: Request):
    db, owner = await signed_personal_action(request, "PERSONAL_BOT_STATUS")
    try:
        stored = PersonalBotVault(VAULT_KEY).status(db, owner) if VAULT_KEY else None
        bound = EnrollmentStore().chat_id_for_owner(db, owner) is not None
        return {
            "configured": stored is not None,
            "enabled": bool(stored and stored.enabled),
            "token_suffix": stored.token_suffix if stored else None,
            "updated_at": stored.updated_at if stored else None,
            "chat_bound": bound,
        }
    finally:
        db.close()


@app.post("/v1/personal-bots/test")
async def test_personal_bot(request: Request):
    db, owner = await signed_personal_action(request, "PERSONAL_BOT_TEST")
    try:
        result = send_personal_test(db, owner)
        if result is None:
            raise HTTPException(409, "personal bot is not enabled and bound")
        if not result:
            raise HTTPException(502, "Telegram notification failed")
        return {"status": "test_sent"}
    finally:
        db.close()


@app.post("/v1/personal-bots/disable")
async def disable_personal_bot(request: Request):
    db, owner = await signed_personal_action(request, "PERSONAL_BOT_DISABLE")
    try:
        changed = PersonalBotVault(VAULT_KEY).disable(db, owner) if VAULT_KEY else False
        db.commit()
        return {"status": "disabled" if changed else "not_configured"}
    finally:
        db.close()


@app.post("/v1/personal-bots/remove")
async def remove_personal_bot(request: Request):
    db, owner = await signed_personal_action(request, "PERSONAL_BOT_REMOVE")
    try:
        removed_bot = PersonalBotVault(VAULT_KEY).remove(db, owner) if VAULT_KEY else False
        removed_enrollment = EnrollmentStore().remove_for_owner(db, owner)
        db.commit()
        return {"status": "removed" if removed_bot or removed_enrollment else "not_configured"}
    finally:
        db.close()


@app.post("/v1/telegram/personal-webhook")
async def personal_webhook(request: Request, x_telegram_bot_api_secret_token: str = Header(default="")):
    with connect_db() as db:
        if not EnrollmentStore().has_webhook_secret(db, x_telegram_bot_api_secret_token):
            raise HTTPException(403, "invalid enrollment webhook")
    try:
        update = await request.json()
        message = update.get("message", {})
        chat_id = message.get("chat", {}).get("id")
        command = message.get("text", "")
        if chat_id is None or not isinstance(command, str):
            return {"status": "ignored"}
    except (json.JSONDecodeError, AttributeError):
        raise HTTPException(400, "invalid Telegram update")
    with connect_db() as db:
        owner = EnrollmentStore().bind_from_webhook(db, x_telegram_bot_api_secret_token, str(chat_id), command)
        if not owner:
            raise HTTPException(403, "invalid enrollment webhook")
        db.commit()
    return {"status": "bound"}


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
