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
from nacl.encoding import HexEncoder
from nacl.public import PrivateKey, SealedBox
from nacl import secret

from fastapi import FastAPI, Header, HTTPException, Request
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from personal_bot_enrollment import EnrollmentStore
from personal_bot_vault import PersonalBotVault

DB_PATH = Path(os.getenv("NOTIFICATION_DB_PATH", "/var/lib/dmash-notify/notifications.db"))
TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
ORIGIN_PRIVATE_KEY_HEX = os.getenv("DMASH_NOTIFICATION_ORIGIN_PRIVATE_KEY", "")
AUTHORIZED_NODE_KEYS = frozenset(key.strip().lower() for key in os.getenv("DMASH_NOTIFICATION_NODE_KEYS", "").split(",") if key.strip())
VAULT_KEY = os.getenv("NOTIFICATION_VAULT_KEY", "")
PERSONAL_WEBHOOK_URL = os.getenv("PERSONAL_BOT_WEBHOOK_URL", "")
TELEGRAM_WEBHOOK_SECRET = os.getenv("TELEGRAM_WEBHOOK_SECRET", "")
MESSAGE = "У вас новое сообщение в D-MASH"
BEACON_CONNECTED_MESSAGE = "✅ Маяк подключен."
BEACON_ALREADY_MESSAGE = "ℹ️ Маяк уже настроен."
BEACON_STOPPED_MESSAGE = "✅ Маяк отключен."
PWA_URL = "https://messenger.d-mash.ru/not_messenger/index.html"
NOTIFICATION_LABELS = {
    "MALYAVA": "✉️ МАЛЯВА",
    "INCOMING_BAZAR": "📞 ВХОДЯЩИЙ БАЗАР",
}

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


def chat_id_for_binding(value: str) -> str:
    """Read encrypted chat IDs; plaintext exists only for pre-migration rows."""
    try:
        return decrypt_chat_id(value)
    except Exception:
        return value


def migrate_binding_chat_ids(db: sqlite3.Connection) -> None:
    """Encrypt legacy binding rows in-place when the vault is configured."""
    if not VAULT_KEY:
        return
    for row in db.execute("SELECT handle_hash, chat_id FROM bindings").fetchall():
        try:
            decrypt_chat_id(row[1])
        except Exception:
            db.execute("UPDATE bindings SET chat_id=? WHERE handle_hash=?", (encrypt_chat_id(row[1]), row[0]))


def handle_hash(handle: str) -> str:
    if not VAULT_KEY:
        raise ValueError("notification vault key is required")
    key = base64.urlsafe_b64decode(VAULT_KEY.encode("ascii"))
    return hmac.new(key, b"dmash-notify-blind-v1:" + handle.encode(), hashlib.sha256).hexdigest()


def valid_beacon_handle(handle: str) -> bool:
    return isinstance(handle, str) and 32 <= len(handle) <= 256 and all(c.isalnum() or c in "-_" for c in handle)


def encrypt_chat_id(chat_id: str) -> str:
    key = base64.urlsafe_b64decode(VAULT_KEY.encode("ascii"))
    return base64.urlsafe_b64encode(secret.SecretBox(key).encrypt(str(chat_id).encode())).decode("ascii")


def decrypt_chat_id(ciphertext: str) -> str:
    key = base64.urlsafe_b64decode(VAULT_KEY.encode("ascii"))
    return secret.SecretBox(key).decrypt(base64.urlsafe_b64decode(ciphertext.encode())).decode()


def decrypt_node_request(body: bytes) -> dict:
    """Verify a configured node signature before decrypting its sealed payload."""
    if not ORIGIN_PRIVATE_KEY_HEX or not AUTHORIZED_NODE_KEYS:
        raise HTTPException(503, "notification service not configured")
    try:
        envelope = json.loads(body)
        node_id, ciphertext, signature = envelope["node_id"].lower(), envelope["ciphertext"], envelope["signature"]
        if envelope["version"] != 1 or node_id not in AUTHORIZED_NODE_KEYS:
            raise ValueError
        VerifyKey(node_id, encoder=HexEncoder).verify(
            f"DMP-ORIGIN-NOTIFY|1|{node_id}|{ciphertext}".encode(), base64.b64decode(signature, validate=True),
        )
        private_key = PrivateKey(ORIGIN_PRIVATE_KEY_HEX, encoder=HexEncoder)
        plaintext = SealedBox(private_key).decrypt(base64.b64decode(ciphertext, validate=True))
        payload = json.loads(plaintext)
        if not isinstance(payload, dict): raise ValueError
        return payload
    except Exception:
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


def telegram_send(chat_id: str, event_type: str) -> bool:
    if not TOKEN:
        raise HTTPException(503, "telegram integration not configured")
    label = NOTIFICATION_LABELS.get(event_type)
    if not label:
        raise ValueError("invalid notification event")
    # The alert intentionally contains neither content nor identifiers. The
    # sole visible text is a single HTML anchor to the public PWA.
    return bool(telegram_call(TOKEN, "sendMessage", {
        "chat_id": chat_id,
        "text": f'<a href="{PWA_URL}">{label}</a>',
        "parse_mode": "HTML",
        "disable_web_page_preview": "true",
    }))


def personal_delivery_target(db: sqlite3.Connection, owner: str) -> tuple[str, str] | None:
    """Resolve a user's own encrypted bot and bound chat only inside Origin.

    The return value is deliberately local to this process. It is never sent to
    a D-MASH node, included in a mesh packet, or returned by an HTTP response.
    """
    if not VAULT_KEY:
        return None
    chat_id = EnrollmentStore().chat_id_for_owner(db, owner, VAULT_KEY)
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
    return {"status": "ok", "telegram_configured": bool(TOKEN), "node_auth_configured": bool(ORIGIN_PRIVATE_KEY_HEX and AUTHORIZED_NODE_KEYS), "personal_bot_enrollment_configured": bool(VAULT_KEY and PERSONAL_WEBHOOK_URL.startswith("https://"))}


@app.post("/v1/beacon/remove")
async def remove_beacon(request: Request):
    try:
        payload = await request.json()
    except json.JSONDecodeError:
        raise HTTPException(400, "invalid JSON")
    if not isinstance(payload, dict):
        raise HTTPException(400, "invalid request")
    db = connect_db()
    try:
        verify_personal_request(db, payload, "BEACON_REMOVE")
        handle = payload.get("beacon_handle")
        if not valid_beacon_handle(handle):
            raise HTTPException(400, "invalid beacon handle")
        removed = db.execute("DELETE FROM bindings WHERE handle_hash=?", (handle_hash(handle),)).rowcount == 1
        db.commit()
        return {"status": "removed" if removed else "not_configured"}
    finally:
        db.close()


@app.post("/v1/telegram/webhook")
async def telegram_beacon_webhook(request: Request, x_telegram_bot_api_secret_token: str = Header(default="")):
    if not TELEGRAM_WEBHOOK_SECRET or not hmac.compare_digest(x_telegram_bot_api_secret_token, TELEGRAM_WEBHOOK_SECRET):
        raise HTTPException(403, "invalid Telegram webhook")
    try:
        message = (await request.json()).get("message", {})
        chat_id, command = message.get("chat", {}).get("id"), message.get("text", "")
    except (AttributeError, json.JSONDecodeError):
        raise HTTPException(400, "invalid Telegram update")
    if chat_id is None or not isinstance(command, str):
        return {"status": "ignored"}
    with connect_db() as db:
        migrate_binding_chat_ids(db)
        if command.startswith("/start "):
            handle = command.removeprefix("/start ").strip()
            if not valid_beacon_handle(handle):
                return {"status": "ignored"}
            key = handle_hash(handle)
            existing = db.execute("SELECT chat_id FROM bindings WHERE handle_hash=?", (key,)).fetchone()
            db.execute("INSERT OR REPLACE INTO bindings (handle_hash, chat_id, enabled) VALUES (?, ?, 1)", (key, encrypt_chat_id(str(chat_id))))
            db.commit()
            telegram_call(TOKEN, "sendMessage", {"chat_id": str(chat_id), "text": BEACON_ALREADY_MESSAGE if existing else BEACON_CONNECTED_MESSAGE})
            return {"status": "already_bound" if existing else "bound"}
        if command.strip() == "/stop":
            removed = False
            for key, stored_chat in db.execute("SELECT handle_hash, chat_id FROM bindings").fetchall():
                if hmac.compare_digest(chat_id_for_binding(stored_chat), str(chat_id)):
                    db.execute("DELETE FROM bindings WHERE handle_hash=?", (key,)); removed = True
            db.commit()
            if removed: telegram_call(TOKEN, "sendMessage", {"chat_id": str(chat_id), "text": BEACON_STOPPED_MESSAGE})
            return {"status": "stopped" if removed else "not_configured"}
    return {"status": "ignored"}


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
        migrate_binding_chat_ids(db)
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
        stopped = EnrollmentStore().stop_from_webhook(db, x_telegram_bot_api_secret_token, str(chat_id), command, VAULT_KEY)
        if stopped:
            db.commit()
            telegram_call(TOKEN, "sendMessage", {"chat_id": str(chat_id), "text": BEACON_STOPPED_MESSAGE})
            return {"status": "stopped"}
        start_status = EnrollmentStore().status_for_start(db, x_telegram_bot_api_secret_token, command)
        if start_status == "already_bound":
            telegram_call(TOKEN, "sendMessage", {"chat_id": str(chat_id), "text": BEACON_ALREADY_MESSAGE})
            return {"status": "already_bound"}
        owner = EnrollmentStore().bind_from_webhook(db, x_telegram_bot_api_secret_token, str(chat_id), command, VAULT_KEY)
        if not owner:
            raise HTTPException(403, "invalid enrollment webhook")
        db.commit()
    # Confirm only after the one-time deep-link code was accepted and consumed.
    # The response intentionally does not echo the code, owner alias, chat ID,
    # or any notification handle back into Telegram.
    telegram_call(TOKEN, "sendMessage", {"chat_id": str(chat_id), "text": BEACON_CONNECTED_MESSAGE})
    return {"status": "bound"}


@app.post("/v1/notify")
async def notify(request: Request):
    body = await request.body()
    try:
        payload = decrypt_node_request(body)
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
        try:
            version = int(payload["version"])
            event_type = payload["event_type"]
            if version != 2 or not isinstance(event_type, str) or event_type not in NOTIFICATION_LABELS:
                raise ValueError
        except (KeyError, TypeError, ValueError):
            raise HTTPException(400, "invalid notification event")
        if not telegram_send(chat_id_for_binding(row[0]), event_type):
            raise HTTPException(502, "notification provider unavailable")
        db.execute("INSERT INTO delivered (idempotency_key, delivered_at, expires_at) VALUES (?, ?, ?)", (key, int(time.time()), expires_at))
        db.execute("DELETE FROM delivered WHERE expires_at < ?", (int(time.time()),))
        db.commit()
    return {"status": "notified"}
