import os
import hashlib
import json
import uuid
import time
from datetime import datetime
from fastapi import APIRouter, HTTPException
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from typing import Optional
from nacl.public import PrivateKey
from nacl.encoding import Base64Encoder
import asyncio

# ``core`` imports this router while it is initializing.  Define it before
# importing runtime state so package imports resolve that intentional cycle.
router = APIRouter()

if __package__:
    from .core import state
    from .database import DatabaseManager
    from .crypto import CryptoManager
else:  # Runtime launcher imports backend modules from its working directory.
    from core import state
    from database import DatabaseManager
    from crypto import CryptoManager
from fastapi.concurrency import run_in_threadpool
# Добавьте в начало
import base64
if __package__:
    from .dsp import AudioProcessor
else:
    from dsp import AudioProcessor

# This HTTP endpoint predates the DMP-C Device transport.  It must not retain
# or route a message when a legacy client attempts to use it: doing so could
# silently revive the raw persistence path instead of requiring DMP-C.
LEGACY_SEND_UNAVAILABLE_DETAIL = (
    "Legacy send endpoint unavailable; DMP-C and mesh routing are not attempted."
)

# --- Pydantic Models ---
class LoginData(BaseModel):
    username: str
    password: str
class ConnectData(BaseModel):
    address: str
class SendData(BaseModel):
    target_id: str
    text: str = "" # Делаем опциональным или пустым по умолчанию
    msg_type: str = "TEXT" # "TEXT", "PCP", "GVP"
    file_data: Optional[str] = None # Base64 для GVP
class RenameData(BaseModel):
    target_id: str
    name: Optional[str] = None
class ReadChatData(BaseModel):
    chat_id: str
class RouteIdRequest(BaseModel):
    sender_id: str
    receiver_id: str

# --- API ROUTES ---

@router.get("/")
async def root():
    return RedirectResponse(url="/auth/login.html")

# --- DEBUG ЭНДПОИНТЫ (BLIND STORAGE AWARE) ---

@router.get("/api/debug/packet/{pkt_id}")
async def debug_packet_status(pkt_id: str):
    """Проверяет статус пакета (используя Blind Hash)"""
    if not state.system_db or not state.node_crypto: return {"status": "offline"}
    
    # Хешируем ID, так как в БД лежат только хеши
    pkt_hash = state.node_crypto.get_blind_hash(pkt_id)
    
    async with state.system_db.conn.execute("SELECT received_at FROM seen_packets WHERE packet_hash = ?", (pkt_hash,)) as cursor:
        seen = await cursor.fetchone()
        
    # В outbox packet_id лежит в открытом виде (в JSON), но колонка packet_id может быть null или хешем в будущих версиях.
    # В текущей схеме outbox.packet_id - это TEXT.
    async with state.system_db.conn.execute("SELECT count(*) as cnt FROM outbox WHERE packet_id = ?", (pkt_id,)) as cursor:
        outbox = await cursor.fetchone()
        
    return {
        "seen": bool(seen), 
        "received_at": seen['received_at'] if seen else None, 
        "in_outbox": outbox['cnt'] if outbox else 0,
        "blind_hash": pkt_hash
    }

@router.get("/api/debug/outbox")
async def debug_get_outbox():
    """Возвращает текущую очередь отправки (Blind Hashes)"""
    if not state.system_db: return []
    async with state.system_db.conn.execute("SELECT id, packet_id, next_hop_hash, exclude_peer_hash, created_at FROM outbox") as cursor:
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

@router.get("/api/debug/routes")
async def debug_get_routes():
    """Возвращает таблицу слепой маршрутизации (Encrypted Blobs)"""
    if not state.system_db: return []
    # Мы не можем расшифровать ключи (хеши), но можем показать, что данные зашифрованы
    async with state.system_db.conn.execute("SELECT route_in_hash, expires_at FROM blind_routes WHERE expires_at > ?", (time.time(),)) as cursor:
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

@router.post("/api/debug/get_route_ids")
async def debug_get_route_ids(data: RouteIdRequest):
    """Хелпер для тестов: вычисляет хеши маршрутов"""
    if not state.crypto: return {}
    return {
        "route_fwd": state.crypto.get_route_id(data.sender_id, data.receiver_id),
        "route_bwd": state.crypto.get_route_id(data.receiver_id, data.sender_id)
    }

# --- ОСНОВНЫЕ ЭНДПОИНТЫ ---

@router.post("/api/login")
async def login(data: LoginData):
    # 1. Генерация ключей
    crypto = CryptoManager()
    crypto.derive_keys_from_password(data.username, data.password)
    new_user_id = crypto.my_id
    
    # 2. Разлогин, если нужно
    if state.is_logged_in and state.user_id != new_user_id:
        state.node.remove_active_user()
        if state.db: await state.db.close()
        state.is_logged_in = False
        state.user_id = ""
        state.crypto = None
        state.db = None
    
    if not state.is_logged_in:
        # 3. Подготовка состояний
        await state.system_db.register_local_user(new_user_id)
        
        state.user_id = new_user_id
        state.crypto = crypto
        
        filename_hash = hashlib.sha256(f"filename_salt_v1_{new_user_id}".encode()).hexdigest()
        state.db = DatabaseManager(f"storage_{filename_hash}.db")
        state.db.set_crypto(crypto)
        await state.db.connect()
        
        # 4. Активация ноды и установка флага
        state.node.set_active_user(new_user_id, state.db, crypto)
        state.is_logged_in = True # <-- ПРАВИЛЬНОЕ МЕСТО!

        # 5. ЗАПУСК ФОНОВЫХ ЗАДАЧ (Теперь все безопасно)
        # Состояние уже полностью готово к работе.
        
        # 5.1 Разбор оффлайн почты
        asyncio.create_task(state.system_db.process_mailbox(state.node._deliver_to_active_user))

        # 5.2 Миграция тегов (если нужно)
        try:
            async with state.db.conn.execute("SELECT user_id FROM contacts WHERE delivery_tag IS NULL") as cursor:
                rows = await cursor.fetchall()
            if rows:
                print(f"🔧 [LOGIN] Updating delivery tags for {len(rows)} contacts...")
                for row in rows:
                    uid = row['user_id']
                    tag = state.crypto.get_delivery_tag(uid)
                    await state.db.update_contact_tag(uid, tag)
        except Exception as e:
            print(f"⚠️ Maintenance warning: {e}")

    return {"status": "ok", "user_id": new_user_id}

@router.post("/api/logout")
async def logout():
    if state.is_logged_in:
        state.node.remove_active_user()
        if state.db: await state.db.close()
        state.db = None
        state.user_id = ""
        state.crypto = None
        state.is_logged_in = False
    return {"status": "ok"}

@router.post("/api/connect")
async def connect_peer(data: ConnectData):
    if not state.node: raise HTTPException(400, "Node not ready")
    res = await state.node.connect_to(data.address)
    return {"success": res}

@router.post("/api/send")
async def send_message(data: SendData):
    # Fail before inspecting state or constructing a packet.  In particular,
    # do not write legacy message/contact rows or enqueue a probe fallback.
    raise HTTPException(status_code=410, detail=LEGACY_SEND_UNAVAILABLE_DETAIL)

    if not state.db: raise HTTPException(400)
    
    pkt_uuid = str(uuid.uuid4())
    p_type = "DATA"
    status = "sent"
    
    # --- ЛОГИКА ФОРМИРОВАНИЯ ПАКЕТА ---
    
    if data.msg_type == "TEXT":
        # СТАНДАРТНЫЙ E2EE
        try: 
            enc_net = state.crypto.encrypt_message(data.target_id, data.text)
        except Exception as e: 
            raise HTTPException(400, "Encryption Fail")
        
        # Локально сохраняем текст
        enc_local = state.crypto.encrypt_db_field(data.text)
        content_to_send = enc_net # Это строка (JSON stringified inside Base64 inside encrypt)

    elif data.msg_type == "PCP":
        # 1. Шифруем текст (T-Ratchet)
        cipher_b64 = state.crypto.encrypt_pcp_payload(data.target_id, data.text)
        
        # 2. Генерируем ЧЕСТНЫЙ MFSK звук из ЗАШИФРОВАННОГО текста
        # (Мы передаем в звук именно шифротекст, чтобы в эфире был хаос)
        # Или можно передавать открытый текст в звук для теста, но правильнее шифрованный.
        # Давай для наглядности передадим в звук исходный текст (чтобы ты мог его декодировать своим скриптом pcp.py)
        # А в JSON положим шифрованный для автоматики.
        
        real_audio_wav = await run_in_threadpool(
            AudioProcessor.generate_pcp_audio,
            data.text
        )
        audio_b64 = base64.b64encode(real_audio_wav).decode('utf-8')
        
        pcp_packet = {
            "sim_type": "PCP",
            "ciphertext": cipher_b64,
            "audio_preview": audio_b64 
        }
        content_to_send = json.dumps(pcp_packet)
        enc_local = state.crypto.encrypt_db_field(f"[PCP] {data.text}")

    elif data.msg_type == "GVP":
        # GHOST VOICE PROTOCOL
        if not data.file_data: raise HTTPException(400, "No file for GVP")
        
        # 1. Декодируем входящий файл
        try:
            # data.file_data приходит как "data:audio/wav;base64,....."
            header, encoded = data.file_data.split(",", 1)
            raw_audio = base64.b64decode(encoded)
        except:
            raw_audio = base64.b64decode(data.file_data)

        # 2. Генерируем Соль и Ключ
        salt = os.urandom(16).hex()
        base_key = state.crypto.get_offline_key(data.target_id, 0)
        session_key = state.crypto.get_gvp_session_key(base_key, salt)
        
        loop = asyncio.get_running_loop()
        
        # Функция для запуска в процессе (обертка, чтобы передать аргументы)
        # AudioProcessor.scramble_audio - это staticmethod, он пиклится (picklable), все ок.
        scrambled_wav = await loop.run_in_executor(
            state.process_pool,  # Наш пул процессов
            AudioProcessor.scramble_audio, # Функция
            raw_audio,      # Аргумент 1
            session_key,    # Аргумент 2
            True            # Аргумент 3 (is_encrypt)
        )
        scrambled_b64 = base64.b64encode(scrambled_wav).decode('utf-8')
        
        # 4. Пакуем: Соль (открыто) + Скремблированный блоб
        gvp_packet = {
            "sim_type": "GVP",
            "salt": salt,
            "blob": scrambled_b64
        }
        content_to_send = json.dumps(gvp_packet)
        
        # Локально сохраняем маркер
        enc_local = state.crypto.encrypt_db_field("[GVP Audio Sent]")

    else:
        raise HTTPException(400, "Unknown Type")

    # --- ДАЛЕЕ СТАНДАРТНАЯ ЛОГИКА СОХРАНЕНИЯ И ОТПРАВКИ ---
    
    contact_tag = state.crypto.get_delivery_tag(data.target_id)
    
    await state.db.conn.execute("""
        INSERT INTO contacts (user_id, last_seen, delivery_tag) 
        VALUES (?, ?, ?) 
        ON CONFLICT(user_id) DO UPDATE SET last_seen=excluded.last_seen, delivery_tag=excluded.delivery_tag
    """, (data.target_id, datetime.now().isoformat(), contact_tag))

    await state.db.conn.execute("""
        INSERT INTO messages (packet_id, chat_id, sender_id, content, timestamp, is_outgoing, is_read) 
        VALUES (?, ?, ?, ?, ?, 1, 1)
    """, (pkt_uuid, data.target_id, state.user_id, enc_local, datetime.now().isoformat()))
    
    await state.db.conn.commit()

    # Маршрутизация (без изменений)
    route_id = state.crypto.get_route_id(state.user_id, data.target_id)
    rev_id = state.crypto.get_route_id(data.target_id, state.user_id)
    route = await state.system_db.get_best_route(route_id)

    if route and not route['is_local']:
        packet = {"type": "DATA", "id": pkt_uuid, "route_id": route_id, "content": content_to_send, "ttl": 20}
        await state.system_db.mark_packet_seen(pkt_uuid)
        next_hop = route['next_hop_id']
        nh_hash = state.node_crypto.get_blind_hash(next_hop)
        await state.system_db.conn.execute("INSERT INTO outbox (packet_id, next_hop_hash, packet_json, exclude_peer_hash) VALUES (?, ?, ?, NULL)", (pkt_uuid, nh_hash, json.dumps(packet)))
        p_type, status = "DATA", "sent"
    else:
        # PROBE logic (без изменений, просто передаем content_to_send)
        await state.system_db.add_route(rev_id, "LOCAL", 0, is_local=True, remote_user_id=data.target_id)
        sig = state.crypto.sign_data(state.user_id + data.target_id)
        auth = state.crypto.encrypt_for_probe(data.target_id, json.dumps({"sid": state.user_id}))
        probe = {
            "type": "PROBE", "id": pkt_uuid, "route_id": route_id, "rev_id": rev_id, 
            "target_hash": state.crypto.get_target_hash(data.target_id), "auth": auth, "sig": sig, 
            "content": content_to_send, "metric": 0, "ttl": 20
        }
        await state.system_db.mark_packet_seen(pkt_uuid)
        await state.system_db.conn.execute("INSERT INTO outbox (packet_id, next_hop_hash, packet_json, exclude_peer_hash) VALUES (?, NULL, ?, NULL)", (pkt_uuid, json.dumps(probe)))
        p_type, status = "PROBE", "finding_route"

    await state.system_db.conn.commit()
    return {"status": status, "packet_id": pkt_uuid, "packet_type": p_type}

@router.get("/api/state")
async def get_state():
    if not state.node: return {"status": "offline"}
    return {
        "user_id": state.user_id if state.is_logged_in else "OFFLINE", 
        "peers": list(state.node.active_connections.keys())
    }

@router.get("/api/peers")
async def get_contacts():
    if not state.db: return []
    async with state.db.conn.execute("""
        SELECT c.user_id, c.nickname, 
        (SELECT COUNT(id) FROM messages WHERE chat_id = c.user_id AND is_read = 0 AND is_outgoing = 0) as unread_count 
        FROM contacts c
    """) as cursor:
        rows = await cursor.fetchall()
    res = []
    for r in rows:
        d = dict(r)
        if d['nickname']: d['nickname'] = state.crypto.decrypt_db_field(d['nickname'])
        res.append(d)
    return res

@router.get("/api/messages/{chat_id}")
async def get_chat_history(chat_id: str):
    if not state.db: return []
    async with state.db.conn.execute("SELECT * FROM messages WHERE chat_id = ? ORDER BY timestamp ASC", (chat_id,)) as cursor:
        rows = await cursor.fetchall()
    res = []
    for r in rows:
        d = dict(r)
        d['content'] = state.crypto.decrypt_db_field(d['content'])
        res.append(d)
    await state.db.conn.execute("UPDATE messages SET is_read = 1 WHERE chat_id = ? AND is_outgoing = 0", (chat_id,))
    await state.db.conn.commit()
    return res

@router.post("/api/rename")
async def rename_peer(data: RenameData):
    if not state.db: raise HTTPException(400)
    enc_name = state.crypto.encrypt_db_field(data.name) if data.name else None
    await state.db.conn.execute("""
        INSERT INTO contacts (user_id, nickname, last_seen) VALUES (?, ?, ?) 
        ON CONFLICT(user_id) DO UPDATE SET nickname=excluded.nickname
    """, (data.target_id, enc_name, datetime.now().isoformat()))
    await state.db.conn.commit()
    return {"status": "ok"}

@router.post("/api/read_chat")
async def mark_chat_as_read(data: ReadChatData):
    if not state.db: raise HTTPException(400)
    await state.db.conn.execute("UPDATE messages SET is_read = 1 WHERE chat_id = ? AND is_outgoing = 0", (data.chat_id,))
    await state.db.conn.commit()
    return {"status": "ok"}
