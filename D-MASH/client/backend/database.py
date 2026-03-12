import aiosqlite
import time
import json
from datetime import datetime
from typing import Optional, List, Dict, Any

class DatabaseManager:
    """
    Менеджер базы данных с поддержкой архитектуры Blind Storage.
    
    Разделяет логику на два слоя:
    1. System DB (Daemon): Использует NodeCryptoManager для 'ослепления' индексов и метаданных.
    2. User DB (Client): Использует CryptoManager для хранения истории сообщений.
    """
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.conn = None
        self.crypto = None       # User Layer (CryptoManager)
        self.node_crypto = None  # Daemon Layer (NodeCryptoManager)

    def set_crypto(self, crypto_manager):
        """Установка криптографии пользователя (для чтения переписки)"""
        self.crypto = crypto_manager

    def set_node_crypto(self, node_crypto_manager):
        """Установка криптографии ноды (для маршрутизации и соседей)"""
        self.node_crypto = node_crypto_manager

    async def connect(self):
        self.conn = await aiosqlite.connect(self.db_path)
        self.conn.row_factory = aiosqlite.Row
        await self._init_tables()

    async def _init_tables(self):
# --- ТАБЛИЦЫ ПОЛЬЗОВАТЕЛЯ (User DB) ---
        
        # Обновленная таблица messages (без изменений, просто для контекста)
        await self.conn.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                packet_id TEXT UNIQUE, 
                chat_id TEXT,
                sender_id TEXT,
                content TEXT, 
                timestamp TEXT,
                is_outgoing INTEGER,
                is_read INTEGER DEFAULT 0
            )
        """)
        
        # ! ИЗМЕНЕНИЕ ЗДЕСЬ !
        # Добавляем delivery_tag и Индекс для мгновенного поиска
        await self.conn.execute("""
            CREATE TABLE IF NOT EXISTS contacts (
                user_id TEXT PRIMARY KEY,
                nickname TEXT,
                last_seen TEXT,
                delivery_tag TEXT
            )
        """)
        
        # Создаем индекс для O(1) поиска в network.py
        await self.conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_delivery_tag ON contacts(delivery_tag)
        """)

        # --- ТАБЛИЦЫ ДЕМОНА (System DB - Blind Storage) ---
        
        # 1. peer_directory (Вместо neighbors)
        await self.conn.execute("""
            CREATE TABLE IF NOT EXISTS peer_directory (
                alias_hash TEXT PRIMARY KEY,
                secured_blob TEXT
            )
        """)
        
        # 2. blind_routes (Вместо routing_table)
        await self.conn.execute("""
            CREATE TABLE IF NOT EXISTS blind_routes (
                route_in_hash TEXT PRIMARY KEY,
                routing_blob TEXT,
                expires_at REAL
            )
        """)

        # 3. local_bindings (Вместо local_users)
        await self.conn.execute("""
            CREATE TABLE IF NOT EXISTS local_bindings (
                binding_hash TEXT PRIMARY KEY,
                user_blob TEXT
            )
        """)

        # 4. Outbox (Очередь отправки)
        await self.conn.execute("""
            CREATE TABLE IF NOT EXISTS outbox (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                packet_id TEXT,
                next_hop_hash TEXT, 
                packet_json TEXT,
                exclude_peer_hash TEXT, 
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # 5. Seen Packets (Дедупликация)
        await self.conn.execute("""
            CREATE TABLE IF NOT EXISTS seen_packets (
                packet_hash TEXT PRIMARY KEY,
                received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # 6. Offline Mailbox
        await self.conn.execute("""
            CREATE TABLE IF NOT EXISTS offline_mailbox (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_hash TEXT,
                packet_json TEXT,
                received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        await self.conn.commit()

    async def close(self):
        if self.conn:
            await self.conn.close()

    # --- МЕТОДЫ СИСТЕМЫ (BLIND LOGIC) ---

    async def mark_packet_seen(self, packet_id: str) -> bool:
        if not self.node_crypto: return False 
        pkt_hash = self.node_crypto.get_blind_hash(packet_id)
        try:
            await self.conn.execute("INSERT INTO seen_packets (packet_hash) VALUES (?)", (pkt_hash,))
            await self.conn.commit()
            return True
        except aiosqlite.IntegrityError:
            return False

    # --- УПРАВЛЕНИЕ СОСЕДЯМИ (PEER DIRECTORY) ---
    async def update_contact_tag(self, user_id: str, tag: str):
        """Обновляет тег доставки для контакта"""
        await self.conn.execute("UPDATE contacts SET delivery_tag = ? WHERE user_id = ?", (tag, user_id))
        await self.conn.commit()

    async def add_neighbor(self, node_id: str, address: str):
        if not self.node_crypto: return

        alias_hash = self.node_crypto.get_blind_hash(node_id)
        data = {
            "real_node_id": node_id,
            "address": address,
            "last_seen": datetime.now().isoformat()
        }
        blob = self.node_crypto.encrypt_for_self(data)
        
        await self.conn.execute("""
            INSERT OR REPLACE INTO peer_directory (alias_hash, secured_blob) VALUES (?, ?)
        """, (alias_hash, blob))
        await self.conn.commit()

    async def get_all_neighbors(self) -> List[Dict]:
        if not self.node_crypto: return []
        async with self.conn.execute("SELECT secured_blob FROM peer_directory") as cursor:
            rows = await cursor.fetchall()
        neighbors = []
        for row in rows:
            data = self.node_crypto.decrypt_from_self(row['secured_blob'])
            if data: neighbors.append(data)
        return neighbors

    # --- МАРШРУТИЗАЦИЯ (BLIND ROUTES) ---

    # ИСПРАВЛЕНИЕ: Добавлен аргумент remote_user_id
    async def add_route(self, route_id: str, next_hop_id: str, metric: int, prev_hop_id: str = None, is_local: bool = False, remote_user_id: str = None):
        """
        Добавляет маршрут.
        remote_user_id нужен, если is_local=True (чтобы знать, какому юзеру отдать пакет).
        """
        if not self.node_crypto: return

        route_hash = self.node_crypto.get_blind_hash(route_id)
        
        # 1. Пытаемся загрузить существующий маршрут
        current_data = {
            "candidates": [], 
            "prev_hop": prev_hop_id, 
            "is_local": is_local,
            "remote_user_id": remote_user_id
        }
        
        async with self.conn.execute("SELECT routing_blob FROM blind_routes WHERE route_in_hash = ?", (route_hash,)) as cursor:
            row = await cursor.fetchone()
            if row:
                decrypted = self.node_crypto.decrypt_from_self(row['routing_blob'])
                if decrypted: 
                    current_data = decrypted
                    # Обновляем поля, если они переданы
                    if prev_hop_id: current_data["prev_hop"] = prev_hop_id
                    if is_local: current_data["is_local"] = True
                    if remote_user_id: current_data["remote_user_id"] = remote_user_id

        # 2. Обновляем список кандидатов
        candidates = current_data.get("candidates", [])
        candidates = [c for c in candidates if c['next_hop'] != next_hop_id]
        candidates.append({"next_hop": next_hop_id, "metric": metric})
        candidates.sort(key=lambda x: x['metric'])
        
        current_data["candidates"] = candidates[:3]

        # 3. Шифруем и сохраняем
        blob = self.node_crypto.encrypt_for_self(current_data)
        expires = time.time() + 1800 
        
        await self.conn.execute("""
            INSERT OR REPLACE INTO blind_routes (route_in_hash, routing_blob, expires_at)
            VALUES (?, ?, ?)
        """, (route_hash, blob, expires))
        await self.conn.commit()

    async def get_best_route(self, route_id: str) -> Optional[Dict]:
        """
        Возвращает лучший маршрут.
        """
        if not self.node_crypto: return None

        route_hash = self.node_crypto.get_blind_hash(route_id)
        
        async with self.conn.execute("""
            SELECT routing_blob FROM blind_routes 
            WHERE route_in_hash = ? AND expires_at > ?
        """, (route_hash, time.time())) as cursor:
            row = await cursor.fetchone()
        
        if not row: return None
        
        data = self.node_crypto.decrypt_from_self(row['routing_blob'])
        if not data or not data.get('candidates'): return None
        
        best = data['candidates'][0]
        return {
            "next_hop_id": best['next_hop'],
            "metric": best['metric'],
            "is_local": data.get('is_local', False),
            "prev_hop_id": data.get('prev_hop'),
            "remote_user_id": data.get('remote_user_id') # ИСПРАВЛЕНИЕ: Возвращаем ID юзера
        }

    # --- ЛОКАЛЬНЫЕ ПРИВЯЗКИ (LOCAL BINDINGS) ---

    async def register_local_user(self, user_id: str):
        if not self.node_crypto: return
        binding_hash = self.node_crypto.get_blind_hash(user_id)
        blob = self.node_crypto.encrypt_for_self({"local_user_id": user_id})
        await self.conn.execute("""
            INSERT OR REPLACE INTO local_bindings (binding_hash, user_blob) VALUES (?, ?)
        """, (binding_hash, blob))
        await self.conn.commit()

    async def is_local_user(self, user_id: str) -> bool:
        if not self.node_crypto: return False
        binding_hash = self.node_crypto.get_blind_hash(user_id)
        async with self.conn.execute("SELECT 1 FROM local_bindings WHERE binding_hash = ?", (binding_hash,)) as cursor:
            return await cursor.fetchone() is not None

    # --- OFFLINE MAILBOX ---

# ВНУТРИ class DatabaseManager:

    async def save_to_mailbox(self, packet_json: str):
        """
        Сохраняет недоставленный пакет в общий ящик.
        """
        # Просто сохраняем пакет как есть. Разберемся при логине.
        await self.conn.execute(
            "INSERT INTO offline_mailbox (packet_json) VALUES (?)", 
            (packet_json,)
        )
        await self.conn.commit()

    async def process_mailbox(self, delivery_callback):
        """
        Перебирает ящик и пытается доставить сообщения, используя переданную функцию (callback).
        Если callback возвращает True (успех), сообщение удаляется.
        """
        async with self.conn.execute("SELECT id, packet_json FROM offline_mailbox") as cursor:
            rows = await cursor.fetchall()
            
        if not rows: return
        
        print(f"📬 [MAILBOX] Processing {len(rows)} stored packets...")
        
        ids_to_delete = []
        for row in rows:
            pkt_json = row['packet_json']
            try:
                packet = json.loads(pkt_json)
                # ВАЖНО: вызываем с await и hint=None
                is_delivered = await delivery_callback(packet, sender_id_hint=None)
                
                if is_delivered:
                    ids_to_delete.append(row['id'])
            except Exception as e:
                print(f"Mailbox process error: {e}")

        # Удаляем только те, что успешно расшифровались
        if ids_to_delete:
            await self.conn.execute(
                f"DELETE FROM offline_mailbox WHERE id IN ({','.join(['?']*len(ids_to_delete))})",
                ids_to_delete
            )
            await self.conn.commit()
            print(f"🗑️ [MAILBOX] Cleaned up {len(ids_to_delete)} delivered packets.")

    async def get_local_user_ids(self) -> list:
        """
        Возвращает список ID всех пользователей, зарегистрированных на этой ноде.
        Демон использует это, чтобы понять, предназначен ли ему PROBE.
        """
        if not self.node_crypto: return []
        
        async with self.conn.execute("SELECT user_blob FROM local_bindings") as cursor:
            rows = await cursor.fetchall()
            
        user_ids = []
        for row in rows:
            decrypted = self.node_crypto.decrypt_from_self(row['user_blob'])
            if decrypted and 'local_user_id' in decrypted:
                user_ids.append(decrypted['local_user_id'])
        return user_ids
        
    async def fetch_mailbox(self, user_id: str):
        if not self.node_crypto: return []
        target_hash = self.node_crypto.get_blind_hash(user_id)
        async with self.conn.execute("SELECT id, packet_json FROM offline_mailbox WHERE target_hash = ?", (target_hash,)) as cursor:
            rows = await cursor.fetchall()
        if rows:
            ids = [row['id'] for row in rows]
            await self.conn.execute(f"DELETE FROM offline_mailbox WHERE id IN ({','.join(['?']*len(ids))})", ids)
            await self.conn.commit()
        return [row['packet_json'] for row in rows]
