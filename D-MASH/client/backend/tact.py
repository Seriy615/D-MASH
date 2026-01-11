import asyncio
import json
import random
import string
import time
from database import DatabaseManager
from network import P2PNode

class TactEngine:
    def __init__(self, db: DatabaseManager, node: P2PNode, interval: float, packet_size: int):
        self.db = db
        self.node = node
        self.interval = interval
        self.packet_size = packet_size
        self.running = False

    async def start(self):
        self.running = True
        print(f"⏱️ [TACT] Engine started. Tick: {self.interval}s")
        while self.running:
            start_time = time.time()
            await self._tick()
            elapsed = time.time() - start_time
            sleep_time = max(0.1, self.interval - elapsed)
            await asyncio.sleep(sleep_time)

    async def _tick(self):
        # 1. Получаем список активных соединений
        # active_connections хранит { real_peer_id: websocket }
        if not self.node.active_connections: return
        
        # 2. Создаем карту хешей для текущих соседей
        # Нам нужно сопоставить хеши из БД (Blind Storage) с реальными сокетами
        # active_hashes = { blind_hash: websocket }
        active_hashes = {}
        if self.db.node_crypto:
            for peer_id, ws in self.node.active_connections.items():
                h = self.db.node_crypto.get_blind_hash(peer_id)
                active_hashes[h] = ws
        else:
            # Если криптография не инициализирована, мы не можем маршрутизировать
            return

        # 3. Читаем очередь (Outbox)
        async with self.db.conn.execute("""
            SELECT id, next_hop_hash, packet_json, exclude_peer_hash 
            FROM outbox ORDER BY created_at ASC LIMIT 5
        """) as cursor:
            rows = await cursor.fetchall()

        # 4. Если очередь пуста - шлем DUMMY (Traffic Obfuscation)
        if not rows:
            dummy = self._create_envelope("", is_dummy=True)
            for ws in self.node.active_connections.values():
                try: await ws.send(dummy)
                except: pass
            return

        # 5. Обработка реальных пакетов
        for row in rows:
            msg_id = row['id']
            target_hash = row['next_hop_hash']
            exclude_hash = row['exclude_peer_hash']
            payload = row['packet_json']
            
            envelope = self._create_envelope(payload, is_dummy=False)
            
            if target_hash:
                # UNICAST: Шлем конкретному соседу, если он подключен
                ws = active_hashes.get(target_hash)
                if ws:
                    try: await ws.send(envelope)
                    except: pass
            else:
                # BROADCAST: Шлем всем, кроме исключенного (exclude_peer_hash)
                for h, ws in active_hashes.items():
                    if h == exclude_hash: continue 
                    try: await ws.send(envelope)
                    except: pass
            
            # Удаляем из очереди после попытки отправки
            await self.db.conn.execute("DELETE FROM outbox WHERE id = ?", (msg_id,))
            
        await self.db.conn.commit()
        
    def _create_envelope(self, payload_str: str, is_dummy: bool) -> str:
        msg_type = "DUMMY" if is_dummy else "REAL"
        envelope = { "t": msg_type, "d": payload_str, "x": "" }
        
        # Padding до фиксированного размера
        current_len = len(json.dumps(envelope).encode('utf-8'))
        padding_needed = self.packet_size - current_len
        
        if padding_needed > 0:
            # Заполняем случайным мусором
            envelope["x"] = ''.join(random.choices(string.ascii_letters + string.digits, k=padding_needed))
            
        return json.dumps(envelope)