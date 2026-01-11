import asyncio
import json
import uuid
import time
from datetime import datetime
from websockets.server import serve
from websockets.client import connect as ws_connect
from database import DatabaseManager

class P2PNode:
    def __init__(self, system_db: DatabaseManager):
        self.system_db = system_db
        self.active_connections = {} 
        self.active_user_id = None
        self.active_user_db = None
        self.active_crypto = None

    def set_active_user(self, user_id, user_db, crypto):
        self.active_user_id = user_id
        self.active_user_db = user_db
        self.active_crypto = crypto

    def remove_active_user(self):
        self.active_user_id = None
        self.active_user_db = None
        self.active_crypto = None

    async def start_server(self, port: int):
        print(f"🌐 [P2P] Daemon listening on port {port}")
        async with serve(self._handle_incoming, "0.0.0.0", port):
            await asyncio.Future()

    async def connect_to(self, address: str):
        try:
            uri = f"ws://{address}"
            ws = await ws_connect(uri, open_timeout=5)
            
            # Handshake: обмениваемся ID
            my_id_handshake = self.active_user_id if self.active_user_id else "daemon_node"
            # В новой версии лучше использовать ID ноды, но пока оставим совместимость
            if self.system_db.node_crypto:
                my_id_handshake = self.system_db.node_crypto.node_id

            await ws.send(my_id_handshake)
            peer_id = await ws.recv()
            
            if peer_id == my_id_handshake:
                 await ws.close()
                 return False

            self.active_connections[peer_id] = ws
            print(f"✅ [P2P] Connected to neighbor {peer_id[:8]}")
            
            # BLIND STORAGE: Используем метод менеджера, а не SQL
            await self.system_db.add_neighbor(peer_id, address)
            
            asyncio.create_task(self._listen_socket(ws, peer_id))
            return True
        except Exception as e:
            print(f"❌ [P2P] Connection failed: {e}")
            return False

    async def _handle_incoming(self, websocket):
        try:
            peer_id = await websocket.recv()
            
            my_id_handshake = "daemon_node"
            if self.system_db.node_crypto:
                my_id_handshake = self.system_db.node_crypto.node_id
            
            await websocket.send(my_id_handshake)
            
            self.active_connections[peer_id] = websocket
            print(f"🔗 [P2P] Neighbor connected: {peer_id[:8]}")
            
            # BLIND STORAGE
            await self.system_db.add_neighbor(peer_id, "incoming")
            
            await self._listen_socket(websocket, peer_id)
        except Exception: pass

    async def _listen_socket(self, websocket, peer_id):
        try:
            async for message in websocket:
                await self._process_envelope(message, from_peer=peer_id)
        except:
            if peer_id in self.active_connections: del self.active_connections[peer_id]

    async def _process_envelope(self, envelope_json: str, from_peer: str):
        try:
            envelope = json.loads(envelope_json)
            if envelope.get("t") == "DUMMY": return

            if envelope.get("t") == "REAL":
                inner_json = envelope.get("d")
                packet = json.loads(inner_json)
                pkt_type = packet.get("type")
                pkt_id = packet.get("id")

                # Регистрируем пакет (внутри используется хеширование ID)
                is_new = await self.system_db.mark_packet_seen(pkt_id)

                if pkt_type == "PROBE":
                    await self._handle_probe(packet, from_peer, is_new)
                elif pkt_type == "DATA":
                    if is_new:
                        await self._handle_data(packet, from_peer)
        except Exception as e:
            print(f"❌ Packet error: {e}")

    async def _handle_probe(self, packet, from_peer, is_new_probe):
        probe_id = packet['id']
        route_id = packet['route_id']   
        rev_id = packet['rev_id']       
        target_hash = packet['target_hash']
        metric = packet['metric']

        # 1. ЗАПИСЬ МАРШРУТА
        # Проверяем, есть ли уже маршрут назад
        existing_rev = await self.system_db.get_best_route(rev_id)
        
        # Если маршрута нет или он не локальный, обновляем таблицу
        if not (existing_rev and existing_rev['is_local']):
            # BLIND STORAGE: add_route сама зашифрует данные
            await self.system_db.add_route(rev_id, from_peer, metric + 1, prev_hop_id=None)

        # 2. ПРОВЕРКА ЦЕЛИ (Мы - Боб?)
        if self.active_user_id and self.active_crypto:
            if self.active_crypto.get_target_hash(self.active_user_id) == target_hash:
                if is_new_probe:
                    sender_id_json = self.active_crypto.decrypt_from_probe(packet['auth'])
                    if sender_id_json:
                        try:
                            sender_data = json.loads(sender_id_json)
                            sender_id = sender_data.get('sid')
                            
                            sig_data = sender_id + self.active_user_id
                            if self.active_crypto.verify_sig(sender_id, sig_data, packet['sig']):
                                print(f"🎯 [PROBE] Validated source: {sender_id[:8]}")
                                
                                # Боб метит ВХОДЯЩИЙ канал как LOCAL
                                await self.system_db.add_route(route_id, "LOCAL", 0, is_local=True, remote_user_id=sender_id)

                                if packet.get('content'):
                                    await self._deliver_to_active_user(packet, sender_id)
                                
                                if existing_rev and existing_rev['is_local']:
                                    return 

                                await self._send_probe_response(sender_id)
                        except Exception as e:
                            print(f"Probe validation error: {e}")
                return 

        # 3. РЕТРАНСЛЯЦИЯ
        if is_new_probe and packet['ttl'] > 0:
            packet['ttl'] -= 1
            packet['metric'] += 1
            
            # BLIND OUTBOX: Хешируем exclude_peer перед записью
            ex_hash = self.system_db.node_crypto.get_blind_hash(from_peer)
            
            await self.system_db.conn.execute("""
                INSERT INTO outbox (packet_id, next_hop_hash, packet_json, exclude_peer_hash) 
                VALUES (?, NULL, ?, ?)
            """, (probe_id, json.dumps(packet), ex_hash))
            await self.system_db.conn.commit()

    async def _send_probe_response(self, requester_id):
        """Боб отправляет свою пробу Алисе в ответ"""
        print(f"🔄 [PROBE] Sending symmetric response to {requester_id[:8]}")
        
        route_id = self.active_crypto.get_route_id(self.active_user_id, requester_id)
        rev_id = self.active_crypto.get_route_id(requester_id, self.active_user_id)
        
        signature = self.active_crypto.sign_data(self.active_user_id + requester_id)
        auth_payload = self.active_crypto.encrypt_for_probe(requester_id, json.dumps({"sid": self.active_user_id}))
        
        e2e_content = self.active_crypto.encrypt_message(requester_id, "🤝 [System] Connection established")
        
        probe_pkt_id = str(uuid.uuid4())
        probe_packet = {
            "type": "PROBE",
            "id": probe_pkt_id,
            "route_id": route_id,
            "rev_id": rev_id,
            "target_hash": self.active_crypto.get_target_hash(requester_id),
            "metric": 0,
            "ttl": 20,
            "auth": auth_payload,
            "sig": signature,
            "content": e2e_content
        }
        
        # Боб метит СВОЙ исходящий канал как LOCAL
        await self.system_db.add_route(route_id, "LOCAL", 0, is_local=True, remote_user_id=requester_id)
        await self.system_db.mark_packet_seen(probe_pkt_id)
        
        await self.system_db.conn.execute("""
            INSERT INTO outbox (packet_id, next_hop_hash, packet_json, exclude_peer_hash) 
            VALUES (?, NULL, ?, NULL)
        """, (probe_pkt_id, json.dumps(probe_packet)))
        await self.system_db.conn.commit()

    async def _handle_data(self, packet, from_peer):
        """Пересылка данных"""
        route_id = packet.get('route_id')
        
        # BLIND ROUTING: Получаем расшифрованный лучший маршрут
        route = await self.system_db.get_best_route(route_id)
        
        if not route: return 

        if route['is_local']:
            # Если маршрут локальный, пытаемся доставить юзеру
            # В route['prev_hop_id'] может лежать ID удаленного юзера, если мы его сохраняли
            # Но надежнее достать sender_id из самого пакета при расшифровке
            # Здесь мы просто передаем пакет на попытку расшифровки
            # (sender_id будет извлечен внутри _deliver_to_active_user из подписи)
            
            # ВАЖНО: В текущей реализации _deliver_to_active_user требует sender_id
            # Но мы его не знаем, пока не расшифруем.
            # Поэтому мы пробуем расшифровать, перебирая известных контактов или (в будущем)
            # передавая "unknown".
            # В Phase 1 мы упростим: мы знаем remote_user_id из таблицы маршрутизации (если сохранили)
            # Но в blind_routes мы сохраняли remote_user_id только для LOCAL маршрутов?
            # Да, в _handle_probe мы делали: add_route(..., remote_user_id=sender_id)
            
            # Однако get_best_route возвращает dict. Проверим, есть ли там remote_user_id?
            # В database.py мы его не возвращали явно в dict, надо проверить.
            # В database.py get_best_route возвращает next_hop_id, metric, is_local, prev_hop_id.
            # remote_user_id там нет. Это баг Phase 1, который мы исправим позже.
            # Пока попробуем доставить, используя prev_hop_id как hint, или просто перебором.
            
            # Временный хак: передаем packet, а sender_id извлечем внутри
            # Но сигнатура метода требует sender_id.
            # Исправим это: передадим None, а метод пусть разбирается.
            await self._deliver_to_active_user(packet, None)
            return
        
        # Если маршрут транзитный
        next_hop = route['next_hop_id']
        if next_hop in self.active_connections:
            # BLIND OUTBOX: Хешируем next_hop и exclude_peer
            nh_hash = self.system_db.node_crypto.get_blind_hash(next_hop)
            ex_hash = self.system_db.node_crypto.get_blind_hash(from_peer)
            
            await self.system_db.conn.execute("""
                INSERT INTO outbox (packet_id, next_hop_hash, packet_json, exclude_peer_hash) 
                VALUES (?, ?, ?, ?)
            """, (packet['id'], nh_hash, json.dumps(packet), ex_hash))
            await self.system_db.conn.commit()

    async def _deliver_to_active_user(self, packet, sender_id_hint):
        """
        Финальная доставка с оптимизацией по Tag (Alias).
        Больше никакого Brute-force перебора контактов.
        """
        if not self.active_crypto or not self.active_user_db: return

        try:
            # 1. ИЗВЛЕЧЕНИЕ ТЕГА И ШИФРОТЕКСТА
            # Мы ожидаем, что теперь content - это JSON-структура {"tag": "...", "ciphertext": "..."}
            raw_content = packet.get("content")
            delivery_tag = None
            ciphertext = raw_content # По дефолту считаем, что это старый формат (только текст)

            # Пробуем достать тег, если контент пришел словарем или JSON-строкой
            if isinstance(raw_content, dict):
                delivery_tag = raw_content.get("tag")
                ciphertext = raw_content.get("ciphertext")
            elif isinstance(raw_content, str):
                # Пробуем распарсить строку, вдруг это JSON-обертка
                if raw_content.strip().startswith('{'):
                    try:
                        parsed = json.loads(raw_content)
                        if isinstance(parsed, dict) and "tag" in parsed:
                            delivery_tag = parsed["tag"]
                            ciphertext = parsed["ciphertext"]
                    except:
                        pass # Значит это обычный Base64 (старая версия)

            candidates = []

            # 2. БЫСТРЫЙ ПОИСК (Fast Path) - O(1)
            if delivery_tag:
                # Ищем контакт, у которого вычисленный Alias совпадает с пришедшим
                # ВАЖНО: Убедись, что колонка delivery_tag существует в таблице contacts!
                try:
                    async with self.active_user_db.conn.execute(
                        "SELECT user_id FROM contacts WHERE delivery_tag = ?", (delivery_tag,)
                    ) as cursor:
                        row = await cursor.fetchone()
                        if row:
                            candidates.append(row['user_id'])
                        else:
                            print(f"⚠️ [MAIL] Tag '{delivery_tag}' not found in contacts. Ignoring.")
                            return # Если тег есть, но контакта нет - это спам или чужой пакет
                except Exception as db_e:
                    print(f"⚠️ [MAIL] DB Error (Schema update needed?): {db_e}")
                    # Фолбэк, если базу еще не обновили
            
            # 3. РЕЗЕРВНЫЙ ПУТЬ (Fallback) - Если тега в пакете нет
            # Используем подсказку из роутинга или (в крайнем случае) старый перебор
            if not candidates and not delivery_tag:
                if sender_id_hint:
                    candidates.append(sender_id_hint)
                else:
                    # Это самый тяжелый вариант, оставим для обратной совместимости
                    # или для первого сообщения "из ниоткуда" (хотя теги должны быть всегда)
                    async with self.active_user_db.conn.execute("SELECT user_id FROM contacts") as cursor:
                        rows = await cursor.fetchall()
                        for r in rows: candidates.append(r['user_id'])

            if not candidates:
                return

            # 4. РАСШИФРОВКА
            decrypted_text = None
            real_sender = None
            
            # Теперь candidates обычно содержит всего 1 запись -> мгновенное выполнение
            for sid in candidates:
                # Здесь внутри decrypt_message уже работает T-Ratchet (подбор по времени)
                res = self.active_crypto.decrypt_message(sid, ciphertext)
                if not res.startswith("[ERROR"):
                    decrypted_text = res
                    real_sender = sid
                    break
            
            if not decrypted_text:
                print(f"❌ [MAIL] Decryption failed. Sender tag: {delivery_tag}, Candidate: {real_sender}")
                return

            msg_uuid = packet.get('id')
            
            # 5. СОХРАНЕНИЕ (User Layer)
            try:
                # Шифруем локальным "вечным" ключом для истории
                local_content = self.active_crypto.encrypt_db_field(decrypted_text)
                
                await self.active_user_db.conn.execute("""
                    INSERT INTO messages (packet_id, chat_id, sender_id, content, timestamp, is_outgoing, is_read) 
                    VALUES (?, ?, ?, ?, ?, 0, 0)
                """, (msg_uuid, real_sender, real_sender, local_content, datetime.now().isoformat()))
                
                await self.active_user_db.conn.execute("""
                    INSERT INTO contacts (user_id, last_seen) VALUES (?, ?) 
                    ON CONFLICT(user_id) DO UPDATE SET last_seen=excluded.last_seen
                """, (real_sender, datetime.now().isoformat()))
                
                await self.active_user_db.conn.commit()
                print(f"📨 [MAIL] Verified & Delivered from {real_sender[:8]}")
            except Exception as e:
                # Игнорируем дубликаты пакетов (UNIQUE constraint)
                if "UNIQUE constraint failed" not in str(e):
                    print(f"Save error: {e}")

        except Exception as e:
            print(f"Critical delivery error: {e}")
