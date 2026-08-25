import asyncio
import json
import uuid
import time
from datetime import datetime
from websockets.server import serve
from websockets.client import connect as ws_connect
from database import DatabaseManager
import base64
# Добавьте в начало
from dsp import AudioProcessor
from crypto import NodeCryptoManager # <-- Импортируем для статических методов
HANDSHAKE_TIMEOUT = 10.0
class P2PNode:
    def __init__(self, system_db: DatabaseManager):
        self.system_db = system_db
        self.active_connections = {} 
        self.active_user_id = None
        self.active_user_db = None
        self.active_crypto = None
        self.connection_tasks = set()

    def set_active_user(self, user_id, user_db, crypto):
        self.active_user_id = user_id
        self.active_user_db = user_db
        self.active_crypto = crypto

    def remove_active_user(self):
        self.active_user_id = None
        self.active_user_db = None
        self.active_crypto = None

    async def start_server(self, port: int, host: str = "0.0.0.0"):
        print(f"🌐 [P2P] Daemon listening on {host}:{port}")
        # Увеличиваем max_size до 10MB и пинг-таймаут до 60 секунд
        async with serve(self._handle_incoming, host, port, max_size=10*1024*1024, ping_timeout=60, ping_interval=20):
            await asyncio.Future()

    async def connect_to(self, address: str):
        """
        Инициирует подключение к другому узлу с криптографическим рукопожатием.
        Процесс: A -> B
        1. A -> B: { "id": A_id, "challenge": random_string }
        2. B -> A: { "id": B_id, "signature": sign(random_string) }
        3. A проверяет PoW(B_id) и подпись.
        """
        ws = None
        try:
            uri = f"ws://{address}"
            ws = await ws_connect(uri, open_timeout=5, max_size=10*1024*1024, ping_timeout=60, ping_interval=20)
            my_node_id = self.system_db.node_crypto.node_id
                
                # --- Шаг 1: Отправляем challenge ---
            challenge = str(uuid.uuid4())
            handshake_init_payload = json.dumps({"id": my_node_id, "challenge": challenge})
            print(f"🤝 [P2P OUT] -> {address}: Sending handshake challenge...")
            await ws.send(handshake_init_payload)

                # --- Шаг 2: Ждем ответ с подписью ---
            response_json = await asyncio.wait_for(ws.recv(), timeout=HANDSHAKE_TIMEOUT)
            response_data = json.loads(response_json)
                
            peer_id = response_data.get("id")
            signature = response_data.get("signature")

            if not peer_id or not signature or peer_id == my_node_id:
                raise ValueError("Invalid handshake response")

                # --- Шаг 3: Верификация ---
                # 3.1 Проверка Proof-of-Work (PoW) собеседника
            if not NodeCryptoManager.verify_node_pow(peer_id):
                print(f"☠️ [P2P REJECT] Peer {peer_id[:8]} failed PoW verification!")
                raise ConnectionRefusedError("PoW verification failed")

                # 3.2 Проверка подписи (доказательство владения ключом)
            if not NodeCryptoManager.verify_challenge_signature(peer_id, challenge, signature):
                print(f"☠️ [P2P REJECT] Peer {peer_id[:8]} failed challenge signature!")
                raise ConnectionRefusedError("Signature verification failed")

                # --- Успех ---
            print(f"✅ [P2P] Handshake with {peer_id[:8]} successful!")
            self.active_connections[peer_id] = ws
            await self.system_db.add_neighbor(peer_id, address)

            task = asyncio.create_task(self._listen_socket(ws, peer_id))
            self.connection_tasks.add(task)
            task.add_done_callback(self.connection_tasks.discard)
            return True
        except asyncio.TimeoutError:
            print(f"❌ [P2P] Handshake with {address} timed out.")
        except (ConnectionRefusedError, ValueError) as e:
            print(f"❌ [P2P] Handshake with {address} failed: {e}")
        except Exception as e:
            print(f"❌ [P2P] Connection to {address} failed: {e}")
        if ws is not None:
            await ws.close()
        return False
    
    async def _handle_incoming(self, websocket):
        """
        Обрабатывает входящее соединение с криптографическим рукопожатием.
        Процесс: A -> B (Мы - B)
        1. A -> B: { "id": A_id, "challenge": random_string }
        2. B проверяет PoW(A_id).
        3. B -> A: { "id": B_id, "signature": sign(random_string) }
        """
        peer_id = None
        try:
            # --- Шаг 1: Получаем challenge ---
            request_json = await asyncio.wait_for(websocket.recv(), timeout=HANDSHAKE_TIMEOUT)
            request_data = json.loads(request_json)
            peer_id = request_data.get("id")
            challenge = request_data.get("challenge")
            my_node_id = self.system_db.node_crypto.node_id

            if not peer_id or not challenge or peer_id == my_node_id:
                raise ValueError("Invalid handshake request")
            print(f"🤝 [P2P IN] <- {peer_id[:8]}: Received handshake challenge...")
            
            # --- Шаг 2: Верификация PoW ---
            if not NodeCryptoManager.verify_node_pow(peer_id):
                print(f"☠️ [P2P REJECT] Incoming peer {peer_id[:8]} failed PoW verification!")
                raise ConnectionRefusedError("PoW verification failed")
            
            # --- Шаг 3: Подписываем challenge и отправляем ответ ---
            signature = self.system_db.node_crypto.sign_challenge(challenge)
            response_payload = json.dumps({
                "id": my_node_id,
                "signature": signature
            })
            await websocket.send(response_payload)

            # --- Успех ---
            print(f"✅ [P2P] Handshake with {peer_id[:8]} successful!")
            self.active_connections[peer_id] = websocket
            await self.system_db.add_neighbor(peer_id, "incoming")
            
            await self._listen_socket(websocket, peer_id)
        
        except asyncio.TimeoutError:
             if websocket.open: await websocket.close(code=1008, reason="Handshake timeout")
        except (ConnectionRefusedError, ValueError) as e:
             if websocket.open: await websocket.close(code=1008, reason=str(e))
        except Exception:
            if peer_id and peer_id in self.active_connections:
                del self.active_connections[peer_id]


    async def _listen_socket(self, websocket, peer_id):
        # Этот метод теперь остается без изменений, но его вызов обернут в async with
        try:
            async for message in websocket:
                await self._process_envelope(message, from_peer=peer_id)
        finally:
            # Соединение закрылось (нормально или с ошибкой), удаляем из активных
            if peer_id in self.active_connections:
                del self.active_connections[peer_id]
            print(f"🔌 [P2P] Connection with {peer_id[:8]} closed.")

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
            # Узел не расшифровывает пользовательский пакет. Если PWA сейчас не
            # активна, сохраняем непрозрачный envelope в mailbox: именно этот
            # переход запускает отложенное opaque-уведомление.
            if not self.active_crypto or not self.active_user_db:
                await self.system_db.save_to_mailbox(json.dumps(packet))
                return

            delivered = await self._deliver_to_active_user(packet, None)
            if not delivered:
                # Не теряем непрозрачный пакет, если PWA временно не может его
                # открыть (например, contact state ещё не загружен). Повторная
                # доставка будет выполнена при следующем входе пользователя.
                await self.system_db.save_to_mailbox(json.dumps(packet))
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
        if not self.active_crypto or not self.active_user_db:
            return False

        try:
            raw_content = packet.get("content")
            delivery_tag = None
            ciphertext = raw_content
            
            # --- ПРОВЕРКА НА СПЕЦ-ПРОТОКОЛЫ (SIMULATION) ---
            sim_type = None
            sim_data = None
            
            # Пытаемся распарсить JSON, вдруг это PCP/GVP или новый формат с тегом
            try:
                if isinstance(raw_content, str) and raw_content.strip().startswith('{'):
                    parsed = json.loads(raw_content)
                    if isinstance(parsed, dict):
                        if "sim_type" in parsed:
                            sim_type = parsed["sim_type"]
                            sim_data = parsed
                        elif "tag" in parsed:
                            delivery_tag = parsed["tag"]
                            ciphertext = parsed["ciphertext"]
            except: pass

            # --- ПОИСК ОТПРАВИТЕЛЯ (КАНДИДАТЫ) ---
            candidates = []
            if delivery_tag:
                try:
                    async with self.active_user_db.conn.execute("SELECT user_id FROM contacts WHERE delivery_tag = ?", (delivery_tag,)) as cursor:
                        row = await cursor.fetchone()
                        if row: candidates.append(row['user_id'])
                except: pass
            
            if not candidates:
                if sender_id_hint: candidates.append(sender_id_hint)
                else:
                    async with self.active_user_db.conn.execute("SELECT user_id FROM contacts") as cursor:
                        rows = await cursor.fetchall()
                        for r in rows: candidates.append(r['user_id'])

            if not candidates:
                return False

            # --- ОБРАБОТКА В ЗАВИСИМОСТИ ОТ ТИПА ---
            
            decrypted_content_for_db = None
            real_sender = None

            for sid in candidates:
                if sim_type == "PCP":
                    # --- PHANTOM CALL (HONEST MODE) ---
                    print(f"🔍 [PCP] Receiving MFSK Audio from {sid}...")
                    
                    # 1. Достаем аудио из пакета
                    audio_b64 = sim_data.get("audio_preview", "")
                    if not audio_b64:
                        print("❌ [PCP] No audio data found!")
                        continue
                        
                    audio_bytes = base64.b64decode(audio_b64)
                    
                    # 2. ЗАПУСКАЕМ ЧЕСТНЫЙ ДЕКОДЕР (FFT)
                    # Это тяжелая операция, запускаем в пуле процессов
                    import core
                    loop = asyncio.get_running_loop()
                    
                    decoded_text = await loop.run_in_executor(
                        core.state.process_pool,
                        AudioProcessor.decode_pcp_audio,
                        audio_bytes
                    )
                    
                    if decoded_text:
                        print(f"✅ [PCP] Successfully decoded via FFT: '{decoded_text}'")
                        real_sender = sid
                        
                        # 3. (Опционально) Если текст был зашифрован T-Ratchet, расшифровываем его
                        # В текущей реализации api.py мы кладем в звук ИСХОДНЫЙ текст для наглядности.
                        # Если бы мы клали шифротекст, тут надо было бы вызвать decrypt_pcp_payload(decoded_text)
                        
                        ui_json = {
                            "protocol": "PCP",
                            "text": decoded_text, # Результат работы FFT!
                            "audio": audio_b64
                        }
                        decrypted_content_for_db = json.dumps(ui_json)
                        break
                    else:
                        print("❌ [PCP] FFT Decoding failed (CRC mismatch or noise)")
                        # Fallback: можно попробовать взять из ciphertext, если звук не прошел
                        # Но мы хотим честно, поэтому если звук битый - пакет потерян.
                        continue

                elif sim_type == "GVP":
                    print(f"🔍 [GVP DEBUG] Processing GVP from {sid}...") # DEBUG
                    try:
                        # 1. Декодируем Base64
                        scrambled_wav = base64.b64decode(sim_data["blob"])
                        print(f"   > Blob size: {len(scrambled_wav)} bytes") # DEBUG

                        # 2. Получаем ключи
                        salt = sim_data["salt"]
                        base_key = self.active_crypto.get_offline_key(sid, 0)
                        session_key = self.active_crypto.get_gvp_session_key(base_key, salt)
                        
                        # 3. Импорт Core (для пула процессов)
                        import core
                        
                        print("   > Starting DSP process...") # DEBUG
                        loop = asyncio.get_running_loop()
                        
                        # 4. Запуск DSP
                        restored_wav = await loop.run_in_executor(
                            core.state.process_pool,
                            AudioProcessor.scramble_audio,
                            scrambled_wav, 
                            session_key, 
                            False 
                        )
                        
                        print(f"   > DSP finished. Result size: {len(restored_wav)}") # DEBUG
                        
                        if not restored_wav:
                            print("❌ [GVP ERROR] DSP returned empty bytes! (FFMPEG failed?)")
                            continue

                        real_sender = sid
                        ui_json = {
                            "protocol": "GVP",
                            "salt": salt,
                            "scrambled": sim_data["blob"], 
                            "restored": base64.b64encode(restored_wav).decode('utf-8') 
                        }
                        decrypted_content_for_db = json.dumps(ui_json)
                        print("✅ [GVP SUCCESS] JSON prepared for DB") # DEBUG
                        break
                        
                    except Exception as e:
                        import traceback
                        print(f"❌ [GVP CRITICAL FAIL]: {e}")
                        traceback.print_exc() # Покажет полную ошибку в консоли
                        continue
                    
                else:
                    # --- STANDARD E2EE ---
                    res = self.active_crypto.decrypt_message(sid, ciphertext)
                    if not res.startswith("[ERROR"):
                        decrypted_content_for_db = res
                        real_sender = sid
                        break

            if not decrypted_content_for_db:
                print(f"❌ [MAIL] Decryption failed. Type: {sim_type}")
                return False

            # --- СОХРАНЕНИЕ ---
            msg_uuid = packet.get('id')
            try:
                local_content = self.active_crypto.encrypt_db_field(decrypted_content_for_db)
                
                await self.active_user_db.conn.execute("""
                    INSERT INTO messages (packet_id, chat_id, sender_id, content, timestamp, is_outgoing, is_read) 
                    VALUES (?, ?, ?, ?, ?, 0, 0)
                """, (msg_uuid, real_sender, real_sender, local_content, datetime.now().isoformat()))
                
                await self.active_user_db.conn.execute("""
                    INSERT INTO contacts (user_id, last_seen) VALUES (?, ?) 
                    ON CONFLICT(user_id) DO UPDATE SET last_seen=excluded.last_seen
                """, (real_sender, datetime.now().isoformat()))
                
                await self.active_user_db.conn.commit()
                print(f"📨 [MAIL] Delivered {sim_type or 'TEXT'} from {real_sender[:8]}")
                return True
            except Exception as e:
                if "UNIQUE constraint failed" in str(e):
                    # Идемпотентная повторная доставка уже находится в локальном
                    # зашифрованном хранилище и не должна удерживать mailbox.
                    return True
                print(f"Save error: {e}")
                return False

        except Exception as e:
            print(f"Critical delivery error: {e}")
            return False
