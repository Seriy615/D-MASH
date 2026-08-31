import time
import json
import base64
import os
import hashlib
from typing import Optional, Tuple
import nacl.bindings 
import nacl.utils
import nacl.secret
import nacl.pwhash
from nacl.public import PrivateKey, PublicKey, Box, SealedBox
from nacl.signing import SigningKey, VerifyKey
from nacl.encoding import HexEncoder, Base64Encoder
import blake3


MAX_MESSAGE_AGE = 300 
NODE_POW_PREFIX = "0520" # Префикс для Proof-of-Work ноды

class NodeCryptoManager:
    """
    Менеджер криптографии для слоя Демона (The Node).
    Отвечает за Identity ноды, PoW и 'ослепление' данных (Blind Storage).
    """
    def __init__(self, signing_key_hex: str = None):
        # The blind-index key must be node-local *and stable*: route aliases
        # are persisted, so a fresh random key here would orphan every route
        # and inbound binding on restart.  It is derived only in RAM from the
        # already-persistent private node identity with an explicit domain;
        # neither the key nor raw locators are written to the database.
        self.secret_salt: Optional[bytes] = None
        self.signing_key: Optional[SigningKey] = None
        self.verify_key: Optional[VerifyKey] = None
        self.private_key: Optional[PrivateKey] = None # Curve25519 (для расшифровки SealedBox)
        self.public_key: Optional[PublicKey] = None   # Curve25519 (для создания SealedBox)
        self.node_id: str = ""

        if signing_key_hex:
            self._load_keys(signing_key_hex)

    def _load_keys(self, signing_key_hex: str):
        """Загрузка существующих ключей ноды"""
        self.signing_key = SigningKey(signing_key_hex, encoder=HexEncoder)
        self.verify_key = self.signing_key.verify_key
        self.node_id = self.verify_key.encode(encoder=HexEncoder).decode()
        
        # Конвертация Ed25519 -> Curve25519 для шифрования
        self.private_key = self.signing_key.to_curve25519_private_key()
        self.public_key = self.verify_key.to_curve25519_public_key()
        self.secret_salt = hashlib.sha256(
            b"D-MASH|NODE_BLIND_ALIAS_KEY|V1\x00" + self.signing_key.encode()
        ).digest()

    @staticmethod
    def generate_node_identity() -> Tuple[str, str]:
        """
        Генерация новой Identity с Proof-of-Work.
        Ищет пару ключей, хеш публичного ключа которой начинается с 0520.
        Возвращает (signing_key_hex, node_id).
        Может занять несколько секунд.
        """
        print(f"🔨 [CRYPTO] Mining Node Identity (PoW prefix {NODE_POW_PREFIX})...")
        attempts = 0
        while True:
            sk = SigningKey.generate()
            vk = sk.verify_key
            node_id = vk.encode(encoder=HexEncoder).decode()
            
            # Проверка PoW: Blake3(NodeID) должен начинаться с 0520
            pow_hash = blake3.blake3(node_id.encode()).hexdigest()
            
            if pow_hash.startswith(NODE_POW_PREFIX):
                print(f"✅ [CRYPTO] Found Identity after {attempts} attempts: {node_id[:12]}...")
                return sk.encode(encoder=HexEncoder).decode(), node_id
            
            attempts += 1

    # --- BLIND STORAGE & HASHING ---

    def get_blind_hash(self, data: str) -> str:
        """
        Keyed Hash для индексов БД.
        Blake3(data, key=secret_salt).
        Без соли (которая в RAM) восстановить связь невозможно.
        """
        if not self.secret_salt:
            raise ValueError("node blind-index key is unavailable")
        return blake3.blake3(data.encode(), key=self.secret_salt).hexdigest()


    def _get_time_key(self, static_secret: bytes, timestamp: float) -> bytes:
        """Получаем T-Ratchet ключ, зависящий от времени, используя Static Secret как базу"""
        epoch_interval = 300
        epoch = int(timestamp / epoch_interval)
        kdf = blake3.blake3(static_secret)
        kdf.update(str(epoch).encode('utf-8'))
        return kdf.digest()
       
    def encrypt_for_self(self, data_dict: dict) -> str:
        """
        Шифрует данные 'сам для себя' (SealedBox).
        Используется для хранения метаданных маршрутов в БД.
        """
        try:
            json_bytes = json.dumps(data_dict).encode('utf-8')
            # SealedBox автоматически генерирует эфемерный ключ отправителя
            box = SealedBox(self.public_key)
            encrypted = box.encrypt(json_bytes)
            return base64.b64encode(encrypted).decode('utf-8')
        except Exception as e:
            print(f"❌ [CRYPTO] Blind encryption failed: {e}")
            return ""

    def decrypt_from_self(self, encrypted_b64: str) -> Optional[dict]:
        """
        Расшифровывает данные из 'слепого' хранилища.
        """
        try:
            box = SealedBox(self.private_key)
            encrypted_bytes = base64.b64decode(encrypted_b64)
            plaintext = box.decrypt(encrypted_bytes)
            return json.loads(plaintext.decode('utf-8'))
        except Exception:
            return None
        
    def sign_challenge(self, challenge: str) -> str:
        """Подписывает challenge-строку своим приватным ключом ноды."""
        if not self.signing_key:
            return ""
        signed = self.signing_key.sign(challenge.encode('utf-8'))
        return base64.b64encode(signed.signature).decode('utf-8')

    @staticmethod
    def verify_node_pow(node_id: str) -> bool:
        """
        Статический метод для проверки Proof-of-Work любого node_id.
        Проверяет, что blake3(node_id) начинается с нужного префикса.
        """
        if len(node_id) != 64: # Ed25519 public key is 32 bytes = 64 hex chars
            return False
        pow_hash = blake3.blake3(node_id.encode()).hexdigest()
        return pow_hash.startswith(NODE_POW_PREFIX)

    @staticmethod
    def verify_challenge_signature(node_id: str, challenge: str, signature_b64: str) -> bool:
        """
        Статический метод для проверки подписи challenge.
        Использует публичный ключ (node_id) для верификации.
        """
        try:
            verify_key = VerifyKey(node_id, encoder=HexEncoder)
            sig_bytes = base64.b64decode(signature_b64)
            verify_key.verify(challenge.encode('utf-8'), sig_bytes)
            return True
        except Exception:
            return False


class CryptoManager:
    """
    Менеджер криптографии для слоя Клиента (The User).
    Отвечает за E2EE, подписи сообщений и шифрование локальной истории.
    """
    def __init__(self):
        self.signing_key: Optional[SigningKey] = None 
        self.verify_key: Optional[VerifyKey] = None   
        self.private_key: Optional[PrivateKey] = None 
        self.public_key: Optional[PublicKey] = None   
        self.sym_key: Optional[bytes] = None          
        self.my_id: str = ""                          

    def derive_keys_from_password(self, username: str, password: str):
        """Генерация всех ключей из пары логин/пароль"""
        salt = hashlib.sha256(username.encode()).digest()[:16]
        
        kdf = nacl.pwhash.argon2id.kdf(
            nacl.secret.SecretBox.KEY_SIZE, password.encode(), salt,
            opslimit=nacl.pwhash.argon2id.OPSLIMIT_SENSITIVE,
            memlimit=nacl.pwhash.argon2id.MEMLIMIT_SENSITIVE
        )
        # Ключи для подписи (Ed25519)
        self.signing_key = SigningKey(kdf)
        self.verify_key = self.signing_key.verify_key
        
        # Ключи для шифрования (Curve25519)
        self.private_key = self.signing_key.to_curve25519_private_key()
        self.public_key = self.verify_key.to_curve25519_public_key()
        
        # ID пользователя - это Hex его публичного ключа подписи
        self.my_id = self.verify_key.encode(encoder=HexEncoder).decode()
        
        # Симметричный ключ для БД
        db_salt = hashlib.sha256((username + "_db_secure").encode()).digest()[:16]
        self.sym_key = nacl.pwhash.argon2id.kdf(
            nacl.secret.SecretBox.KEY_SIZE, password.encode(), db_salt,
            opslimit=nacl.pwhash.argon2id.OPSLIMIT_INTERACTIVE,
            memlimit=nacl.pwhash.argon2id.MEMLIMIT_INTERACTIVE
        )

    def _get_time_based_key(self, target_pub_hex: str, offset: int = 0) -> bytes:
        """
        Вычисляет сессионный ключ на основе ECDH + Время.
        offset: смещение по времени (0 - сейчас, -1 - прошлая эпоха, +1 - будущая)
        """
        # 1. Парсим чужой публичный ключ
        verify_key = VerifyKey(target_pub_hex, encoder=HexEncoder)
        target_curve_pub = verify_key.to_curve25519_public_key()

        # 2. Делаем ECDH (Математически: MyPriv * TheirPub == TheirPriv * MyPub)
        # Получаем "Вечный" общий секрет. 
        # (В будущем можно сделать Handshake, чтобы он не был вечным, но для начала сойдет)
        shared_secret = nacl.bindings.crypto_scalarmult(
            self.private_key.encode(),
            target_curve_pub.encode()
        )

        # 3. Получаем Эпоху (Номер "пятиминутки")
        # 300 секунд = 5 минут. Можно уменьшить до 60.
        epoch_interval = 300 
        current_epoch = int(time.time() / epoch_interval) + offset
        
        # 4. Смешиваем (Ratchet): Ключ = HASH(SharedSecret + EpochID)
        # Используем Blake3 как KDF
        kdf = blake3.blake3(shared_secret)
        kdf.update(str(current_epoch).encode('utf-8'))
        
        return kdf.digest() # Возвращает 32 байта для SecretBox
    
    # --- ROUTING & IDENTITY (Blake3) ---
    
    def get_route_id(self, sender_pub_hex: str, receiver_pub_hex: str) -> str:
        """ID маршрута = blake3(A + B). Конкатенация строк."""
        combined = sender_pub_hex + receiver_pub_hex
        return blake3.blake3(combined.encode()).hexdigest()

    def get_target_hash(self, pub_key_hex: str) -> str:
        """Хеш цели = blake3(B)"""
        return blake3.blake3(pub_key_hex.encode()).hexdigest()
        
    def get_blind_index(self, data: str, salt: bytes) -> str:
        """Хелпер для вычисления слепого индекса (если нужно клиенту)"""
        return blake3.blake3(data.encode(), key=salt).hexdigest()

    # --- SIGNATURES (Ed25519) ---

    def sign_data(self, data_str: str) -> str:
        """Подписывает строку и возвращает подпись в Base64"""
        signed = self.signing_key.sign(data_str.encode('utf-8'))
        return base64.b64encode(signed.signature).decode('utf-8')

    def verify_sig(self, pub_key_hex: str, data_str: str, sig_b64: str) -> bool:
        """Проверяет подпись данных"""
        try:
            verify_key = VerifyKey(pub_key_hex, encoder=HexEncoder)
            sig_bytes = base64.b64decode(sig_b64)
            verify_key.verify(data_str.encode('utf-8'), sig_bytes)
            return True
        except Exception:
            return False

        # --- E2EE (XSalsa20-Poly1305 + Ed25519 Signature) ---
        # --- TIME-BASED KEY DERIVATION (T-RATCHET) ---

    def _get_time_key(self, static_secret: bytes, timestamp: float) -> bytes:
        """Получаем 32-байтный временный ключ"""
        epoch_interval = 300
        epoch = int(timestamp / epoch_interval)
        
        # --- FIX: ИСПОЛЬЗУЕМ SHA256 ---
        data_to_hash = static_secret + str(epoch).encode('utf-8')
        return hashlib.sha256(data_to_hash).digest()
    
    def _get_static_secret(self, target_pub_hex: str) -> bytes:
        """Получаем 32-байтный вечный ключ из ECDH"""
        verify_key = VerifyKey(target_pub_hex, encoder=HexEncoder)
        target_curve_pub = verify_key.to_curve25519_public_key()
        shared = nacl.bindings.crypto_scalarmult(
            self.private_key.encode(), target_curve_pub.encode()
        )
        
        # --- FIX: ИСПОЛЬЗУЕМ SHA256 (всегда 32 байта) ---
        # Мешаем с солью
        return hashlib.sha256(shared + b'static_header_key_v2').digest()


    def _get_time_based_key(self, target_pub_hex: str, offset: int = 0) -> bytes:
        """
        Вычисляет сессионный ключ на основе ECDH + Время.
        offset: смещение по времени (0 - сейчас, -1 - прошлая эпоха, +1 - будущая)
        """
        # 1. Парсим чужой публичный ключ
        verify_key = VerifyKey(target_pub_hex, encoder=HexEncoder)
        target_curve_pub = verify_key.to_curve25519_public_key()

        # 2. Делаем ECDH (Математически: MyPriv * TheirPub == TheirPriv * MyPub)
        # Получаем "Вечный" общий секрет. 
        # (В будущем можно сделать Handshake, чтобы он не был вечным, но для начала сойдет)
        shared_secret = nacl.bindings.crypto_scalarmult(
            self.private_key.encode(),
            target_curve_pub.encode()
        )

        # 3. Получаем Эпоху (Номер "пятиминутки")
        # 300 секунд = 5 минут. Можно уменьшить до 60.
        epoch_interval = 300 
        current_epoch = int(time.time() / epoch_interval) + offset
        
        # 4. Смешиваем (Ratchet): Ключ = HASH(SharedSecret + EpochID)
        # Используем Blake3 как KDF
        kdf = blake3.blake3(shared_secret)
        kdf.update(str(current_epoch).encode('utf-8'))
        
        return kdf.digest() # Возвращает 32 байта для SecretBox
    
    def encrypt_message(self, target_pub_key_hex: str, message_text: str) -> str:
        # Генерируем ключ ДЛЯ ТЕКУЩЕГО МОМЕНТА ВРЕМЕНИ
        session_key = self._get_time_based_key(target_pub_key_hex, offset=0)

        timestamp = time.time()
        # Подпись оставляем - она нужна для аутентификации!
        sig_content = f"{message_text}{timestamp}{self.my_id}"
        signature = self.sign_data(sig_content)

        payload = {
            "txt": message_text,
            "ts": timestamp,
            "sid": self.my_id,
            "sig": signature,
            # Добавим паддинг (мусор), чтобы все сообщения были разной длины или кратной
            "rnd": base64.b64encode(os.urandom(16)).decode()
        }
        
        payload_bytes = json.dumps(payload).encode('utf-8')
        
        # ИСПОЛЬЗУЕМ SECRETBOX (Symmetric) ВМЕСТО BOX
        box = nacl.secret.SecretBox(session_key)
        encrypted = box.encrypt(payload_bytes)
        
        return base64.b64encode(encrypted).decode('utf-8')

    def decrypt_message(self, sender_pub_key_hex: str, encrypted_b64: str) -> str:
        """Расшифровывает, пробуя ключи разных временных эпох (Window of tolerance)"""
        try:
            encrypted_bytes = base64.b64decode(encrypted_b64)
            plaintext_bytes = None
            
            # --- T-RATCHET LOGIC ---
            # Пробуем расшифровать ключами: [Сейчас, Минуту назад, Минуту вперед]
            # Это решает проблемы рассинхрона часов и задержек сети.
            for offset in [0, -1, 1]:
                try:
                    candidate_key = self._get_time_based_key(sender_pub_key_hex, offset)
                    box = nacl.secret.SecretBox(candidate_key)
                    plaintext_bytes = box.decrypt(encrypted_bytes)
                    break # Успех! Выходим из цикла
                except Exception:
                    continue # Пробуем следующий ключ
            
            if plaintext_bytes is None:
                return "[ERROR: Decryption Failed - Keys rotated or Clock Skew]"

            # --- Дальше старая логика проверок ---
            payload = json.loads(plaintext_bytes.decode('utf-8'))
            
            # Проверки подписи и времени...
            if time.time() - payload.get("ts", 0) > MAX_MESSAGE_AGE:
                return "[ERROR: Message expired]"
            
            if payload.get("sid") != sender_pub_key_hex:
                return "[ERROR: Sender ID mismatch]"

            sig_content = f"{payload['txt']}{payload['ts']}{payload['sid']}"
            if not self.verify_sig(sender_pub_key_hex, sig_content, payload['sig']):
                return "[ERROR: Invalid Signature]"

            return payload.get("txt", "")

        except Exception as e:
            return f"[ERROR: Decryption Critical Fail: {str(e)}]"

    def encrypt_for_probe(self, target_pub_key_hex: str, data_str: str) -> str:
        try:
            recipient_verify_key = VerifyKey(target_pub_key_hex, encoder=HexEncoder)
            recipient_pub_key = recipient_verify_key.to_curve25519_public_key()
            box = SealedBox(recipient_pub_key)
            encrypted = box.encrypt(data_str.encode('utf-8'))
            return base64.b64encode(encrypted).decode('utf-8')
        except Exception:
            return ""

    def decrypt_from_probe(self, encrypted_b64: str) -> str:
        try:
            box = SealedBox(self.private_key)
            encrypted_bytes = base64.b64decode(encrypted_b64)
            plaintext = box.decrypt(encrypted_bytes)
            return plaintext.decode('utf-8')
        except Exception:
            return ""
        
    def get_recipient_tag(self, target_pub_hex: str) -> str:
        """
        Генерирует короткий ID (Алиас) для конкретного собеседника.
        Основан на статическом ECDH.
        Мы будем клеить это к началу каждого пакета.
        """
        # 1. Получаем ECDH секрет (он одинаковый у тебя и у друга)
        verify_key = VerifyKey(target_pub_hex, encoder=HexEncoder)
        target_curve_pub = verify_key.to_curve25519_public_key()
        shared_secret = nacl.bindings.crypto_scalarmult(
            self.private_key.encode(), 
            target_curve_pub.encode()
        )
        
        # 2. Вычисляем HMAC или Hash от секрета + Контекст
        # Берем первые 8 символов hex (4 байта). Этого достаточно чтобы не было коллизий у одного юзера.
        # "alias_tag" - строка-соль, чтобы тег отличался от ключей шифрования
        tag_hash = blake3.blake3(shared_secret, key=b'recipient_tag_context').hexdigest()
        return tag_hash[:8]
    
    # --- НОВЫЙ МЕТОД ДЛЯ TAGS (ALIAS) ---
    def get_delivery_tag(self, target_pub_hex: str) -> str:
        try:
            static_sec = self._get_static_secret(target_pub_hex)
            # Для тега достаточно md5 или sha256 (нужно 16 символов hex)
            # Не важно какой алгоритм, главное детерминированный
            tag_hash = hashlib.sha256(static_sec + b'delivery_tag_public').hexdigest()
            return tag_hash[:16] 
        except: return "0000000000000000"
        
    # --- DB Encryption (SecretBox) ---
    def encrypt_db_field(self, data: str) -> str:
        if not data: return ""
        box = nacl.secret.SecretBox(self.sym_key)
        encrypted = box.encrypt(data.encode('utf-8'))
        return base64.b64encode(encrypted).decode('utf-8')

    def decrypt_db_field(self, data_b64: str) -> str:
        if not data_b64: return ""
        try:
            box = nacl.secret.SecretBox(self.sym_key)
            encrypted = base64.b64decode(data_b64)
            plaintext = box.decrypt(encrypted)
            return plaintext.decode('utf-8')
        except:
            return "[DB DECRYPT FAIL]"
        
# --- OFFLINE T-RATCHET (PCP/GVP) ---

    def get_offline_key(self, target_pub_hex: str, offset: int = 0) -> bytes:
        """
        Публичная обертка для получения 'сырого' ключа T-Ratchet.
        Используется для GVP/PCP, где нет рукопожатия, а есть только Время.
        """
        # Используем ту же логику, что и для E2EE, но возвращаем байты
        return self._get_time_based_key(target_pub_hex, offset)

    def get_gvp_session_key(self, base_key: bytes, salt: str) -> bytes:
        """
        GVP: SessionKey = SHA256(BaseKey + Salt)
        """
        return hashlib.sha256(base_key + salt.encode('utf-8')).digest()

    def encrypt_pcp_payload(self, target_pub_hex: str, text: str) -> dict:
        """
        Шифрует текст для PCP.
        Возвращает: {ciphertext_b64, epoch_offset=0}
        """
        key = self.get_offline_key(target_pub_hex, 0)
        # Используем SecretBox для простоты (хотя в реальном PCP это был бы AES-CTR)
        box = nacl.secret.SecretBox(key)
        encrypted = box.encrypt(text.encode('utf-8'))
        return base64.b64encode(encrypted).decode('utf-8')

    def decrypt_pcp_payload(self, sender_pub_hex: str, ciphertext_b64: str) -> str:
        """
        Пытается расшифровать PCP, перебирая эпохи [0, -1, 1].
        """
        encrypted_bytes = base64.b64decode(ciphertext_b64)
        
        for offset in [0, -1, 1]:
            try:
                key = self.get_offline_key(sender_pub_hex, offset)
                box = nacl.secret.SecretBox(key)
                plaintext = box.decrypt(encrypted_bytes)
                return plaintext.decode('utf-8') + f" [Key Epoch: {offset}]"
            except:
                continue
        return "[PCP DECRYPT FAILED]"
