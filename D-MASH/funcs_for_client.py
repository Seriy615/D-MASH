#это код для клиента

from cryptography.hazmat.primitives import asymmetric, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers.algorithms import AES
import base64
import time
import json
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.primitives.asymmetric.padding import PSS
import hashlib
import os


def decrypt_text(user_id, password):

    input_file = f'key_{user_id}.json'
    with open(input_file, 'r') as f:
        # Читаем соль, вектор и зашифрованный текст из файла
        saltn, ivn, nciphertext = json.load(f)
    iv = base64.b64decode(ivn)
    salt = base64.b64decode(saltn)
    ciphertext = base64.b64decode(nciphertext)

    # Создаем ключевой производный от пароля
    backend = default_backend()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256 битов для ключа AES-256
        salt=salt,
        iterations=100000,
        backend=backend
    )
    key = kdf.derive(password.encode())

    # Создаем объект шифра AES с режимом CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    # Создаем дешифратор и дешифруем текст
    decryptor = cipher.decryptor()
    decrypted_text = decryptor.update(ciphertext) + decryptor.finalize()
    print(decrypted_text.decode())
    return decrypted_text.decode()


def encrypt_text(password, input_text, output_file):
    # Преобразовать текст в байты
    input_bytes = input_text.encode()

    # Вычислить остаток от деления длины данных на длину блока
    padding_length = AES.block_size - len(input_bytes) % AES.block_size

    # Добавить дополнительные байты, чтобы сделать длину данных кратной длине блока
    input_bytes += bytes([padding_length] * padding_length)

    # Генерировать случайную соль
    salt = os.urandom(16)

    # Создать объект PBKDF2 для генерации ключа из пароля
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # Длина ключа
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    # Получить ключ из пароля
    key = kdf.derive(password.encode())

    # Генерировать случайный вектор инициализации
    iv = os.urandom(16)

    # Создать объект шифра AES в режиме CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    # Создать шифратор и зашифровать текст
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(input_bytes) + encryptor.finalize()
    ciphertextn=base64.b64encode(ciphertext).decode()
    saltn=base64.b64encode(salt).decode()
    niv=base64.b64encode(iv).decode()
    # Записать соль, вектор инициализации и зашифрованный текст в файл
    with open(output_file, 'w') as f:
        json.dump([saltn, niv, ciphertextn], f)




def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key


def from_json(json_file):
    with open(json_file, 'r') as f:
        json_data = json.load(f)
    sorted_chats = {}
    for chat, messages in json_data['messages'].items():
        decoded_messages = []
        for msg in messages:
            iv = base64.b64decode(msg['iv'])
            ciphertext = base64.b64decode(msg['ciphertext'])
            tag = base64.b64decode(msg['tag'])
            encrypted_sym_key = base64.b64decode(msg['encrypted_sym_key'])
            encrypted_sym_key_for_sender = base64.b64decode(msg['encrypted_sym_key_for_sender'])
            signature = base64.b64decode(msg['signature'])
            time = msg['time']
            t_time = msg['t_time']
            decoded_messages.append(Transaction(msg['sender'], msg['recipient'], msg['message_hash'], iv, ciphertext, tag, encrypted_sym_key, encrypted_sym_key_for_sender, signature, time, t_time))
        sorted_chats[chat] = decoded_messages
    return (sorted_chats,json_data['last_id'])

def private_key_to_str(private_key):
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return base64.b64encode(private_key_bytes).decode()

def get_public_key(private_key_str):
    private_key = str_private_key_to_class(private_key_str)
    public_key = private_key.public_key()
    return public_key_to_str(public_key)

def public_key_to_str(public_key):
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return base64.b64encode(public_key_bytes).decode()

def str_public_key_to_class(public_key_str):
    public_key_bytes = base64.b64decode(public_key_str.encode())
    public_key = serialization.load_pem_public_key(public_key_bytes)
    return public_key

def str_private_key_to_class(private_key_str):
    private_key_bytes = base64.b64decode(private_key_str.encode())
    private_key = serialization.load_pem_private_key(private_key_bytes, password=None)
    return private_key


class Transaction:
    def __init__(self, sender, recipient, message_hash,  iv, ciphertext, tag, encrypted_sym_key, encrypted_sym_key_for_sender, signature, time, t_time):
        self.sender = sender
        self.recipient = recipient
        self.message_hash = message_hash
        self.iv = iv
        self.ciphertext = ciphertext
        self.tag = tag
        self.encrypted_sym_key = encrypted_sym_key
        self.encrypted_sym_key_for_sender =encrypted_sym_key_for_sender
        self.signature = signature
        self.time = time
        self.t_time = t_time


    def to_dict(self):
        return {
            "sender": self.sender,
            "recipient": self.recipient,
            "message_hash":self.message_hash,
            "iv": base64.b64encode(self.iv).decode(),
            "ciphertext": base64.b64encode(self.ciphertext).decode(),
            "tag": base64.b64encode(self.tag).decode(),
            "encrypted_sym_key": base64.b64encode(self.encrypted_sym_key).decode(),
            "encrypted_sym_key_for_sender": base64.b64encode(self.encrypted_sym_key_for_sender).decode(),
            "signature": base64.b64encode(self.signature).decode(),
            "time": self.time,
            "t_time": self.t_time
        }

class Blockchain:
    def __init__(self):
        self.chain = []
        self.users = {}
        self.keys = {}
        self.last_id = -1
    def create_user(self):
        user_id = None
        a=True
        while a:
            user_id=input("Введите имя пользователя: ")
            if user_id not in self.users.keys():a=False
            else:print('Имя пользователя занято, попробуйте другое имя')
        password= input("Введите пароль: ")
        private_key, public_key=generate_keys()
        private_key_str = private_key_to_str(private_key)
        public_key_str = public_key_to_str(public_key)
        encrypt_text(password,private_key_str,f'key_{user_id}.json')
        self.register_user(public_key_str,user_id)
        
    def register_user(self,user_public_key_str,user_id ):
        self.users[user_id] = user_public_key_str
        self.keys[user_public_key_str] = user_id
        #отправить в БД


    def add_transaction(self, user_private_key_str, recipient_id, message):
        user_private_key = str_private_key_to_class(user_private_key_str)
        user_public_key = get_public_key(user_private_key_str)
        recipient_public_key = str_public_key_to_class(self.users[recipient_id])
        user_public_key_cls= str_public_key_to_class(user_public_key)
        sym_key = os.urandom(32)
        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(sym_key), modes.GCM(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
        hm = hashlib.sha256()
        hm.update(message.encode())
        message_hash= hm.hexdigest()
        signature = user_private_key.sign(
            message_hash.encode(),
            asymmetric.padding.PSS(
                mgf=asymmetric.padding.MGF1(hashes.SHA256()),
                salt_length=asymmetric.padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        encrypted_sym_key = recipient_public_key.encrypt(
            sym_key,
            asymmetric.padding.OAEP(
                mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        encrypted_sym_key_for_sender = user_public_key_cls.encrypt(
            sym_key,
            asymmetric.padding.OAEP(
                mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        transaction = Transaction(
            sender=self.keys[user_public_key],
            recipient=recipient_id,
            message_hash=message_hash,
            iv=iv,
            ciphertext=ciphertext,
            tag=encryptor.tag,
            encrypted_sym_key=encrypted_sym_key,
            encrypted_sym_key_for_sender=encrypted_sym_key_for_sender,
            signature=signature,
            t_time=time.time(),
            time=time.ctime()
        )

        self.chain.append(transaction) # заменить на отправку на сервер
        self.last_id += 1

    def reseive_message(self, transaction, user_private_key_str):
        user_private_key = str_private_key_to_class(user_private_key_str)
        sender_public_key = str_public_key_to_class(self.users[transaction.sender])
        iv = transaction.iv
        ciphertext = transaction.ciphertext
        tag = transaction.tag
        encrypted_sym_key = transaction.encrypted_sym_key
        encrypted_sym_key_for_sender = transaction.encrypted_sym_key_for_sender
        if user_private_key.public_key()==sender_public_key:
            message = self.decrypt_message(
                recipient_private_key=user_private_key,
                sender_public_key=sender_public_key,
                iv=iv,
                ciphertext=ciphertext,
                tag=tag,
                encrypted_sym_key = encrypted_sym_key_for_sender
            )
        else:
            message = self.decrypt_message(
                recipient_private_key=user_private_key,
                sender_public_key=sender_public_key,
                iv=iv,
                ciphertext=ciphertext,
                tag=tag,
                encrypted_sym_key=encrypted_sym_key
            )
        if message:
            hm = hashlib.sha256()
            hm.update(message.encode())
            message_hash_from_plaintext= hm.hexdigest()
            first_valid= message_hash_from_plaintext == transaction.message_hash
            sec_valid = self.verify_signature(
                public_key=sender_public_key,
                message=transaction.message_hash,
                signature=transaction.signature
            )
            is_valid= first_valid and sec_valid
            if is_valid:
                return (transaction.sender, message, transaction.time)
        return None
    def decrypt_chats(self, chats, user_private_key_str):
        user_private_key = str_private_key_to_class(user_private_key_str)
        new_chats = {}
        for chat in chats.keys():
            new_chats[chat] = []
            for transaction in chats[chat]:
                message = self.reseive_message(transaction, user_private_key_str)
                if message:
                    new_chats[chat].append(message)
        return new_chats


    def decrypt_message(self, recipient_private_key, sender_public_key, iv, ciphertext, tag, encrypted_sym_key):
        try:
            sym_key = recipient_private_key.decrypt(
                encrypted_sym_key,
                asymmetric.padding.OAEP(
                    mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            cipher = Cipher(algorithms.AES(sym_key), modes.GCM(iv, tag))
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            return plaintext.decode()
        except Exception as e:
            print(f"Error decrypting message: {e}")
            return None

    def show_chats(self, sorted_chats, user_private_key_str, create_nsf=True):
        decrypted_chats = self.decrypt_chats(sorted_chats, user_private_key_str)
        this_user = get_public_key(user_private_key_str)
        user_id=self.keys[this_user]
        decrypted_chats_s = {'this_user':user_id, 'messages': decrypted_chats}
        # Вывод расшифрованных сообщений

        if create_nsf:
            with open(f'{user_id}_not_safety_chats.json','w') as f:
                json.dump(decrypted_chats_s, f, indent=4)

        for chat, messages in decrypted_chats.items():
            print(f"Чат с {chat}:\n")
            for message in messages:
                print(f"{message[2]}: ({'companion' if message[0] != user_id else 'you'}) {message[1]}")
            print("------\n\n")
        return f'{user_id}_not_safety_chats.json'
    def verify_signature(self, public_key, message, signature):
        try:
            public_key.verify(
                signature,
                message.encode(),
                asymmetric.padding.PSS(
                    mgf=asymmetric.padding.MGF1(hashes.SHA256()),
                    salt_length=asymmetric.padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            return False
    def show_chats_from_not_safety(self,not_safety_file):
        with open(not_safety_file,'r') as f:
            decrypted_chats_s = json.load(f)
        this_user, decrypted_chats= decrypted_chats_s['this_user'],decrypted_chats_s['messages']
        for chat, messages in decrypted_chats.items():
            print(f"Чат с {chat}:\n")
            for message in messages:
                print(f"{message[2]}: ({'companion' if message[0] != this_user else 'you'}) {message[1]}")
            print("------\n\n")
