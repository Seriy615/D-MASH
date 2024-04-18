from cryptography.hazmat.primitives import asymmetric, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import base64
import time
class User:
    def __init__(self, private_key, public_key):
        self.private_key = private_key
        self.public_key = public_key

    @classmethod
    def generate_user(cls):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()
        
        return cls(private_key, public_key)

    @classmethod
    def from_keys(cls, private_key_str, public_key_str):
        private_key = serialization.load_pem_private_key(
            private_key_str.encode(),
            password=None
        )
        
        public_key = serialization.load_pem_public_key(public_key_str.encode())
        
        return cls(private_key, public_key)

    def private_key_to_str(self):
        private_key_bytes = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        return base64.b64encode(private_key_bytes).decode()

    def public_key_to_str(self):
        public_key_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return base64.b64encode(public_key_bytes).decode()

    def encrypt_message(self, recipient_public_key, message):
        sym_key = os.urandom(32)
        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(sym_key), modes.GCM(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
        
        encrypted_sym_key = recipient_public_key.encrypt(
            sym_key,
            asymmetric.padding.OAEP(
                mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return (iv, ciphertext, encryptor.tag, encrypted_sym_key)

    def decrypt_message(self, sender_public_key, iv, ciphertext, tag, encrypted_sym_key):
        sym_key = self.private_key.decrypt(
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

    def sign_message(self, message):
        signature = self.private_key.sign(
            message.encode(),
            asymmetric.padding.PSS(
                mgf=asymmetric.padding.MGF1(hashes.SHA256()),
                salt_length=asymmetric.padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        return signature

    def verify_signature(self, message, signature, sender_public_key):
        try:
            sender_public_key.verify(
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

class Blockchain:
    def __init__(self):
        self.chain = []

    def add_transaction(self, sender_public_key, recipient_public_key, encrypted_message, signature):
        transaction = {
            'sender': sender_public_key,
            'recipient': recipient_public_key,
            'message': encrypted_message,
            'signature': signature,
            'time': time.ctime(),
            't_time': time.time()
        }
        self.chain.append(transaction)

    def get_transactions_for_user(self, user_public_key, user_private_key):
        messages = []
        for transaction in self.chain:
            if transaction['recipient'] == user_public_key:
                message = User(user_private_key, user_public_key).decrypt_message(
                    sender_public_key=transaction['sender'],
                    iv=transaction['message'][0],
                    ciphertext=transaction['message'][1],
                    tag=transaction['message'][2],
                    encrypted_sym_key=transaction['message'][3]
                )
                is_valid = User(user_private_key, user_public_key).verify_signature(
                    message,
                    transaction['signature'],
                    sender_public_key=transaction['sender']
                )
                if is_valid:
                    messages.append((transaction['sender'], message, transaction['time']))
        return messages
def private_key_to_str(private_key):
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return base64.b64encode(private_key_bytes).decode()

def public_key_to_str(public_key):
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return base64.b64encode(public_key_bytes).decode()


if __name__ == "__main__":
    # Генерация ключей для двух пользователей
    alice = User.generate_user()
    bob = User.generate_user()

    # Отправка сообщения от Alice к Bob
    message_from_alice = "Hello, Bob!"
    encrypted_message = alice.encrypt_message(bob.public_key, message_from_alice)
    signature = alice.sign_message(message_from_alice)

    blockchain = Blockchain()
    blockchain.add_transaction(alice.public_key, bob.public_key, encrypted_message, signature)

    # Получение сообщений для Bob
    received_messages = blockchain.get_transactions_for_user(bob.public_key, bob.private_key)

    print("Received Messages for Bob:")
    for sender, message, time in received_messages:
        print(f"From:\n\n{public_key_to_str(sender)}\n\nat {time}:\n\n{message}")
