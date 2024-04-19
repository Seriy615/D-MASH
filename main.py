from cryptography.hazmat.primitives import asymmetric, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import base64
import time

def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key

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

def str_public_key_to_class(public_key_str):
    public_key_bytes = base64.b64decode(public_key_str.encode())
    public_key = serialization.load_pem_public_key(public_key_bytes)
    return public_key

def str_private_key_to_class(private_key_str):
    private_key_bytes = base64.b64decode(private_key_str.encode())
    private_key = serialization.load_pem_private_key(private_key_bytes, password=None)
    return private_key

class Transaction:
    def __init__(self, sender, recipient, message, signature, time, t_time):
        self.sender = sender
        self.recipient = recipient
        self.message = message
        self.signature = signature
        self.time = time
        self.t_time = t_time

class Blockchain:
    def __init__(self):
        self.chain = []

    def add_transaction(self, user_public_key_str, user_private_key_str, recipient_public_key_str, message):
        user_private_key = str_private_key_to_class(user_private_key_str)
        user_public_key = str_public_key_to_class(user_public_key_str)
        recipient_public_key = str_public_key_to_class(recipient_public_key_str)

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

        signature = user_private_key.sign(
            message.encode(),
            asymmetric.padding.PSS(
                mgf=asymmetric.padding.MGF1(hashes.SHA256()),
                salt_length=asymmetric.padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        transaction = Transaction(
            sender=user_public_key,
            recipient=recipient_public_key,
            message=(iv, ciphertext, encryptor.tag, encrypted_sym_key),
            signature=signature,
            time=time.ctime(),
            t_time=time.time()
        )
        
        self.chain.append(transaction)

    def get_transactions_for_user(self, user_public_key_str, user_private_key_str):
        messages = []
        user_private_key = str_private_key_to_class(user_private_key_str)
        user_public_key = str_public_key_to_class(user_public_key_str)

        for transaction in self.chain:
            if transaction.recipient == user_public_key:
                message = self.decrypt_message(
                    recipient_private_key=user_private_key,
                    sender_public_key=transaction.sender,
                    iv=transaction.message[0],
                    ciphertext=transaction.message[1],
                    tag=transaction.message[2],
                    encrypted_sym_key=transaction.message[3]
                )
                is_valid = self.verify_signature(
                    public_key=transaction.sender,
                    message=message,
                    signature=transaction.signature
                )
                if is_valid:
                    messages.append((transaction.sender, message, transaction.time))
        return messages

    def decrypt_message(self, recipient_private_key, sender_public_key, iv, ciphertext, tag, encrypted_sym_key):
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

if __name__ == "__main__":
    # Генерация ключей для двух пользователей
    alice_private_key, alice_public_key = generate_keys()
    bob_private_key, bob_public_key = generate_keys()

    # Преобразование ключей в строковое представление
    alice_private_key_str = private_key_to_str(alice_private_key)
    alice_public_key_str = public_key_to_str(alice_public_key)
    bob_private_key_str = private_key_to_str(bob_private_key)
    bob_public_key_str = public_key_to_str(bob_public_key)

    # Отправка сообщения от Alice к Bob
    message_from_alice = "Hello, Bob!"
    blockchain = Blockchain()
    blockchain.add_transaction(
        alice_public_key_str,
        alice_private_key_str,
        bob_public_key_str,
        message_from_alice
    )

    # Получение сообщений для Bob
    received_messages = blockchain.get_transactions_for_user(
        bob_public_key_str,
        bob_private_key_str
    )

    print("Received Messages for Bob:")
    for sender, message, time in received_messages:
        print(f"From:\n\n{public_key_to_str(sender)}\n\nat {time}:\n\n{message}")
