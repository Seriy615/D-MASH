#это код для сервера

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

    def get_all_transactions_for_user(self, user_private_key_str):
        messages = []
        user_public_key = self.keys[get_public_key(user_private_key_str)]

        for transaction in self.chain:
            if transaction.recipient == user_public_key or transaction.sender == user_public_key:
                messages.append(transaction)
        return messages
    # заменить на работу с БД

    def sort_to_chats(self, messages, user_id_key):
        chats = {}
        user_public_key_str=self.keys[user_id_key]
        for transaction in messages:
            if transaction.sender not in chats.keys() and transaction.recipient not in chats.keys():
                if transaction.recipient == user_public_key_str:
                    chats[transaction.sender] = []
                    chats[transaction.sender].append(transaction)
                elif transaction.sender == user_public_key_str:
                    chats[transaction.recipient] = []
                    chats[transaction.recipient].append(transaction)
            else:
                if transaction.recipient == user_public_key_str:
                    chats[transaction.sender].append(transaction)
                elif transaction.sender == user_public_key_str:
                    chats[transaction.recipient].append(transaction)
        new_chats={}
        for chat in chats.keys():
            sorted_transactions = sorted(chats[chat], key=lambda x: x.t_time)
            new_chats[chat] = sorted_transactions
        return new_chats
    
    def update_chats(self, json_file, user_private_key_str):
        sorted_chats, last_id =from_json(json_file)

        all_id=self.last_id

        messages = []
        user_public_key = get_public_key(user_private_key_str)
        user_id=self.keys[user_public_key]
        while last_id < all_id:
            transaction=self.chain[last_id+1]
            if transaction.recipient == user_id or transaction.sender == user_id:
                messages.append(transaction)
            last_id+=1
        sorted_new_chats = blockchain.sort_to_chats(messages, user_public_key)
        for chat in sorted_new_chats.keys():
            if chat in sorted_chats.keys():
                sorted_chats[chat].extend(sorted_new_chats[chat])
            else:
                sorted_chats[chat]=sorted_new_chats[chat]


        serialized_chats = {chat: [msg.to_dict() for msg in messages] for chat, messages in sorted_chats.items()}
        data={'last_id':last_id, 'messages': serialized_chats}
        # Сохранение отсортированных чатов в JSON
        with open(json_file, 'w') as f:
            json.dump(data, f, indent=4)
        return (json_file,sorted_chats)

    #заменить на работу с БД
    def get_all_chats(self, user_private_key_str):
        user_private_key = str_private_key_to_class(user_private_key_str)
        this_user = get_public_key(user_private_key_str)
        output_file= f"{self.keys[get_public_key(user_private_key_str)]}_chats.json"
        last_id=self.last_id
        user_messages = blockchain.get_all_transactions_for_user(user_private_key_str)

        sorted_chats = blockchain.sort_to_chats(user_messages, this_user)

        serialized_chats = {chat: [msg.to_dict() for msg in messages] for chat, messages in sorted_chats.items()}
        data={'last_id':last_id, 'messages': serialized_chats}
        # Сохранение отсортированных чатов в JSON
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=4)

        return (output_file, sorted_chats)
    #заменить на работу с БД

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
    
