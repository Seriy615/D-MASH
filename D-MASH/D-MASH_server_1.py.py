import sqlite3
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
import socket
import threading

server_host, server_port='127.0.0.1',12345

def create_db():
    conn = sqlite3.connect('blockchain.db')
    c = conn.cursor()
    
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    user_id TEXT PRIMARY KEY,
                    public_key TEXT NOT NULL)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS transactions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sender TEXT,
                    recipient TEXT,
                    message_hash TEXT,
                    iv BLOB,
                    ciphertext BLOB,
                    tag BLOB,
                    encrypted_sym_key BLOB,
                    encrypted_sym_key_for_sender BLOB,
                    signature BLOB,
                    time TEXT,
                    t_time REAL)''')
    
    conn.commit()
    conn.close()
create_db()
class Blockchain:
    def __init__(self):
        self.last_id = self.get_last_transaction_id()
    
    def get_last_transaction_id(self):
        conn = sqlite3.connect('blockchain.db')
        c = conn.cursor()
        c.execute('SELECT MAX(id) FROM transactions')
        last_id = c.fetchone()[0]
        conn.close()
        return last_id if last_id else -1

    def register_user(self, user_public_key_str, user_id):
        conn = sqlite3.connect('blockchain.db')
        c = conn.cursor()
        c.execute('INSERT INTO users (user_id, public_key) VALUES (?, ?)', (user_id, user_public_key_str))
        conn.commit()
        conn.close()

    def add_transaction(self, transaction):
        conn = sqlite3.connect('blockchain.db')
        c = conn.cursor()
        c.execute('''INSERT INTO transactions (sender, recipient, message_hash, iv, ciphertext, tag, encrypted_sym_key,
                     encrypted_sym_key_for_sender, signature, time, t_time)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                  (transaction.sender, transaction.recipient, transaction.message_hash, transaction.iv,
                   transaction.ciphertext, transaction.tag, transaction.encrypted_sym_key,
                   transaction.encrypted_sym_key_for_sender, transaction.signature, transaction.time, transaction.t_time))
        conn.commit()
        conn.close()
        self.last_id += 1
        
    def get_all_transactions_for_user(user_id):
        conn = sqlite3.connect('blockchain.db')
        c = conn.cursor()
        c.execute('SELECT * FROM transactions WHERE sender = ? OR recipient = ?', (user_id, user_id))
        rows = c.fetchall()
        transactions = []
        for row in rows:
                transactions.append(Transaction(
		    sender=row[1], recipient=row[2], message_hash=row[3], iv=row[4], ciphertext=row[5],
		    tag=row[6], encrypted_sym_key=row[7], encrypted_sym_key_for_sender=row[8],
		    signature=row[9], time=row[10], t_time=row[11]))
        conn.close()
        return transactions
    
    def get_transactions_for_user(user_id, last_id):
        conn = sqlite3.connect('blockchain.db')
        c = conn.cursor()
        c.execute('SELECT * FROM transactions WHERE sender = ? OR recipient = ? AND id > ? ', (user_id, user_id, last_id))
        rows = c.fetchall()
        transactions = []
        for row in rows:
                transactions.append(Transaction(
		    sender=row[1], recipient=row[2], message_hash=row[3], iv=row[4], ciphertext=row[5],
		    tag=row[6], encrypted_sym_key=row[7], encrypted_sym_key_for_sender=row[8],
		    signature=row[9], time=row[10], t_time=row[11]))
        conn.close()
        return transactions

blockchain = Blockchain()

def handle_client(client_socket):
    transaction_data = client_socket.recv(1024*8)
    
    message = json.loads(transaction_data.decode())
    
    if message[0]=='add_transaction':
        transaction_dict=message[1]
        transaction = Transaction(
            sender=transaction_dict['sender'],
            recipient=transaction_dict['recipient'],
            message_hash=transaction_dict['message_hash'], 
            iv=base64.b64decode(transaction_dict['iv']),
            ciphertext=base64.b64decode(transaction_dict['ciphertext']), 
            tag=base64.b64decode(transaction_dict['tag']),
            encrypted_sym_key=base64.b64decode(transaction_dict['encrypted_sym_key']),
            encrypted_sym_key_for_sender=base64.b64decode(transaction_dict['encrypted_sym_key_for_sender']),
            signature=base64.b64decode(transaction_dict['signature']), 
            time=transaction_dict['time'],
            t_time=transaction_dict['t_time'])
        blockchain.add_transaction(transaction)
        client_socket.send('message added'.encode())
        client_socket.close()
        
    elif message[0]=='get_all_transactions':
        user_id=message[1]
        last_id= blockchain.get_last_transaction_id()
        transactions=get_all_transactions_for_user(user_id)
        #send back
        
    elif message[0]=='get_transactions':
        user_id=message[1][0]
        last_id=message[1][1]
        get_transactions_for_user(user_id, last_id)
        #send back
        
    elif message[0]=='create_user':
        user_id=message[1][0]
        user_key=message[1][1]
        blockchain.register_user(user_key,user_id)
        #send back
        
    elif message[0]=='get_key':
        user_id=message[1][0]
        conn = sqlite3.connect('blockchain.db')
        c = conn.cursor()
        c.execute('SELECT public_key FROM transactions WHERE user_id = ?  ', (user_id))
        rows = c.fetchall()
        #send back
        
def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((server_host, server_port))
    server_socket.listen(5)
    print("Server listening on port", server_port)

    while True:
        client_socket, addr = server_socket.accept()
        client_handler = threading.Thread(target=handle_client, args=(client_socket))
        client_handler.start()

start_server()
