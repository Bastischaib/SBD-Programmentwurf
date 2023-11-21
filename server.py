"""Chat Room Connection - Client-to-Client"""
import base64
import os
import socket
import threading

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305, AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

host = '127.0.0.1'
port = 59000
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((host, port))
server.listen()
clients = []
aliases = []


# Verschlüsselungsfunktion mit ChaCha20
def encrypt_chacha20(message, key_chacha):
    cipher = ChaCha20Poly1305(key_chacha)
    nonce = b'\x00' * 12  # 96-bit Nullnonce
    ciphertext = cipher.encrypt(nonce, message.encode('utf-8'), None)
    return base64.b64encode(ciphertext)


# Entschlüsselungsfunktion mit ChaCha20
def decrypt_chacha20(ciphertext, key_chacha):
    cipher = ChaCha20Poly1305(key_chacha)
    nonce = b'\x00' * 12  # 96-bit Nullnonce
    decrypted = cipher.decrypt(nonce, base64.b64decode(ciphertext), None)
    return decrypted.decode('utf-8')


# Verschlüsselungsfunktion mit AES
def encrypt_aes(message, key_aes):
    cipher = AESGCM(key_aes)
    nonce = b'\x00' * 12  # 96-bit Nullnonce
    ciphertext = cipher.encrypt(nonce, message.encode('utf-8'), None)
    return base64.b64encode(ciphertext)


# Entschlüsselungsfunktion mit AES
def decrypt_aes(ciphertext, key_aes):
    cipher = AESGCM(key_aes)
    nonce = b'\x00' * 12  # 96-bit Nullnonce
    decrypted = cipher.decrypt(nonce, base64.b64decode(ciphertext), None)
    return decrypted.decode('utf-8')


def broadcast(message, key_encrypt):
    encrypted_message = encrypt_aes(message, key_encrypt)
    for client in clients:
        client.send(encrypted_message)


def handle_client(client, key_decrypt):
    while True:
        try:
            encrypted_message = client.recv(1024)
            decrypted_message = decrypt_aes(encrypted_message, key_decrypt)
            broadcast(decrypted_message, key_decrypt)
        except:
            index = clients.index(client)
            clients.remove(client)
            client.close()
            alias = aliases[index]
            broadcast(f'{alias} has left the chat room!', key_decrypt)
            aliases.remove(alias)
            break


# Hauptfunktion zum Aufbau der Client-Verbindung


def receive():
    while True:
        print('Server is running and listening ...')
        client, address = server.accept()
        print(f'connection is established with {str(address)}')
        client.send('alias?'.encode('utf-8'))
        alias = client.recv(1024)
        aliases.append(alias)
        clients.append(client)
        print(f'The alias of this client is {alias}'.encode('utf-8'))
        broadcast(f'{alias} has connected to the chat room', key)
        client.send('you are now connected!'.encode('utf-8'))
        thread = threading.Thread(target=handle_client, args=(client, key))
        thread.start()


def generate_secure_key():
    try:
        secure_key = os.urandom(16)
        return secure_key
    except NotImplementedError:
        password = b"schaible-sturm23"
        salt = b"haufen_grattler"
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            iterations=100000,
            salt=salt,
            length=16,
            backend=default_backend()
        )
        secure_key = kdf.derive(password)
        return secure_key


if __name__ == "__main__":
    key = bytes(generate_secure_key())
    receive()
