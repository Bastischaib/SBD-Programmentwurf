import base64
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from flask import Flask, render_template, request, session

app = Flask(__name__)
app.secret_key = os.urandom(24)


# Funktion zur Initialisierung des Cipher-Objekts
def initialize_cipher(key):
    backend = default_backend()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.ChaCha20(key, iv), mode=None, backend=backend)
    return cipher, iv


# Funktion zur Verschlüsselung der Nachricht
def encrypt_message(message, key):
    cipher, iv = initialize_cipher(key)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message) + encryptor.finalize()
    return base64.urlsafe_b64encode(iv + ciphertext)


# Funktion zur Entschlüsselung der Nachricht
def decrypt_message(encrypted_message, key):
    decoded_message = base64.urlsafe_b64decode(encrypted_message)
    cipher, iv = initialize_cipher(key)
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(decoded_message[16:]) + decryptor.finalize()
    return decrypted_message.decode('utf-8')


# Middleware für sichere Schlüsselverwaltung
def get_key():
    if 'key' not in session:
        session['key'] = base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8')
    return session['key']


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/send', methods=['POST'])
def send():
    if 'user' not in session:
        return {'error': 'Unauthorized'}, 401

    message = request.form['message']
    key = get_key()
    encrypted_message = encrypt_message(message.encode('utf-8'), key.encode('utf-8'))
    return {'encrypted_message': encrypted_message.decode('utf-8')}


@app.route('/receive', methods=['POST'])
def receive():
    if 'user' not in session:
        return {'error': 'Unauthorized'}, 401

    encrypted_message = request.form['encrypted_message']
    key = get_key()
    decrypted_message = decrypt_message(encrypted_message, key)
    return {'decrypted_message': decrypted_message}


@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    # Hier sollte eine sichere Authentifizierung implementiert werden
    if username == 'admin' and password == 'securepassword':
        session['user'] = username
        return {'message': 'Login successful'}
    else:
        return {'error': 'Invalid credentials'}, 401


@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user', None)
    return {'message': 'Logout successful'}


if __name__ == '__main__':
    app.run(debug=True)
