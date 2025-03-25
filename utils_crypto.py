# utils_crypto.py

import os
import time
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def pad(data):
    while len(data) % 16 != 0:
        data += b'\x00'
    return data

def unpad(data):
    return data.rstrip(b'\x00')

def encrypt_aes(key, plaintext):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padded_data = pad(plaintext)
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(iv + ciphertext)

def decrypt_aes(key, encoded_data):
    data = base64.b64decode(encoded_data)
    iv = data[:16]
    ciphertext = data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return unpad(padded_plaintext)


def encrypt_chacha20(key, plaintext):
    nonce = os.urandom(16)
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext)
    return base64.b64encode(nonce + ciphertext)

def decrypt_chacha20(key, encoded_data):
    data = base64.b64decode(encoded_data)
    nonce = data[:16]
    ciphertext = data[16:]
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext)

def benchmark(crypto_fn, *args):
    start = time.time()
    result = crypto_fn(*args)
    end = time.time()
    return result, round((end - start) * 1000, 3)  # tiempo en ms


def generar_nonce():
    return os.urandom(16)
