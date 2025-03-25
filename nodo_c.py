# nodo_c.py

import os
import base64
from utils_crypto import encrypt_aes

# Claves maestras precompartidas (simuladas) para A y B
master_key_A = os.urandom(32)
master_key_B = os.urandom(32)

# Generar clave de sesión (simétrica) para cifrar datos
clave_sesion = os.urandom(32)
print(">> Clave de sesión generada (secreta)")

# Cifrar la clave de sesión para cada nodo
clave_para_A = encrypt_aes(master_key_A, clave_sesion)
clave_para_B = encrypt_aes(master_key_B, clave_sesion)

# Simulamos el envío mostrando en consola
print("\nClave cifrada para Nodo A:")
print(clave_para_A.decode())

print("\nClave cifrada para Nodo B:")
print(clave_para_B.decode())

# Guardamos las claves maestras y la clave de sesión para uso futuro
with open("clave_maestra_A.bin", "wb") as f:
    f.write(master_key_A)

with open("clave_maestra_B.bin", "wb") as f:
    f.write(master_key_B)

with open("clave_sesion.bin", "wb") as f:
    f.write(clave_sesion)
