# nodo_c.py

import os
from utils_crypto import encrypt_aes

# Crear carpeta para guardar claves
os.makedirs("claves", exist_ok=True)

# Claves maestras para A y B
master_key_A = os.urandom(32)
master_key_B = os.urandom(32)
clave_sesion = os.urandom(32)
print(">> Clave de sesión generada (secreta)")

# Cifrar la clave de sesión con cada clave maestra
clave_para_A = encrypt_aes(master_key_A, clave_sesion)
clave_para_B = encrypt_aes(master_key_B, clave_sesion)

print("\nClave cifrada para Nodo A:\n", clave_para_A.decode())
print("\nClave cifrada para Nodo B:\n", clave_para_B.decode())

# Guardar claves
with open("claves/clave_maestra_A.bin", "wb") as f:
    f.write(master_key_A)

with open("claves/clave_maestra_B.bin", "wb") as f:
    f.write(master_key_B)

with open("claves/clave_sesion.bin", "wb") as f:
    f.write(clave_sesion)
