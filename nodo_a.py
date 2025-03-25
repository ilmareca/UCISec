# nodo_a.py

import time
import paho.mqtt.client as mqtt
from utils_crypto import decrypt_aes, encrypt_aes
import base64

# Leer clave maestra y clave de sesión cifrada
with open("clave_maestra_A.bin", "rb") as f:
    master_key = f.read()

with open("clave_sesion.bin", "rb") as f:
    # Simula recibirla cifrada desde nodo C
    clave_cifrada = encrypt_aes(master_key, f.read())

# Descifrar clave de sesión
clave_sesion = decrypt_aes(master_key, clave_cifrada)

# MQTT setup
broker = "localhost"
topic = "ucisec/med"

client = mqtt.Client()
client.connect(broker)

print("Nodo A listo. Enviando datos cifrados...\n")

while True:
    # Simula una medición de temperatura
    temperatura = f"temperatura:{round(36 + 2 * time.time() % 1, 1)}°C"
    mensaje = temperatura.encode()

    # Cifrado AES (bloque) por defecto
    mensaje_cifrado = encrypt_aes(clave_sesion, mensaje)
    print(">> Enviando:", mensaje_cifrado.decode())

    # Publicar mensaje cifrado
    client.publish(topic, mensaje_cifrado)
    time.sleep(5)
