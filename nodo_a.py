# nodo_a.py

import time
import base64
import paho.mqtt.client as mqtt
from utils_crypto import (
    encrypt_aes, decrypt_aes,
    generar_nonce
)

# Leer claves
with open("claves/clave_maestra_A.bin", "rb") as f:
    master_key = f.read()

with open("claves/clave_sesion.bin", "rb") as f:
    clave_cifrada = encrypt_aes(master_key, f.read())

clave_sesion = decrypt_aes(master_key, clave_cifrada)

# MQTT
broker = "localhost"
topic_datos = "ucisec/med"
client = mqtt.Client()

# Autenticación mutua

def autenticar_con_b(client, clave_sesion):
    print("\n[Autenticación A → B]")

    nonce_A = generar_nonce()
    client.publish("ucisec/authA", encrypt_aes(clave_sesion, nonce_A))

    respuesta = []

    def recibir_respuesta(client, userdata, msg):
        if decrypt_aes(clave_sesion, msg.payload) == nonce_A:
            print("<< B autenticado correctamente")
        else:
            print("!! Nodo B no es confiable")
        respuesta.append(True)

    client.subscribe("ucisec/authA_response")
    client.message_callback_add("ucisec/authA_response", recibir_respuesta)

    while not respuesta:
        client.loop(timeout=0.1)

def responder_a_b(client, userdata, msg):
    nonce_B = decrypt_aes(clave_sesion, msg.payload)
    client.publish("ucisec/authB_response", encrypt_aes(clave_sesion, nonce_B))
    print(">> Respuesta de autenticación enviada a B")

client.message_callback_add("ucisec/authB", responder_a_b)

# Iniciar conexión
client.connect(broker)
client.loop_start()
autenticar_con_b(client, clave_sesion)
client.subscribe("ucisec/authB")

print("\nNodo A listo. Enviando datos cifrados...\n")

while True:
    temperatura = f"temperatura:{round(36 + 2 * time.time() % 1, 1)}°C"
    mensaje = temperatura.encode()

    mensaje_cifrado = encrypt_aes(clave_sesion, mensaje)
    print(">> Enviando:", mensaje_cifrado.decode())

    client.publish(topic_datos, mensaje_cifrado)
    time.sleep(5)
