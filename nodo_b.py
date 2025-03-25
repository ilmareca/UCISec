# nodo_b.py

import time
import paho.mqtt.client as mqtt
from utils_crypto import encrypt_aes, decrypt_aes, generar_nonce

# Leer claves
with open("claves/clave_maestra_B.bin", "rb") as f:
    master_key = f.read()

with open("claves/clave_sesion.bin", "rb") as f:
    clave_cifrada = encrypt_aes(master_key, f.read())

clave_sesion = decrypt_aes(master_key, clave_cifrada)

broker = "localhost"
client = mqtt.Client()

# Parte 1: responder autenticación de A
def on_authA(client, userdata, msg):
    nonce_recibido = decrypt_aes(clave_sesion, msg.payload)
    respuesta = encrypt_aes(clave_sesion, nonce_recibido)
    client.publish("ucisec/authA_response", respuesta)
    print("<< Nodo A autenticado correctamente")

client.message_callback_add("ucisec/authA", on_authA)
client.subscribe("ucisec/authA")

# Parte 2: autenticar a A
def autenticar_con_a():
    print("\n[Autenticación B → A]")

    nonce_B = generar_nonce()
    client.publish("ucisec/authB", encrypt_aes(clave_sesion, nonce_B))

    respuesta = []

    def recibir_respuesta(client, userdata, msg):
        if decrypt_aes(clave_sesion, msg.payload) == nonce_B:
            print("<< A autenticado correctamente")
        else:
            print("!! Nodo A no es confiable")
        respuesta.append(True)

    client.subscribe("ucisec/authB_response")
    client.message_callback_add("ucisec/authB_response", recibir_respuesta)

    while not respuesta:
        client.loop(timeout=0.1)

# Recibir datos
def on_message(client, userdata, msg):
    print("\nMensaje cifrado recibido:", msg.payload.decode())
    try:
        mensaje_descifrado = decrypt_aes(clave_sesion, msg.payload)
        print(">> Mensaje descifrado:", mensaje_descifrado.decode())
    except:
        print("Error al descifrar")

client.on_message = on_message
client.subscribe("ucisec/med")

# Conectar y ejecutar
client.connect(broker)
client.loop_start()

print("Nodo B esperando autenticación de A...")
time.sleep(2)

autenticar_con_a()

print("\n[Autenticación mutua completada]\n")
client.loop_forever()
