# nodo_b.py

import time
import paho.mqtt.client as mqtt
from utils_crypto import encrypt_aes, decrypt_aes, decrypt_chacha20, generar_nonce

print("[B] Iniciando Nodo B (Servidor Médico)")

with open("claves/clave_maestra_B.bin", "rb") as f:
    master_key = f.read()
with open("claves/clave_sesion.bin", "rb") as f:
    clave_cifrada = encrypt_aes(master_key, f.read())
clave_sesion = decrypt_aes(master_key, clave_cifrada)
print("[B] Clave de sesión descifrada correctamente")

broker = "localhost"
client = mqtt.Client()

autenticado = []
nonce_B = generar_nonce()

# ---- RESPONDER AL NONCE DE A ----
def on_authA(client, userdata, msg):
    nonce = decrypt_aes(clave_sesion, msg.payload)
    print(f"[B] Recibido nonce A: {nonce.hex()}")
    client.publish("ucisec/authA_response", encrypt_aes(clave_sesion, nonce))
    print("[B] Respuesta enviada a A")

# ---- VERIFICAR RESPUESTA DE A ----
def on_authB_response(client, userdata, msg):
    respuesta = decrypt_aes(clave_sesion, msg.payload)
    if respuesta == nonce_B:
        print("[B] A autenticado correctamente")
        autenticado.append(True)
    else:
        print("[B] Error: A no autenticado")

# ---- RECIBIR DATOS MÉDICOS ----
def on_datos_med(client, userdata, msg):
    try:
        mensaje = decrypt_chacha20(clave_sesion, msg.payload)
        print(f"[B] Datos médicos descifrados (ChaCha20): {mensaje.decode()}")
    except Exception as e:
        print(f"[B] Error al descifrar con ChaCha20: {e}")


client.message_callback_add("ucisec/authA", on_authA)
client.message_callback_add("ucisec/authB_response", on_authB_response)
client.on_message = on_datos_med

client.connect(broker)
client.subscribe("ucisec/authA")
client.subscribe("ucisec/authB_response")
client.subscribe("ucisec/med")
client.loop_start()

# ---- INICIAR AUTENTICACIÓN B → A ----
print(f"[B] Enviando nonce B: {nonce_B.hex()}")
client.publish("ucisec/authB", encrypt_aes(clave_sesion, nonce_B))

while not autenticado:
    time.sleep(0.2)

print("\n[B] Autenticación mutua completada. Esperando datos...\n")

while True:
    time.sleep(0.5)
