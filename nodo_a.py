# nodo_a.py

import time
import random
import paho.mqtt.client as mqtt
from utils_crypto import encrypt_aes, decrypt_aes, encrypt_chacha20, generar_nonce

print("[A] Iniciando Nodo A (Sensor Médico)")

with open("claves/clave_maestra_A.bin", "rb") as f:
    master_key = f.read()
with open("claves/clave_sesion.bin", "rb") as f:
    clave_cifrada = encrypt_aes(master_key, f.read())
clave_sesion = decrypt_aes(master_key, clave_cifrada)
print("[A] Clave de sesión descifrada correctamente")

broker = "localhost"
client = mqtt.Client()

autenticado = []
nonce_A = generar_nonce()

# ---- RESPONDER AL NONCE DE B ----
def recibir_nonce_de_B(client, userdata, msg):
    nonce_B = decrypt_aes(clave_sesion, msg.payload)
    print(f"[A] Recibido nonce B: {nonce_B.hex()}")
    client.publish("ucisec/authB_response", encrypt_aes(clave_sesion, nonce_B))
    print("[A] Respuesta enviada a B")

# ---- VERIFICAR RESPUESTA DE B ----
def recibir_respuesta_de_B(client, userdata, msg):
    respuesta = decrypt_aes(clave_sesion, msg.payload)
    if respuesta == nonce_A:
        print("[A] B autenticado correctamente")
        autenticado.append(True)
    else:
        print("[A] Error: B no autenticado")

client.message_callback_add("ucisec/authB", recibir_nonce_de_B)
client.message_callback_add("ucisec/authA_response", recibir_respuesta_de_B)

client.connect(broker)
client.subscribe("ucisec/authB")
client.subscribe("ucisec/authA_response")
client.loop_start()

# ---- INICIAR AUTENTICACIÓN A → B ----
print(f"[A] Enviando nonce A: {nonce_A.hex()}")
client.publish("ucisec/authA", encrypt_aes(clave_sesion, nonce_A))

while not autenticado:
    time.sleep(0.2)

print("\n[A] Autenticación mutua completada. Enviando datos médicos...\n")

while True:
    temperatura = round(36 + random.random() * 2, 1)
    pulso = random.randint(60, 100)
    spo2 = random.randint(94, 100)
    datos = f"TEMP:{temperatura}°C | PULSO:{pulso}bpm | SpO2:{spo2}%"
    mensaje = encrypt_chacha20(clave_sesion, datos.encode())
    client.publish("ucisec/med", mensaje)
    print(f"[A] Datos enviados: {datos}")
    time.sleep(5)
