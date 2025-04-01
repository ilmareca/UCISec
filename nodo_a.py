import os
import time
import json
import paho.mqtt.client as mqtt
from utils_crypto import encrypt_aes, decrypt_aes, encrypt_chacha20, generar_nonce

print("[A] Iniciando Nodo A (Sensor Médico)")

# --- Entrada del usuario ---
planta = input("Planta del sensor: ")
habitacion = input("Habitación del sensor: ")
sensor_id = input("ID del sensor: ")

sensor_path = f"{planta}_{habitacion}_{sensor_id}"
topic_base = f"ucisec/{planta}/{habitacion}/{sensor_id}"

# --- Ruta a la clave maestra del sensor ---
clave_dir = "claves_por_sensor"
path_clave_maestra = os.path.join(clave_dir, f"{sensor_path}_maestra.bin")

if not os.path.exists(path_clave_maestra):
    print("[A] ❌ Clave maestra no encontrada.")
    exit(1)

with open(path_clave_maestra, "rb") as f:
    clave_maestra = f.read()

# --- MQTT setup ---
broker = "localhost"
client = mqtt.Client()
clave_sesion = None
nonce_A = generar_nonce()
autenticado = []

# --- Recibir clave cifrada desde Nodo C ---
def on_clave_para_A(client, userdata, msg):
    global clave_sesion
    clave_sesion = decrypt_aes(clave_maestra, msg.payload)
    print(f"[A] ✅ Clave de sesión recibida y descifrada.")

# --- Verificar respuesta de B ---
def on_authA_response(client, userdata, msg):
    respuesta = decrypt_aes(clave_sesion, msg.payload)
    if respuesta == nonce_A:
        print("[A] B autenticado correctamente")
        autenticado.append(True)
    else:
        print("[A] Error: B no autenticado")

# --- Recibir nonce B y responder ---
def on_authB(client, userdata, msg):
    nonce_B = decrypt_aes(clave_sesion, msg.payload)
    print(f"[A] Recibido nonce B: {nonce_B.hex()}")

    topic_response = f"{topic_base}/authB_response"
    client.publish(topic_response, encrypt_aes(clave_sesion, nonce_B))
    print(f"[A] Respuesta enviada a B en topic {topic_response}")

# --- Suscripciones ---
client.message_callback_add(f"ucisec/claves/{planta}/{habitacion}/{sensor_id}/para_A", on_clave_para_A)
client.message_callback_add(f"{topic_base}/authA_response", on_authA_response)
client.message_callback_add(f"{topic_base}/authB", on_authB)

client.connect(broker)
client.subscribe(f"ucisec/claves/{planta}/{habitacion}/{sensor_id}/para_A")
client.subscribe(f"{topic_base}/authA_response")
client.subscribe(f"{topic_base}/authB")
client.loop_start()

# --- Solicitar clave de sesión al Nodo C ---
solicitud = {
    "planta": planta,
    "habitacion": habitacion,
    "sensor_id": sensor_id
}
client.publish("ucisec/clave_solicitud", json.dumps(solicitud).encode())
print("[A] Solicitud de clave de sesión enviada al nodo C")

# --- Esperar clave de sesión ---
while clave_sesion is None:
    time.sleep(0.2)

# --- Iniciar autenticación A → B ---
print(f"[A] Enviando nonce A: {nonce_A.hex()}")
client.publish(f"{topic_base}/authA", encrypt_aes(clave_sesion, nonce_A))

while not autenticado:
    time.sleep(0.2)

print("\n[A] Autenticación mutua completada. Enviando datos médicos...\n")

# --- Enviar datos médicos cifrados ---
while True:
    mensaje = "TEMP:37.7°C | PULSO:76bpm | SpO2:98%"
    cifrado = encrypt_chacha20(clave_sesion, mensaje.encode())
    client.publish(f"{topic_base}/med", cifrado)
    print(f"[A] Datos enviados (ChaCha20): {mensaje}")
    time.sleep(5)
