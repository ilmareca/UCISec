import os
import time
import paho.mqtt.client as mqtt
from utils_crypto import encrypt_aes, decrypt_aes, decrypt_chacha20, generar_nonce

print("[B] Iniciando Nodo B (Servidor Médico)")

# --- Rutas y claves ---
broker = "localhost"
CLAVES_PATH = "claves_por_sensor"
CLAVE_B_PATH = os.path.join(CLAVES_PATH, "clave_maestra_B.bin")

with open(CLAVE_B_PATH, "rb") as f:
    clave_maestra_B = f.read()

client = mqtt.Client()

# --- Estados por sensor ---
claves_sesion = {}    # sensor_path: clave
nonces = {}           # sensor_path: nonce_B generado
autenticados = {}     # sensor_path: True/False

# --- Extraer sensor_path del topic ---
def extraer_sensor_path(topic):
    partes = topic.split("/")
    return f"{partes[2]}_{partes[3]}_{partes[4]}"

# --- Recibir clave cifrada desde Nodo C ---
def on_clave_para_B(client, userdata, msg):
    sensor_path = extraer_sensor_path(msg.topic)
    clave_sesion = decrypt_aes(clave_maestra_B, msg.payload)
    claves_sesion[sensor_path] = clave_sesion
    print(f"[B] ✅ Clave de sesión recibida y descifrada para {sensor_path}")

    # Iniciar autenticación
    nonce_B = generar_nonce()
    nonces[sensor_path] = nonce_B
    topic_authB = f"ucisec/{sensor_path.replace('_','/')}/authB"
    client.publish(topic_authB, encrypt_aes(clave_sesion, nonce_B))
    print(f"[B] Enviando nonce B a {sensor_path} en topic {topic_authB}")

# --- Recibir nonce A y responder ---
def on_authA(client, userdata, msg):
    partes = msg.topic.split("/")
    sensor_path = f"{partes[1]}_{partes[2]}_{partes[3]}"
    clave_sesion = claves_sesion.get(sensor_path)
    if not clave_sesion:
        print(f"[B] ⚠ Clave de sesión no disponible para {sensor_path}")
        return

    nonce = decrypt_aes(clave_sesion, msg.payload)
    print(f"[B] Recibido nonce A de {sensor_path}: {nonce.hex()}")

    topic_resp = f"ucisec/{sensor_path.replace('_','/')}/authA_response"
    client.publish(topic_resp, encrypt_aes(clave_sesion, nonce))
    print(f"[B] Respuesta enviada en topic {topic_resp}")

# --- Verificar respuesta de A a nonce B ---
def on_authB_response(client, userdata, msg):
    sensor_path = extraer_sensor_path(msg.topic)
    clave_sesion = claves_sesion.get(sensor_path)
    if not clave_sesion:
        return

    respuesta = decrypt_aes(clave_sesion, msg.payload)
    if respuesta == nonces.get(sensor_path):
        print(f"[B] ✅ {sensor_path} autenticado correctamente")
        autenticados[sensor_path] = True
    else:
        print(f"[B] ❌ Error autenticando a {sensor_path}")

# --- Recibir datos médicos ---
def on_datos_med(client, userdata, msg):
    partes = msg.topic.split("/")
    sensor_path = f"{partes[1]}_{partes[2]}_{partes[3]}"    
    clave_sesion = claves_sesion.get(sensor_path)
    if not clave_sesion:
        print(f"[B] ⚠ No se puede descifrar, clave de {sensor_path} no encontrada")
        return
    try:
        mensaje = decrypt_chacha20(clave_sesion, msg.payload)
        print(f"[B] Datos médicos de {sensor_path}: {mensaje.decode()}")
    except Exception as e:
        print(f"[B] Error descifrando datos de {sensor_path}: {e}")

# --- Suscripciones y configuración MQTT ---
client.message_callback_add("ucisec/claves/+/+/+/para_B", on_clave_para_B)
client.message_callback_add("ucisec/+/+/+/authA", on_authA)
client.message_callback_add("ucisec/+/+/+/authB_response", on_authB_response)
client.message_callback_add("ucisec/+/+/+/med", on_datos_med)

client.on_message = lambda c, u, m: None

client.connect(broker)
client.subscribe("ucisec/claves/+/+/+/para_B")
client.subscribe("ucisec/+/+/+/authA")
client.subscribe("ucisec/+/+/+/authB_response")
client.subscribe("ucisec/+/+/+/med")
client.loop_start()

print("[B] Esperando mensajes de claves y sensores...")

while True:
    time.sleep(0.5)
