import os
import json
import paho.mqtt.client as mqtt
from utils_crypto import encrypt_aes
from Crypto.Random import get_random_bytes

# MQTT broker
broker = "localhost"
client = mqtt.Client()

# Rutas
CLAVES_MAESTRAS_PATH = "claves_por_sensor"
CLAVE_B_PATH = os.path.join(CLAVES_MAESTRAS_PATH, "clave_maestra_B.bin")

# Cargar clave maestra del servidor médico
with open(CLAVE_B_PATH, "rb") as f:
    clave_maestra_B = f.read()

# --- Gestionar solicitud de clave ---
def on_solicitud_clave(client, userdata, msg):
    try:
        datos = json.loads(msg.payload.decode())
        planta = datos["planta"]
        habitacion = datos["habitacion"]
        sensor_id = datos["sensor_id"]
        sensor_path = f"{planta}_{habitacion}_{sensor_id}"

        print(f"[C] Solicitud recibida de {sensor_path}")

        # Cargar clave maestra del sensor
        clave_A_path = os.path.join(CLAVES_MAESTRAS_PATH, f"{sensor_path}_maestra.bin")
        if not os.path.exists(clave_A_path):
            print(f"[C] ⚠ No existe clave maestra para {sensor_path}")
            return

        with open(clave_A_path, "rb") as f:
            clave_maestra_A = f.read()

        # Generar nueva clave de sesión
        clave_sesion = get_random_bytes(32)

        # Cifrar con claves maestras
        clave_para_A = encrypt_aes(clave_maestra_A, clave_sesion)
        clave_para_B = encrypt_aes(clave_maestra_B, clave_sesion)

        # Publicar las claves
        base_topic = f"ucisec/claves/{planta}/{habitacion}/{sensor_id}"
        client.publish(f"{base_topic}/para_A", clave_para_A)
        client.publish(f"{base_topic}/para_B", clave_para_B)

        print(f"[C] Clave de sesión enviada a {base_topic}/para_A y para_B")

    except Exception as e:
        print(f"[C] ❌ Error procesando solicitud: {e}")

# --- MQTT setup ---
client.message_callback_add("ucisec/clave_solicitud", on_solicitud_clave)
client.on_message = lambda c, u, m: None
client.connect(broker)
client.subscribe("ucisec/clave_solicitud")
client.loop_forever()
