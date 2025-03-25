# nodo_b.py

import paho.mqtt.client as mqtt
from utils_crypto import decrypt_aes
from utils_crypto import decrypt_chacha20  # si luego querés comparar
import base64

# Leer clave maestra y clave de sesión cifrada
with open("clave_maestra_B.bin", "rb") as f:
    master_key = f.read()

with open("clave_sesion.bin", "rb") as f:
    # Simula recibirla cifrada desde nodo C
    from utils_crypto import encrypt_aes
    clave_cifrada = encrypt_aes(master_key, f.read())

# Descifrar la clave de sesión
clave_sesion = decrypt_aes(master_key, clave_cifrada)

# Callback cuando llega un mensaje
def on_message(client, userdata, msg):
    try:
        print("\nMensaje cifrado recibido:", msg.payload.decode())
        mensaje_descifrado = decrypt_aes(clave_sesion, msg.payload)
        print(">> Mensaje descifrado:", mensaje_descifrado.decode())
    except Exception as e:
        print("Error al descifrar:", e)

# Conectarse al broker y suscribirse
broker = "localhost"
topic = "ucisec/med"

client = mqtt.Client()
client.on_message = on_message

client.connect(broker)
client.subscribe(topic)
print("Nodo B conectado y escuchando...\n")
client.loop_forever()
