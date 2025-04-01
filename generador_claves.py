import os
from Crypto.Random import get_random_bytes
from utils_crypto import encrypt_aes

CARPETA_DEFECTO = "claves_generadas"
CARPETA_CLAVES_MAESTRAS = "claves_por_sensor"

# --- Datos del sensor ---
planta = input("Introduce la planta: ").strip()
habitacion = input("Introduce la habitación: ").strip()
sensor_id = input("Introduce el ID del sensor: ").strip()

nombre_clave = f"{planta}_{habitacion}_{sensor_id}"
os.makedirs(CARPETA_DEFECTO, exist_ok=True)
os.makedirs(CARPETA_CLAVES_MAESTRAS, exist_ok=True)

# --- Ruta de guardado de la clave de sesión ---
ruta_guardado = input(f"Ruta para guardar la clave de sesión (ENTER = '{CARPETA_DEFECTO}/'): ").strip()
if ruta_guardado == "":
    ruta_guardado = CARPETA_DEFECTO

# --- Generar clave de sesión ---
clave_sesion = get_random_bytes(32)
print(f"\n[✔] Clave de sesión generada: {clave_sesion.hex()}")

# --- Preguntar si se cifra con clave maestra ---
cifrar = input("\n¿Deseas cifrar la clave con una clave maestra? (s/n): ").strip().lower() == "s"

if cifrar:
    ruta_maestra = input(f"Ruta del archivo de clave maestra (ENTER = autogenerar en '{CARPETA_CLAVES_MAESTRAS}/'): ").strip()
    if ruta_maestra == "":
        ruta_maestra = os.path.join(CARPETA_CLAVES_MAESTRAS, f"{nombre_clave}_maestra.bin")

    if not os.path.exists(ruta_maestra):
        crear = input(f"La clave maestra no existe. ¿Deseas generarla en '{ruta_maestra}'? (s/n): ").strip().lower()
        if crear == "s":
            clave_maestra = get_random_bytes(32)
            os.makedirs(os.path.dirname(ruta_maestra), exist_ok=True)
            with open(ruta_maestra, "wb") as f:
                f.write(clave_maestra)
            print(f"[✔] Clave maestra creada en: {ruta_maestra}")
        else:
            print("[✘] Operación cancelada.")
            exit(1)
    else:
        with open(ruta_maestra, "rb") as f:
            clave_maestra = f.read()

    # --- Cifrar y guardar clave de sesión ---
    clave_cifrada = encrypt_aes(clave_maestra, clave_sesion)
    archivo_sesion = os.path.join(ruta_guardado, f"{nombre_clave}_cifrada.bin")
    with open(archivo_sesion, "wb") as f:
        f.write(clave_cifrada)
    print(f"[✔] Clave cifrada guardada en: {archivo_sesion}")

else:
    archivo_sesion = os.path.join(ruta_guardado, f"{nombre_clave}_en_claro.bin")
    with open(archivo_sesion, "wb") as f:
        f.write(clave_sesion)
    print(f"[✔] Clave en claro guardada en: {archivo_sesion}")
