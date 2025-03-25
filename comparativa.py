# comparativa.py

from utils_crypto import encrypt_aes, decrypt_aes, encrypt_chacha20, decrypt_chacha20
import os
import time

key = os.urandom(32)
mensaje = "TEMP:37.2C | PULSO:75bpm | SpO2:97%".encode()

print("\n--- COMPARATIVA DE CIFRADO SIMÉTRICO ---")
print(f"Mensaje original: {mensaje.decode()}\n")

def benchmark_repeat(fn_encrypt, fn_decrypt, key, mensaje, repeticiones=100):
    tiempos_enc = []
    tiempos_dec = []
    resultado = b""

    for _ in range(repeticiones):
        inicio = time.perf_counter()
        cifrado = fn_encrypt(key, mensaje)
        tiempos_enc.append((time.perf_counter() - inicio) * 1000)

        inicio = time.perf_counter()
        resultado = fn_decrypt(key, cifrado)
        tiempos_dec.append((time.perf_counter() - inicio) * 1000)

    return round(sum(tiempos_enc) / repeticiones, 4), round(sum(tiempos_dec) / repeticiones, 4), resultado

# AES
t_enc_aes, t_dec_aes, resultado_aes = benchmark_repeat(encrypt_aes, decrypt_aes, key, mensaje)

# ChaCha20
t_enc_chacha, t_dec_chacha, resultado_chacha = benchmark_repeat(encrypt_chacha20, decrypt_chacha20, key, mensaje)

print("AES:")
print(f"  Tiempo medio de cifrado:   {t_enc_aes} ms")
print(f"  Tiempo medio de descifrado:{t_dec_aes} ms")
print(f"  Resultado:                  {resultado_aes.decode()}")

print("\nChaCha20:")
print(f"  Tiempo medio de cifrado:   {t_enc_chacha} ms")
print(f"  Tiempo medio de descifrado:{t_dec_chacha} ms")
print(f"  Resultado:                  {resultado_chacha.decode()}")
