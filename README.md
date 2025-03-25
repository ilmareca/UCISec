# MedSecureIoT

## Description

**MedSecureIoT** is a secure IoT communication system designed for critical healthcare environments, such as Intensive Care Units (ICUs). It simulates a network of medical sensors and servers where patient data is encrypted, authenticated, and transmitted using lightweight symmetric cryptographic algorithms.

### Features
- Symmetric encryption with **AES** (block cipher) and **ChaCha20** (stream cipher)
- Key establishment through a **trusted third-party node**
- **Mutual authentication** protocol between sensor and server
- **MQTT** communication for real-time data exchange
- Performance analysis of the cryptographic algorithms

---

## Descripción (Español)

**MedSecureIoT** es un sistema de comunicación IoT seguro, orientado a entornos sanitarios críticos como las Unidades de Cuidados Intensivos (UCI). Simula una red de sensores médicos y servidores, donde los datos del paciente son cifrados, autenticados y transmitidos utilizando algoritmos criptográficos simétricos ligeros.

### Funcionalidades
- Cifrado simétrico con **AES** (bloque) y **ChaCha20** (flujo)
- Establecimiento de claves mediante un **tercero de confianza**
- Protocolo de **autenticación mutua** entre los nodos
- Comunicación en tiempo real mediante **MQTT**
- Análisis de rendimiento de los algoritmos criptográficos

---

## Installation

```bash
pip install cryptography paho-mqtt
