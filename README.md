# University_Final-Year_Project


# 🛡️ Multi-Layered Automotive RKE Security System
### **ESP32 + CC1101 | AES-128 | TOTP | Rolling Codes**

This repository contains the implementation of a high-security Remote Keyless Entry (RKE) system designed to neutralize common wireless automotive vulnerabilities. By combining **AES-128 encryption**, **RFC 6238 (TOTP)**, and **Rolling Codes**, the system ensures every signal is sequence-unique and time-sensitive.

---

## ⚠️ The Problem: Traditional Vulnerabilities
Standard automotive RKE systems (like KeeLoq) rely on simple rolling codes. While these prevent basic duplication, they lack **"Time-Freshness,"** making them susceptible to:

* **Replay Attack:** Capturing a valid RF signal and replaying it later to gain unauthorized access.
* **RollJam Attack:** Jamming the receiver while sniffing the signal to steal an "unused" rolling code.

### 🎥 Demonstration: Traditional Replay Attack
In this video, I demonstrate how a traditional car's security can be bypassed using simple sub-GHz tools before applying our multi-layer defense.



---

## 🚀 Our Solution: The Triple-Layer Defense
To mitigate these attacks, this project implements a 3-tier validation process:

1.  **AES-128 (Privacy):** The entire 34-byte payload is encrypted. No plain-text IDs are sent over the air.
2.  **Rolling Codes (Sequence):** A 32-bit counter increments per press, validated against a 256-step window.
3.  **TOTP (Time):** A 6-digit code that changes every **5 seconds**. Even a perfectly captured signal expires before it can be replayed.

---

## 🔌 Hardware & Wiring
The system consists of a **Keyfob (Transmitter)** and a **Car (Receiver)** using ESP32 MCUs and CC1101 modules.



### **Peripheral Connections**
* **Keyfob:** Buttons on **GPIO 25** (Unlock) and **GPIO 26** (Lock).
* **Car Receiver:** LEDs on **GPIO 16** (Green/Unlock) and **GPIO 17** (Red/Lock).
