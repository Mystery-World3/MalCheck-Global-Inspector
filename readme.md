# 🛡️ VTReps-Inspector: Malware & URL Reputation Scanner

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![OSINT](https://img.shields.io/badge/Main%20Topic-OSINT-red.svg)]()

**VTReps-Inspector** adalah alat berbasis CLI (Command Line Interface) yang dirancang untuk melakukan inspeksi keamanan cepat terhadap file dan tautan web. Dengan memanfaatkan **VirusTotal API v3**, tool ini memberikan laporan reputasi *real-time* untuk membantu mendeteksi ancaman siber sebelum berinteraksi dengan data yang mencurigakan.

---

## 🚀 Fitur Utama
- **URL Inspection**: Memverifikasi reputasi link website menggunakan encoding Base64 yang aman.
- **File Hash Analysis**: Mengecek keamanan file melalui SHA256 hash tanpa perlu mengunggah file asli (menjaga privasi).
- **Fast Response**: Menampilkan statistik analisis (Malicious, Harmless, Suspicious) secara instan.
- **Lightweight**: Tanpa GUI yang berat, fokus pada kecepatan eksekusi di terminal.

## 🛠️ Persyaratan Sistem
- Python 3.8 atau versi lebih baru.
- API Key VirusTotal (Gratis tersedia di [VirusTotal Intelligence](https://www.virustotal.com/)).

## 📦 Instalasi

1. **Clone Repository:**
   ```bash
   git clone [https://github.com/Mystery-World3/VTReps-Inspector.git](https://github.com/Mystery-World3/VTReps-Inspector.git)
   cd VTReps-Inspector