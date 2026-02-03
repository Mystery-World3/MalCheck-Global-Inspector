# 🛡️ VTReps-Inspector: Malware & URL Reputation Scanner

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![OSINT](https://img.shields.io/badge/Main%20Topic-OSINT-red.svg)]()

**VTReps-Inspector** adalah alat berbasis CLI (Command Line Interface) yang dirancang untuk melakukan inspeksi keamanan cepat terhadap file dan tautan web. Dengan memanfaatkan **VirusTotal API v3**, tool ini memberikan laporan reputasi *real-time* untuk membantu mendeteksi ancaman siber sebelum berinteraksi dengan data yang mencurigakan.

---

## 🚀 Fitur Utama
- **URL Inspection**: Memverifikasi reputasi link website menggunakan encoding Base64 yang aman.
- **File Hash Analysis**: Mengecek keamanan file melalui SHA256 hash tanpa perlu mengunggah file asli (menjaga privasi).
- **Fast Response**: Menampilkan statistik analisis (Malicious, Harmless, Suspicious) secara instan.
- **Lightweight**: Tanpa GUI yang berat, fokus pada kecepatan eksekusi di terminal.

---

## 🛠️ Persyaratan Sistem
- Python 3.8 atau versi lebih baru.
- API Key VirusTotal (Gratis tersedia di [VirusTotal Intelligence](https://www.virustotal.com/)).

---

## 📦 Instalasi

1. **Clone Repository:**
   ```bash
   git clone https://github.com/Mystery-World3/MalCheck-Global-Inspector.git
   cd MalCheck-Global-Inspector
   ```
   
2. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
2. **Konfigurasi API: Buka main.py dan masukkan API Key kamu pada variabel:**
   ```bash
   API_KEY = 'YOUR_VIRUSTOTAL_API_KEY'
   ```
## 📖 Cara Penggunaan

### Mengecek URL/Website:
```bash
python main.py -u [https://www.contoh-website.com](https://www.contoh-website.com)
```

### Mengecek SHA256 Hash:
```bash
python main.py -s 138386647253504f762a0487d602a8cf23e20ecf89f9215886d9a1050e891392
```

### Mengecek File Lokal:
```bash
python main.py -f "C:\Path\File\Aplication.exe"
```

---

## 👤 Author
**Muhammad Mishbahul Muflihin** *Software Engineering Student at Darussalam Gontor University*
<br>
 Email: [mishbahulmuflihin@gmail.com](mailto:mishbahulmuflihin@gmail.com)

