# SecureDrop

SecureDrop adalah aplikasi keamanan informasi dan enkripsi file berbasis web yang dirancang menggunakan prinsip kriptografi modern. Aplikasi ini berfokus pada penyediaan enkripsi authenticated cipher modern (**AES-256-GCM** dan **ChaCha20-Poly1305**) untuk menjamin aspek kerahasiaan (*confidentiality*) dan keutuhan data (*integrity*).

Proyek ini merupakan implementasi Tugas Proyek Mata Kuliah **Keamanan Informasi — Topik A: Aplikasi Enkripsi (Algoritma Modern)**.

---

## Anggota Kelompok & Pembagian Peran

* **Nama Anggota 1 — NPM** (Orang 1 — Core Encryption + Encrypt & Send)
* **Nama Anggota 2 — NPM** (Orang 2 — Receive & Decrypt)
* **Nama Anggota 3 — NPM** (Orang 3 — Security Testing & Analysis)

---

## Teknologi yang Digunakan

* **Backend**: Python 3.10+, Flask
* **Template Engine**: Jinja2
* **Frontend**: HTML5, Vanilla CSS (Design System), JavaScript
* **Testing Framework**: pytest
* **Version Control**: Git & GitHub

---

## Struktur Aplikasi

```text
SecureDrop/
├── app.py                  # Entry point aplikasi Flask
├── crypto/                 # Modul Core Encryption (Orang 1)
│   └── __init__.py
├── routes/                 # Blueprint & Route handler
│   ├── __init__.py
│   └── main.py
├── templates/              # Jinja2 HTML Templates
│   ├── base.html           # Layout dasar & navigasi
│   ├── encrypt.html        # Halaman Encrypt & Send
│   ├── decrypt.html        # Placeholder Receive & Decrypt (Tahap 2)
│   └── testing.html        # Placeholder Security Testing (Tahap 3)
├── static/                 # Aset Frontend
│   ├── css/
│   │   └── style.css       # Design System & Styling
│   └── js/
│       └── app.js          # Interaktivitas UI & Pratinjau
├── tests/                  # Unit Test Suite
│   ├── __init__.py
│   └── test_app.py         # 5 Pengujian Route & Inisialisasi
├── .gitignore              # Proteksi file rahasia & cache
├── pytest.ini              # Konfigurasi pytest
├── requirements.txt        # Dependensi dasar
└── README.md               # Dokumentasi proyek
```

---

## Panduan Instalasi & Menjalankan Aplikasi

### 1. Setup Virtual Environment (Rekomendasi)
```bash
# Membuat virtual environment
python -m venv venv

# Mengaktifkan di Windows (PowerShell):
venv\Scripts\Activate.ps1

# Atau Windows (CMD):
venv\Scripts\activate.bat

# Linux / macOS:
source venv/bin/activate
```

### 2. Install Dependensi
```bash
pip install -r requirements.txt
```

### 3. Menjalankan Server Flask
```bash
python app.py
```
Aplikasi akan berjalan di `http://127.0.0.1:5000/`. Buka alamat tersebut melalui web browser.

### 4. Menjalankan Unit Test (pytest)
```bash
pytest -v
```

---

## Ketentuan & Keamanan Proyek

1. **Proteksi Kunci/Secret**: Kunci, password, dan secret tidak ditulis langsung (*hardcode*) di source code maupun diunggah ke GitHub.
2. **CSPRNG**: Pembangkit bilangan acak wajib menggunakan generator yang aman secara kriptografis (`secrets` / `os.urandom`) pada tahap implementasi kriptografi.
3. **Algoritma Terlarang**: Mode ECB dan algoritma usang (MD5, SHA-1, DES, RC4) tidak digunakan untuk fitur keamanan utama.
