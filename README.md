# SecureDrop

Aplikasi web sederhana untuk enkripsi dan dekripsi file secara aman menggunakan algoritma kriptografi modern (AES-256-GCM dan ChaCha20-Poly1305) serta enkripsi hibrida berbasis RSA-OAEP. Aplikasi ini dibuat untuk memenuhi tugas proyek mata kuliah Keamanan Informasi.

## Anggota Kelompok

1. Nabinadya Abinazzahra (247006111079)
2. Annisa Safira Wibowo (247006111101)
3. Nanda Raissa (247006111108)

## Deskripsi

SecureDrop adalah aplikasi berbasis web yang membantu pengguna mengamankan file dokumen atau gambar sebelum dibagikan. File dienkripsi langsung di memori dan dikemas ke dalam format file container `.sdrop` yang menyatukan ciphertext, metadata keamanan, dan verifikasi integritas data.

Aplikasi mendukung dua metode pengelolaan kunci:
1. **Password Biasa (Symmetric KDF)**: Kunci enkripsi diturunkan dari password/passphrase menggunakan KDF yang aman (Argon2id).
2. **Enkripsi Hibrida (Hybrid Cryptography)**: File dienkripsi menggunakan kunci sesi acak 256-bit (AES-256-GCM), lalu kunci sesi tersebut dibungkus (*key wrapping*) menggunakan Public Key RSA penerima dengan skema RSA-OAEP (SHA-256).

Fitur utama yang tersedia:

- **Encrypt & Send**: mengenkripsi file asli menjadi paket `.sdrop` menggunakan mode password (AES-256-GCM / ChaCha20-Poly1305) atau mode enkripsi hibrida (RSA-OAEP + AES-256-GCM), dilengkapi generator kunci RSA 2048-bit bawaan.
- **Receive & Decrypt**: mengembalikan paket `.sdrop` ke bentuk aslinya dengan memverifikasi password atau mengunggah Private Key RSA penerima, disertai validasi integritas (*authentication tag*).
- **Security Testing**: pengujian mandiri untuk mengukur kecepatan enkripsi, keutuhan file, entropi Shannon, dan efek avalanche (*bit-flip*).

## Cara Instalasi

Pastikan komputer sudah terpasang Python versi 3.10 ke atas.

1. Buka terminal atau Command Prompt di folder proyek ini.

2. Buat virtual environment (opsional tapi disarankan):
   ```bash
   python -m venv venv
   ```

3. Aktifkan virtual environment:
   - Windows (PowerShell):
     ```powershell
     venv\Scripts\Activate.ps1
     ```
   - Windows (CMD):
     ```cmd
     venv\Scripts\activate.bat
     ```
   - Linux / macOS:
     ```bash
     source venv/bin/activate
     ```

4. Install library yang dibutuhkan:
   ```bash
   pip install -r requirements.txt
   ```

## Cara Menjalankan

1. Jalankan server aplikasi dengan perintah:
   ```bash
   python app.py
   ```

2. Buka browser dan akses alamat berikut:
   ```
   http://127.0.0.1:5000/
   ```

3. Untuk menjalankan pengujian otomatis (unit test):
   ```bash
   pytest -v
   ```

## Contoh Penggunaan

### Contoh 1: Mengenkripsi File (Mode Password)

1. Buka menu **Encrypt & Send** di browser.
2. Pilih mode **Password Biasa (KDF)**.
3. Klik area upload atau seret file yang ingin diamankan (misalnya `laporan.pdf`).
4. Pilih algoritma enkripsi (**AES-256-GCM** atau **ChaCha20-Poly1305**).
5. Masukkan password enkripsi yang kuat.
6. Klik tombol **Encrypt**.
7. Setelah proses selesai, klik tombol **Download Paket .sdrop** untuk menyimpan file terenkripsi.

### Contoh 2: Mengenkripsi File (Mode Hibrida RSA)

1. Buka menu **Encrypt & Send** di browser.
2. Pilih mode **Enkripsi Hibrida (RSA-OAEP)**.
3. Unggah file dokumen yang ingin diamankan.
4. Masukkan Public Key RSA penerima (`.pem`) atau gunakan tombol **Generate Kunci RSA 2048-bit** jika belum memiliki pasangan kunci (file `private_key.pem` akan terunduh otomatis untuk penerima).
5. Klik tombol **Encrypt** dan unduh paket `.sdrop` yang dihasilkan.

### Contoh 3: Mendekripsi File

1. Buka menu **Receive & Decrypt**.
2. Unggah file terenkripsi (`.sdrop`).
3. Masukkan password (jika dienkripsi dengan mode password) atau unggah file Private Key RSA (`private_key.pem`) penerima (jika dienkripsi dengan mode hibrida).
4. Klik tombol **Decrypt**.
5. Jika kunci/password valid dan data belum pernah dimodifikasi, sistem akan menampilkan tombol **Download File Asli**.
