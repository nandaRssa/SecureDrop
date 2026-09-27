# SecureDrop

Aplikasi web sederhana untuk enkripsi dan dekripsi file secara aman menggunakan algoritma kriptografi modern (AES-256-GCM dan ChaCha20-Poly1305). Aplikasi ini dibuat untuk memenuhi tugas proyek mata kuliah Keamanan Informasi.

## Anggota Kelompok

1. Nabinadya Abinazzahra (247006111079)
2. Annisa Safira Wibowo (247006111101)
3. Nanda Raissa (247006111108)

## Deskripsi

SecureDrop adalah aplikasi berbasis web yang membantu pengguna mengamankan file dokumen atau gambar sebelum dibagikan. File dienkripsi langsung di memori menggunakan password dan dikemas ke dalam format file .sdrop.

Fitur utama yang tersedia:

- Encrypt & Send: mengenkripsi file asli menjadi file .sdrop dengan pilihan algoritma AES-256-GCM atau ChaCha20-Poly1305
- Receive & Decrypt: mengembalikan file .sdrop ke bentuk file aslinya dengan memverifikasi password dan keaslian data (authentication tag)
- Security Testing: pengujian mandiri untuk mengukur kecepatan enkripsi, keutuhan file, dan efek avalanche

## Cara Instalasi

Pastikan komputer sudah terpasang Python versi 3.10 ke atas.

1. Buka terminal atau Command Prompt di folder proyek ini.

2. Buat virtual environment (opsional tapi disarankan):
   python -m venv venv

3. Aktifkan virtual environment:

- Windows (PowerShell):
  venv\Scripts\Activate.ps1
- Windows (CMD):
  venv\Scripts\activate.bat
- Linux / macOS:
  source venv/bin/activate

4. Install library yang dibutuhkan:
   pip install -r requirements.txt

## Cara Menjalankan

1. Jalankan server aplikasi dengan perintah:
   python app.py

2. Buka browser dan akses alamat berikut:
   http://127.0.0.1:5000/

3. Untuk menjalankan pengujian otomatis (unit test):
   pytest -v

## Contoh Penggunaan

Contoh 1: Mengenkripsi File

1. Buka menu Encrypt & Send di browser.
2. Klik area upload atau seret file yang ingin diamankan (misalnya laporan.pdf).
3. Pilih algoritma enkripsi (AES-256-GCM atau ChaCha20-Poly1305).
4. Masukkan password enkripsi yang kuat.
5. Klik tombol Encrypt.
6. Setelah proses selesai, klik tombol Download Paket .sdrop untuk menyimpan file terenkripsi (misalnya laporan.pdf.sdrop).

Contoh 2: Mendekripsi File

1. Buka menu Receive & Decrypt.
2. Upload file terenkripsi (.sdrop).
3. Masukkan password yang sama seperti saat mengenkripsi.
4. Klik tombol Decrypt.
5. Jika password benar dan file belum pernah dimodifikasi, sistem akan menampilkan tombol Download File Asli.
