# SecureDrop – Dokumentasi Teknis

## Deskripsi
SecureDrop adalah aplikasi web untuk enkripsi dan dekripsi berkas secara aman
menggunakan algoritma kriptografi modern berbasis AEAD.

## Algoritma yang Didukung
| Algoritma | Mode | Key | Nonce | Tag |
|---|---|---|---|---|
| AES-256 | GCM (AEAD) | 32 byte | 12 byte | 16 byte |
| ChaCha20 | Poly1305 (AEAD) | 32 byte | 12 byte | 16 byte |

## Derivasi Kunci
- Fungsi: **PBKDF2-HMAC-SHA256**
- Iterasi: **600.000**
- Salt: **16 byte (CSPRNG)**
- Output: **32 byte (256-bit key)**

## Format Berkas .sdrop
Berkas terenkripsi dikemas dalam format JSON:
```json
{
  "format": "SecureDrop",
  "version": 1,
  "mode": "password",
  "algorithm": "aes-256-gcm",
  "original_filename": "dokumen.pdf",
  "salt": "<Base64>",
  "nonce": "<Base64>",
  "ciphertext": "<Base64>",
  "tag": "<Base64>"
}
```
