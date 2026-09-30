-- SecureDrop: Contoh data sensitif yang perlu dienkripsi sebelum disimpan
-- Ini adalah contoh plaintext yang harus TIDAK disimpan langsung ke database

CREATE TABLE IF NOT EXISTS pengguna_sensitif (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    nama_lengkap TEXT NOT NULL,
    nik_encrypted TEXT NOT NULL,   -- NIK dienkripsi AES-256-GCM sebelum INSERT
    rekening_encrypted TEXT,       -- No. rekening dienkripsi
    salt         TEXT NOT NULL,    -- PBKDF2 salt (Base64)
    nonce        TEXT NOT NULL,    -- Nonce enkripsi (Base64)
    tag          TEXT NOT NULL,    -- Auth tag (Base64)
    algoritma    TEXT DEFAULT 'AES-256-GCM',
    dibuat_pada  DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Contoh query INSERT (nilai NIK sudah dalam bentuk ciphertext):
-- INSERT INTO pengguna_sensitif (nama_lengkap, nik_encrypted, salt, nonce, tag)
-- VALUES ('Nabinadya A.', 'BASE64_CIPHERTEXT_DISINI', 'BASE64_SALT', 'BASE64_NONCE', 'BASE64_TAG');
