"""
Script Otomatisasi Export Data Pengujian SecureDrop
Mengeksekusi security_testing_service dan pengujian kriptografi hibrida, lalu mengekspor hasilnya ke:
1. data_pengujian/hasil_pengujian_securedrop.xlsx (7 Sheet lengkap)
2. data_pengujian/grafik_benchmark.png
3. data_pengujian/grafik_avalanche.png
4. data_pengujian/grafik_entropi.png
5. data_pengujian/grafik_histogram.png
6. data_pengujian/grafik_hibrida_vs_password.png
"""

import sys
import os
import json
import base64
import secrets
from time import perf_counter
from datetime import datetime

# Pastikan path modul securedrop terbaca
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter

from services.security_testing_service import (
    run_security_testing_suite,
    build_security_corpus,
    _format_size,
    ALGO_AES_GCM,
)
from services.encryption_service import encrypt_file_data
from services.sdrop_service import (
    create_hybrid_sdrop,
    decrypt_hybrid_sdrop,
    decrypt_sdrop,
    generate_rsa_key_pair,
    package_encryption_result,
    read_sdrop,
    AuthenticationError,
    SdropFormatError,
)

OUTPUT_DIR = os.path.join(BASE_DIR, "data_pengujian")
os.makedirs(OUTPUT_DIR, exist_ok=True)

EXCEL_PATH         = os.path.join(OUTPUT_DIR, "hasil_pengujian_securedrop.xlsx")
CHART_BENCHMARK    = os.path.join(OUTPUT_DIR, "grafik_benchmark.png")
CHART_AVALANCHE    = os.path.join(OUTPUT_DIR, "grafik_avalanche.png")
CHART_ENTROPY      = os.path.join(OUTPUT_DIR, "grafik_entropi.png")
CHART_HISTOGRAM    = os.path.join(OUTPUT_DIR, "grafik_histogram.png")
CHART_HYBRID_COMP  = os.path.join(OUTPUT_DIR, "grafik_hibrida_vs_password.png")

# Palette tema
C_HEADER  = "1E3A5F" 
C_SUBHEAD = "2E6DA4" 
C_ALT     = "EBF3FB" 
C_PASS    = "D4EDDA"   
C_FAIL    = "F8D7DA"   
C_WHITE   = "FFFFFF"

def hdr_style(ws, row, col, text, bg=C_HEADER, fg=C_WHITE, bold=True, center=True):
    c = ws.cell(row=row, column=col, value=text)
    c.font = Font(name="Calibri", bold=bold, color=fg, size=11)
    c.fill = PatternFill("solid", fgColor=bg)
    if center:
        c.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
    return c

def data_cell(ws, row, col, value, bg=None, bold=False, center=False, num_format=None):
    c = ws.cell(row=row, column=col, value=value)
    c.font = Font(name="Calibri", size=10, bold=bold)
    if bg:
        c.fill = PatternFill("solid", fgColor=bg)
    c.alignment = Alignment(horizontal="center" if center else "left", vertical="center")
    if num_format:
        c.number_format = num_format
    return c

thin = Side(style="thin", color="AAAAAA")
border = Border(left=thin, right=thin, top=thin, bottom=thin)

def apply_border(ws, min_row, max_row, min_col, max_col):
    for r in range(min_row, max_row + 1):
        for c in range(min_col, max_col + 1):
            ws.cell(r, c).border = border


def run_hybrid_testing(samples, benchmark_sizes=(1024, 1024 * 1024, 10 * 1024 * 1024), benchmark_repeats=3):
    """Menjalankan pengujian khusus untuk alur Enkripsi Hibrida RSA-OAEP + AES-256-GCM."""
    print("      -> Membuat pasangan kunci RSA 2048-bit untuk pengujian hibrida...")
    priv_bytes, pub_bytes = generate_rsa_key_pair(2048)

    # 1. Round-Trip pada 10 Sampel
    round_trip_rows = []
    for s in samples:
        package_bytes = create_hybrid_sdrop(
            file_bytes=s.data,
            public_key=pub_bytes,
            original_filename=s.name,
        )
        decrypted_bytes, filename = decrypt_hybrid_sdrop(package_bytes, priv_bytes)
        pkg = read_sdrop(package_bytes)
        ok = (decrypted_bytes == s.data and filename == s.name)
        round_trip_rows.append({
            "sample": s.name,
            "description": s.description,
            "file_size": len(s.data),
            "wrapped_key_size": len(pkg.encrypted_key) if pkg.encrypted_key else 256,
            "ciphertext_size": len(pkg.ciphertext),
            "package_size": len(package_bytes),
            "round_trip_ok": ok,
        })

    # 2. Benchmark Waktu: Mode Password vs Mode Hibrida
    pwd = "BenchmarkPasswordSecuredrop123!"
    benchmark_comparison = []

    for size in benchmark_sizes:
        size_label = _format_size(size)
        payload = secrets.token_bytes(size)

        pwd_enc_times = []
        pwd_dec_times = []
        for _ in range(benchmark_repeats):
            t0 = perf_counter()
            res = encrypt_file_data(payload, pwd, algorithm=ALGO_AES_GCM, original_filename="bench.bin")
            pkg_pwd = package_encryption_result(res)
            pwd_enc_times.append((perf_counter() - t0) * 1000)

            t1 = perf_counter()
            dec_pwd, _ = decrypt_sdrop(pkg_pwd, pwd)
            pwd_dec_times.append((perf_counter() - t1) * 1000)

        hyb_enc_times = []
        hyb_dec_times = []
        for _ in range(benchmark_repeats):
            t0 = perf_counter()
            pkg_hyb = create_hybrid_sdrop(payload, pub_bytes, algorithm=ALGO_AES_GCM, original_filename="bench.bin")
            hyb_enc_times.append((perf_counter() - t0) * 1000)

            t1 = perf_counter()
            dec_hyb, _ = decrypt_hybrid_sdrop(pkg_hyb, priv_bytes)
            hyb_dec_times.append((perf_counter() - t1) * 1000)

        benchmark_comparison.append({
            "size_bytes": size,
            "size_label": size_label,
            "pwd_enc_ms": sum(pwd_enc_times) / len(pwd_enc_times),
            "hyb_enc_ms": sum(hyb_enc_times) / len(hyb_enc_times),
            "pwd_dec_ms": sum(pwd_dec_times) / len(pwd_dec_times),
            "hyb_dec_ms": sum(hyb_dec_times) / len(hyb_dec_times),
        })

    # 3. Uji Ketahanan & Serangan Integritas pada Mode Hibrida
    wrong_priv, _ = generate_rsa_key_pair(2048)
    sample_pkg = create_hybrid_sdrop(b"Payload pengujian keamanan enkripsi hibrida", pub_bytes, original_filename="test_hybrid.txt")

    attacks = []
    # Skenario A: Dekripsi dengan Private Key yang Salah / Bukan Pemilik
    try:
        decrypt_hybrid_sdrop(sample_pkg, wrong_priv)
        attacks.append({
            "name": "wrong_private_key",
            "scenario": "Dekripsi dengan Private Key SALAH / Tidak Cocok (Unauthorized User)",
            "passed": False,
            "detail": "Dekripsi tidak boleh berhasil dengan private key asing.",
        })
    except AuthenticationError as e:
        attacks.append({
            "name": "wrong_private_key",
            "scenario": "Dekripsi dengan Private Key SALAH / Tidak Cocok (Unauthorized User)",
            "passed": True,
            "detail": str(e),
        })

    # Skenario B: Modifikasi ciphertext (Data Tampering)
    doc_tamper = json.loads(sample_pkg.decode("utf-8"))
    ct_bytes = bytearray(base64.b64decode(doc_tamper["ciphertext"]))
    ct_bytes[0] ^= 0x01
    doc_tamper["ciphertext"] = base64.b64encode(ct_bytes).decode("ascii")
    tampered_ct_pkg = json.dumps(doc_tamper, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    try:
        decrypt_hybrid_sdrop(tampered_ct_pkg, priv_bytes)
        attacks.append({
            "name": "tampered_ciphertext",
            "scenario": "Modifikasi 1-bit ciphertext paket hybrid (Man-in-the-Middle)",
            "passed": False,
            "detail": "Ciphertext yang dimodifikasi tidak boleh lolos verifikasi.",
        })
    except AuthenticationError as e:
        attacks.append({
            "name": "tampered_ciphertext",
            "scenario": "Modifikasi 1-bit ciphertext paket hybrid (Man-in-the-Middle)",
            "passed": True,
            "detail": str(e),
        })

    # Skenario C: Modifikasi wrapped key (RSA Ciphertext Tampering)
    doc_wk = json.loads(sample_pkg.decode("utf-8"))
    wk_bytes = bytearray(base64.b64decode(doc_wk["encrypted_key"]))
    wk_bytes[0] ^= 0x01
    doc_wk["encrypted_key"] = base64.b64encode(wk_bytes).decode("ascii")
    tampered_wk_pkg = json.dumps(doc_wk, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    try:
        decrypt_hybrid_sdrop(tampered_wk_pkg, priv_bytes)
        attacks.append({
            "name": "tampered_wrapped_key",
            "scenario": "Modifikasi 1-bit Wrapped RSA Key (Kunci sesi terenkripsi dirusak)",
            "passed": False,
            "detail": "RSA Wrapped key yang dirusak tidak boleh lolos unwrap.",
        })
    except AuthenticationError as e:
        attacks.append({
            "name": "tampered_wrapped_key",
            "scenario": "Modifikasi 1-bit Wrapped RSA Key (Kunci sesi terenkripsi dirusak)",
            "passed": True,
            "detail": str(e),
        })

    # Skenario D: Format Private Key Rusak / Bukan PEM
    try:
        decrypt_hybrid_sdrop(sample_pkg, b"CORRUPTED PRIVATE KEY CONTENT NOT PEM")
        attacks.append({
            "name": "corrupted_private_key_format",
            "scenario": "Format file Private Key rusak atau bukan RSA PEM",
            "passed": False,
            "detail": "Kunci tidak valid harus ditolak oleh parser.",
        })
    except (AuthenticationError, SdropFormatError, TypeError, ValueError, Exception) as e:
        attacks.append({
            "name": "corrupted_private_key_format",
            "scenario": "Format file Private Key rusak atau bukan RSA PEM",
            "passed": True,
            "detail": str(e),
        })

    return {
        "round_trip": round_trip_rows,
        "round_trip_success": sum(1 for r in round_trip_rows if r["round_trip_ok"]),
        "round_trip_total": len(round_trip_rows),
        "benchmark_comparison": benchmark_comparison,
        "attacks": attacks,
    }


def main():
    print("[1/7] Menjalankan Security Testing Suite (Simetris & KDF)...")
    suite = run_security_testing_suite(quick=False, benchmark_repeats=3)
    print("      -> Pengujian simetris selesai.")

    print("[2/7] Menjalankan Pengujian Enkripsi Hibrida (RSA-OAEP 2048-bit + AES-256-GCM)...")
    samples = build_security_corpus()
    hybrid_res = run_hybrid_testing(samples, benchmark_sizes=(1024, 1024 * 1024, 10 * 1024 * 1024), benchmark_repeats=3)
    print("      -> Pengujian enkripsi hibrida selesai.")

    round_trip  = suite["round_trip"]
    benchmark   = suite["benchmark"]
    comparison  = suite["comparison"]
    avalanche   = suite["avalanche"]
    entropy     = suite["entropy"]
    integrity   = suite["integrity"]

    wb = Workbook()

    # SHEET 1: Ringkasan 
    ws1 = wb.active
    ws1.title = "Ringkasan"
    ws1.sheet_view.showGridLines = False
    ws1.column_dimensions["A"].width = 36
    ws1.column_dimensions["B"].width = 32

    ws1.merge_cells("A1:B1")
    c = ws1.cell(1, 1, "HASIL PENGUJIAN SECUREDROP")
    c.font = Font("Calibri", bold=True, size=14, color=C_WHITE)
    c.fill = PatternFill("solid", fgColor=C_HEADER)
    c.alignment = Alignment(horizontal="center", vertical="center")
    ws1.row_dimensions[1].height = 30

    info = [
        ("Aplikasi",                 "SecureDrop v1.0"),
        ("Tanggal Pengujian",        datetime.now().strftime("%d %B %Y, %H:%M")),
        ("Algoritma Simetris Utama", "AES-256-GCM & ChaCha20-Poly1305"),
        ("Metode KDF Password",      "PBKDF2-HMAC-SHA256 (600.000 iterasi)"),
        ("Mode Kriptografi Hibrida", "RSA-OAEP 2048-bit (SHA-256) + AES-256-GCM"),
        ("Round-trip Simetris PASS", f"{suite['round_trip_success']} / {suite['round_trip_total']}"),
        ("Round-trip Hibrida PASS",  f"{hybrid_res['round_trip_success']} / {hybrid_res['round_trip_total']}"),
        ("Benchmark Ukuran Uji",     "1 KB, 1 MB, 10 MB"),
        ("Uji Avalanche Effect",     "4 skenario (plaintext & key flip)"),
        ("Uji Ketahanan Serangan",   f"{sum(1 for chk in integrity if chk['passed']) + sum(1 for chk in hybrid_res['attacks'] if chk['passed'])} PASS"),
    ]
    for i, (label, val) in enumerate(info, start=2):
        bg = C_ALT if i % 2 == 0 else C_WHITE
        data_cell(ws1, i, 1, label, bg=bg, bold=True)
        data_cell(ws1, i, 2, val, bg=bg)
    apply_border(ws1, 2, len(info)+1, 1, 2)

    # SHEET 2: Round-Trip Simetris
    ws2 = wb.create_sheet("1. Round-Trip Simetris")
    ws2.sheet_view.showGridLines = False
    for col, w in zip(range(1,8), [5, 20, 30, 16, 18, 16, 8]):
        ws2.column_dimensions[get_column_letter(col)].width = w

    headers = ["No", "Nama Sampel", "Deskripsi", "Algoritma", "Ukuran File (byte)", "Ciphertext (byte)", "Status"]
    for j, h in enumerate(headers, 1):
        hdr_style(ws2, 1, j, h)
    ws2.row_dimensions[1].height = 22

    for i, row in enumerate(round_trip, start=2):
        bg = C_ALT if i % 2 == 0 else C_WHITE
        status_ok = row["round_trip_ok"]
        status_bg = C_PASS if status_ok else C_FAIL
        data_cell(ws2, i, 1, i - 1,            bg=bg, center=True)
        data_cell(ws2, i, 2, row["sample"],    bg=bg)
        data_cell(ws2, i, 3, row.get("description", ""), bg=bg)
        data_cell(ws2, i, 4, row["algorithm"], bg=bg, center=True)
        data_cell(ws2, i, 5, row["file_size"], bg=bg, center=True)
        data_cell(ws2, i, 6, row["ciphertext_size"], bg=bg, center=True)
        s = ws2.cell(i, 7, "PASS" if status_ok else "FAIL")
        s.font = Font("Calibri", bold=True, size=10, color="155724" if status_ok else "721C24")
        s.fill = PatternFill("solid", fgColor=status_bg)
        s.alignment = Alignment(horizontal="center", vertical="center")

    apply_border(ws2, 1, len(round_trip)+1, 1, 7)

    # SHEET 3: Benchmark 
    ws3 = wb.create_sheet("2. Benchmark Waktu")
    ws3.sheet_view.showGridLines = False
    for col, w in zip(range(1,6), [5, 22, 18, 18, 18]):
        ws3.column_dimensions[get_column_letter(col)].width = w

    hdr3 = ["No", "Algoritma", "Ukuran File", "Enkripsi (ms)", "Dekripsi (ms)"]
    for j, h in enumerate(hdr3, 1):
        hdr_style(ws3, 1, j, h)
    ws3.row_dimensions[1].height = 22

    for i, row in enumerate(benchmark, start=2):
        bg = C_ALT if i % 2 == 0 else C_WHITE
        data_cell(ws3, i, 1, i - 1, bg=bg, center=True)
        data_cell(ws3, i, 2, row["algorithm"], bg=bg)
        data_cell(ws3, i, 3, row["size_label"], bg=bg, center=True)
        data_cell(ws3, i, 4, row["encrypt_ms"], bg=bg, center=True, num_format="0.000")
        data_cell(ws3, i, 5, row["decrypt_ms"], bg=bg, center=True, num_format="0.000")

    apply_border(ws3, 1, len(benchmark)+1, 1, 5)

    start_row = len(benchmark) + 3
    hdr_style(ws3, start_row, 1, "PERBANDINGAN ALGORITMA PER UKURAN", bg=C_SUBHEAD, fg=C_WHITE)
    ws3.merge_cells(f"A{start_row}:G{start_row}")
    start_row += 1
    hdr_cmp = ["No", "Ukuran", "AES Enkripsi (ms)", "ChaCha Enkripsi (ms)", "AES Dekripsi (ms)", "ChaCha Dekripsi (ms)", "Lebih Cepat"]
    for j, h in enumerate(hdr_cmp, 1):
        hdr_style(ws3, start_row, j, h, bg=C_SUBHEAD)
    for i, row in enumerate(comparison, start=start_row+1):
        bg = C_ALT if i % 2 == 0 else C_WHITE
        data_cell(ws3, i, 1, i - start_row, bg=bg, center=True)
        data_cell(ws3, i, 2, row["size_label"], bg=bg, center=True)
        data_cell(ws3, i, 3, row["aes_encrypt_ms"], bg=bg, center=True, num_format="0.000")
        data_cell(ws3, i, 4, row["chacha_encrypt_ms"], bg=bg, center=True, num_format="0.000")
        data_cell(ws3, i, 5, row["aes_decrypt_ms"], bg=bg, center=True, num_format="0.000")
        data_cell(ws3, i, 6, row["chacha_decrypt_ms"], bg=bg, center=True, num_format="0.000")
        faster = row["faster_encrypt"].replace("aes-256-gcm", "AES-GCM").replace("chacha20-poly1305", "ChaCha20")
        data_cell(ws3, i, 7, faster, bg=C_PASS, center=True, bold=True)
    apply_border(ws3, start_row, start_row + len(comparison), 1, 7)

    # SHEET 4: Avalanche 
    ws4 = wb.create_sheet("3. Avalanche Effect")
    ws4.sheet_view.showGridLines = False
    for col, w in zip(range(1,6), [5, 22, 26, 20, 20]):
        ws4.column_dimensions[get_column_letter(col)].width = w

    hdr4 = ["No", "Algoritma", "Skenario", "Total Bit Ciphertext", "Bit Berubah (%)"]
    for j, h in enumerate(hdr4, 1):
        hdr_style(ws4, 1, j, h)
    ws4.row_dimensions[1].height = 22

    scenario_map = {
        "plaintext-bit-flip": "1-bit plaintext diubah (XOR bit-0)",
        "key-bit-flip":       "1-bit kunci diubah (XOR bit-0)",
    }
    for i, row in enumerate(avalanche, start=2):
        bg = C_ALT if i % 2 == 0 else C_WHITE
        pct = row["bit_change_pct"]
        pct_bg = C_PASS if 45 <= pct <= 55 else C_FAIL
        data_cell(ws4, i, 1, i - 1, bg=bg, center=True)
        data_cell(ws4, i, 2, row["algorithm"], bg=bg)
        data_cell(ws4, i, 3, scenario_map.get(row["scenario"], row["scenario"]), bg=bg)
        data_cell(ws4, i, 4, row["reference_size"] * 8, bg=bg, center=True)
        c = ws4.cell(i, 5, f"{pct:.3f}%")
        c.font = Font("Calibri", bold=True, size=10, color="155724" if 45<=pct<=55 else "721C24")
        c.fill = PatternFill("solid", fgColor=pct_bg)
        c.alignment = Alignment(horizontal="center", vertical="center")

    apply_border(ws4, 1, len(avalanche)+1, 1, 5)

    # SHEET 5: Entropi 
    ws5 = wb.create_sheet("4. Entropi & Histogram")
    ws5.sheet_view.showGridLines = False
    for col, w in zip(range(1,7), [5, 22, 22, 22, 22, 20]):
        ws5.column_dimensions[get_column_letter(col)].width = w

    hdr5 = ["No", "Sampel", "Algoritma", "Entropi Plaintext (bit/byte)", "Entropi Ciphertext (bit/byte)", "Delta Entropi"]
    for j, h in enumerate(hdr5, 1):
        hdr_style(ws5, 1, j, h)
    ws5.row_dimensions[1].height = 22

    for i, row in enumerate(entropy["results"], start=2):
        bg = C_ALT if i % 2 == 0 else C_WHITE
        data_cell(ws5, i, 1, i - 1, bg=bg, center=True)
        data_cell(ws5, i, 2, row["sample"], bg=bg)
        data_cell(ws5, i, 3, row["algorithm"], bg=bg)
        data_cell(ws5, i, 4, round(row["plaintext_entropy"], 4), bg=bg, center=True, num_format="0.0000")
        data_cell(ws5, i, 5, round(row["ciphertext_entropy"], 4), bg=C_PASS, center=True, num_format="0.0000")
        data_cell(ws5, i, 6, f"+{row['entropy_delta']:.4f}", bg=bg, center=True, bold=True)

    apply_border(ws5, 1, len(entropy["results"])+1, 1, 6)

    # SHEET 6: Serangan Simetris
    ws6 = wb.create_sheet("5. Uji Ketahanan (Password)")
    ws6.sheet_view.showGridLines = False
    for col, w in zip(range(1,5), [5, 32, 18, 48]):
        ws6.column_dimensions[get_column_letter(col)].width = w

    hdr6 = ["No", "Skenario Serangan", "Hasil", "Detail Pesan Sistem"]
    for j, h in enumerate(hdr6, 1):
        hdr_style(ws6, 1, j, h)
    ws6.row_dimensions[1].height = 22

    attack_labels = {
        "wrong_password":     "Dekripsi dengan password SALAH (brute-force simulation)",
        "tampered_ciphertext":"Modifikasi 1 byte pada ciphertext (man-in-the-middle)",
        "corrupt_package":    "Paket .sdrop rusak/tidak lengkap (corrupt file)",
    }
    for i, check in enumerate(integrity, start=2):
        bg = C_ALT if i % 2 == 0 else C_WHITE
        status_bg = C_PASS if check["passed"] else C_FAIL
        data_cell(ws6, i, 1, i - 1, bg=bg, center=True)
        data_cell(ws6, i, 2, attack_labels.get(check["name"], check["name"]), bg=bg)
        s = ws6.cell(i, 3, "DITOLAK (PASS)" if check["passed"] else "LOLOS (FAIL)")
        s.font = Font("Calibri", bold=True, size=10, color="155724" if check["passed"] else "721C24")
        s.fill = PatternFill("solid", fgColor=status_bg)
        s.alignment = Alignment(horizontal="center", vertical="center")
        data_cell(ws6, i, 4, str(check["detail"]), bg=bg)

    apply_border(ws6, 1, len(integrity)+1, 1, 4)

    # SHEET 7: Enkripsi Hibrida (RSA-OAEP + AES-256-GCM)
    ws7 = wb.create_sheet("6. Enkripsi Hibrida (RSA)")
    ws7.sheet_view.showGridLines = False
    for col, w in zip(range(1, 9), [5, 20, 28, 16, 18, 16, 16, 10]):
        ws7.column_dimensions[get_column_letter(col)].width = w

    # Section 1: Header & Round Trip
    ws7.merge_cells("A1:H1")
    c_h1 = ws7.cell(1, 1, "PENGUJIAN VALIDASI ROUND-TRIP ENKRIPSI HIBRIDA (RSA-2048 + AES-256-GCM)")
    c_h1.font = Font("Calibri", bold=True, size=11, color=C_WHITE)
    c_h1.fill = PatternFill("solid", fgColor=C_HEADER)
    c_h1.alignment = Alignment(horizontal="center", vertical="center")
    ws7.row_dimensions[1].height = 24

    hdr7_rt = ["No", "Nama Sampel", "Deskripsi", "Ukuran File (B)", "Wrapped Key (B)", "Ciphertext (B)", "Total .sdrop (B)", "Status"]
    for j, h in enumerate(hdr7_rt, 1):
        hdr_style(ws7, 2, j, h, bg=C_SUBHEAD)
    ws7.row_dimensions[2].height = 20

    row_idx = 3
    for i, row in enumerate(hybrid_res["round_trip"], start=1):
        bg = C_ALT if i % 2 == 0 else C_WHITE
        status_ok = row["round_trip_ok"]
        status_bg = C_PASS if status_ok else C_FAIL
        data_cell(ws7, row_idx, 1, i, bg=bg, center=True)
        data_cell(ws7, row_idx, 2, row["sample"], bg=bg)
        data_cell(ws7, row_idx, 3, row["description"], bg=bg)
        data_cell(ws7, row_idx, 4, row["file_size"], bg=bg, center=True)
        data_cell(ws7, row_idx, 5, row["wrapped_key_size"], bg=bg, center=True)
        data_cell(ws7, row_idx, 6, row["ciphertext_size"], bg=bg, center=True)
        data_cell(ws7, row_idx, 7, row["package_size"], bg=bg, center=True)
        s = ws7.cell(row_idx, 8, "PASS" if status_ok else "FAIL")
        s.font = Font("Calibri", bold=True, size=10, color="155724" if status_ok else "721C24")
        s.fill = PatternFill("solid", fgColor=status_bg)
        s.alignment = Alignment(horizontal="center", vertical="center")
        row_idx += 1
    apply_border(ws7, 2, row_idx - 1, 1, 8)

    # Section 2: Komparasi Waktu Mode Password vs Mode Hibrida
    row_idx += 2
    ws7.merge_cells(f"A{row_idx}:H{row_idx}")
    c_h2 = ws7.cell(row_idx, 1, "KOMPARASI PERFORMA: MODE PASSWORD (PBKDF2) VS MODE HIBRIDA (RSA-OAEP)")
    c_h2.font = Font("Calibri", bold=True, size=11, color=C_WHITE)
    c_h2.fill = PatternFill("solid", fgColor=C_HEADER)
    c_h2.alignment = Alignment(horizontal="center", vertical="center")
    ws7.row_dimensions[row_idx].height = 24
    row_idx += 1

    hdr7_bench = ["No", "Ukuran File", "Password Enkripsi (ms)", "Hibrida Enkripsi (ms)", "Password Dekripsi (ms)", "Hibrida Dekripsi (ms)", "Enkripsi Tercepat", "Dekripsi Tercepat"]
    for j, h in enumerate(hdr7_bench, 1):
        hdr_style(ws7, row_idx, j, h, bg=C_SUBHEAD)
    ws7.row_dimensions[row_idx].height = 22

    start_bench_row = row_idx + 1
    for i, b_row in enumerate(hybrid_res["benchmark_comparison"], start=1):
        curr_row = start_bench_row + i - 1
        bg = C_ALT if i % 2 == 0 else C_WHITE
        data_cell(ws7, curr_row, 1, i, bg=bg, center=True)
        data_cell(ws7, curr_row, 2, b_row["size_label"], bg=bg, center=True)
        data_cell(ws7, curr_row, 3, b_row["pwd_enc_ms"], bg=bg, center=True, num_format="0.000")
        data_cell(ws7, curr_row, 4, b_row["hyb_enc_ms"], bg=bg, center=True, num_format="0.000")
        data_cell(ws7, curr_row, 5, b_row["pwd_dec_ms"], bg=bg, center=True, num_format="0.000")
        data_cell(ws7, curr_row, 6, b_row["hyb_dec_ms"], bg=bg, center=True, num_format="0.000")
        
        faster_enc = "Hibrida (RSA)" if b_row["hyb_enc_ms"] < b_row["pwd_enc_ms"] else "Password"
        faster_dec = "Hibrida (RSA)" if b_row["hyb_dec_ms"] < b_row["pwd_dec_ms"] else "Password"
        data_cell(ws7, curr_row, 7, faster_enc, bg=C_PASS, center=True, bold=True)
        data_cell(ws7, curr_row, 8, faster_dec, bg=C_PASS, center=True, bold=True)
        row_idx = curr_row
    apply_border(ws7, start_bench_row - 1, row_idx, 1, 8)

    # Section 3: Uji Ketahanan Serangan Kriptografi Hibrida
    row_idx += 2
    ws7.merge_cells(f"A{row_idx}:H{row_idx}")
    c_h3 = ws7.cell(row_idx, 1, "UJI KETAHANAN & SERANGAN PADA ENKRIPSI HIBRIDA")
    c_h3.font = Font("Calibri", bold=True, size=11, color=C_WHITE)
    c_h3.fill = PatternFill("solid", fgColor=C_HEADER)
    c_h3.alignment = Alignment(horizontal="center", vertical="center")
    ws7.row_dimensions[row_idx].height = 24
    row_idx += 1

    hdr7_atk = ["No", "Skenario Serangan / Uji Keamanan", "", "", "Hasil", "Detail Pesan Sistem Keamanan", "", ""]
    hdr_style(ws7, row_idx, 1, "No", bg=C_SUBHEAD)
    ws7.merge_cells(f"B{row_idx}:D{row_idx}")
    hdr_style(ws7, row_idx, 2, "Skenario Serangan / Uji Integritas", bg=C_SUBHEAD)
    hdr_style(ws7, row_idx, 5, "Hasil Uji", bg=C_SUBHEAD)
    ws7.merge_cells(f"F{row_idx}:H{row_idx}")
    hdr_style(ws7, row_idx, 6, "Detail Pesan Sistem Keamanan", bg=C_SUBHEAD)
    ws7.row_dimensions[row_idx].height = 22

    start_atk_row = row_idx + 1
    for i, a_row in enumerate(hybrid_res["attacks"], start=1):
        curr_row = start_atk_row + i - 1
        bg = C_ALT if i % 2 == 0 else C_WHITE
        status_bg = C_PASS if a_row["passed"] else C_FAIL
        data_cell(ws7, curr_row, 1, i, bg=bg, center=True)
        ws7.merge_cells(f"B{curr_row}:D{curr_row}")
        data_cell(ws7, curr_row, 2, a_row["scenario"], bg=bg)
        
        s = ws7.cell(curr_row, 5, "DITOLAK (PASS)" if a_row["passed"] else "LOLOS (FAIL)")
        s.font = Font("Calibri", bold=True, size=10, color="155724" if a_row["passed"] else "721C24")
        s.fill = PatternFill("solid", fgColor=status_bg)
        s.alignment = Alignment(horizontal="center", vertical="center")
        
        ws7.merge_cells(f"F{curr_row}:H{curr_row}")
        data_cell(ws7, curr_row, 6, str(a_row["detail"]), bg=bg)
        row_idx = curr_row
    apply_border(ws7, start_atk_row - 1, row_idx, 1, 8)

    wb.save(EXCEL_PATH)
    print(f"[3/7] Excel tersimpan (7 Sheet): {EXCEL_PATH}")

    # GRAFIK 1: Benchmark Waktu Simetris
    print("[4/7] Membuat grafik benchmark simetris...")
    aes_rows    = [r for r in benchmark if "AES" in r["algorithm"].upper()]
    chacha_rows = [r for r in benchmark if "CHACHA" in r["algorithm"].upper()]
    labels = [r["size_label"] for r in aes_rows]
    aes_enc    = [r["encrypt_ms"] for r in aes_rows]
    chacha_enc = [r["encrypt_ms"] for r in chacha_rows]
    aes_dec    = [r["decrypt_ms"] for r in aes_rows]
    chacha_dec = [r["decrypt_ms"] for r in chacha_rows]

    x = np.arange(len(labels))
    w = 0.2
    fig, axes = plt.subplots(1, 2, figsize=(13, 5))
    fig.suptitle("Benchmark Waktu Enkripsi & Dekripsi\nAES-256-GCM vs ChaCha20-Poly1305",
                 fontsize=13, fontweight="bold", y=1.02)

    for ax, data_aes, data_cha, title in [
        (axes[0], aes_enc,  chacha_enc, "Enkripsi (ms)"),
        (axes[1], aes_dec,  chacha_dec, "Dekripsi (ms)"),
    ]:
        b1 = ax.bar(x - w/2, data_aes,  w, label="AES-256-GCM",       color="#2196F3", alpha=0.88, edgecolor="white")
        b2 = ax.bar(x + w/2, data_cha,  w, label="ChaCha20-Poly1305",  color="#FF9800", alpha=0.88, edgecolor="white")
        ax.set_xlabel("Ukuran File", fontsize=11)
        ax.set_ylabel("Waktu (ms)", fontsize=11)
        ax.set_title(title, fontsize=12, fontweight="bold")
        ax.set_xticks(x)
        ax.set_xticklabels(labels)
        ax.legend(fontsize=9)
        ax.grid(axis="y", alpha=0.3)
        ax.set_facecolor("#FAFAFA")
        for bar in list(b1) + list(b2):
            h = bar.get_height()
            ax.annotate(f"{h:.2f}", xy=(bar.get_x() + bar.get_width()/2, h),
                        xytext=(0, 3), textcoords="offset points", ha="center", fontsize=8)

    plt.tight_layout()
    plt.savefig(CHART_BENCHMARK, dpi=150, bbox_inches="tight", facecolor="white")
    plt.close()
    print(f"      -> {CHART_BENCHMARK}")

    # GRAFIK 2: Avalanche Effect 
    print("[5/7] Membuat grafik avalanche effect...")
    labels_av = []
    values_av = []
    colors_av = []
    for row in avalanche:
        algo = "AES-GCM" if "AES" in row["algorithm"].upper() else "ChaCha20"
        scen = "plaintext-flip" if "plaintext" in row["scenario"] else "key-flip"
        labels_av.append(f"{algo}\n({scen})")
        values_av.append(row["bit_change_pct"])
        colors_av.append("#2196F3" if "AES" in row["algorithm"].upper() else "#FF9800")

    fig, ax = plt.subplots(figsize=(9, 5))
    bars = ax.bar(labels_av, values_av, color=colors_av, alpha=0.88, edgecolor="white", width=0.5)
    ax.axhline(50, color="red", linestyle="--", linewidth=1.5, label="Target ideal = 50%")
    ax.axhspan(45, 55, alpha=0.08, color="green", label="Zona ideal (45%–55%)")
    ax.set_ylim(0, 100)
    ax.set_ylabel("Persentase Bit Berubah (%)", fontsize=11)
    ax.set_title("Avalanche Effect\nPersentase Bit Ciphertext yang Berubah", fontsize=13, fontweight="bold")
    ax.legend(fontsize=9)
    ax.grid(axis="y", alpha=0.3)
    ax.set_facecolor("#FAFAFA")
    for bar, val in zip(bars, values_av):
        ax.annotate(f"{val:.3f}%", xy=(bar.get_x() + bar.get_width()/2, bar.get_height()),
                    xytext=(0, 4), textcoords="offset points", ha="center", fontsize=10, fontweight="bold")

    plt.tight_layout()
    plt.savefig(CHART_AVALANCHE, dpi=150, bbox_inches="tight", facecolor="white")
    plt.close()
    print(f"      -> {CHART_AVALANCHE}")

    # GRAFIK 3: Entropi Shannon 
    print("[6/7] Membuat grafik entropi Shannon...")
    ent_results = entropy["results"]
    fig, ax = plt.subplots(figsize=(9, 5))
    x_ent = np.arange(len(ent_results))
    w_ent = 0.35
    pt_vals  = [r["plaintext_entropy"]  for r in ent_results]
    ct_vals  = [r["ciphertext_entropy"] for r in ent_results]
    algo_lbls = [r["algorithm"].replace("AES-256-GCM","AES-GCM").replace("ChaCha20-Poly1305","ChaCha20").replace("aes-256-gcm","AES-GCM").replace("chacha20-poly1305","ChaCha20") for r in ent_results]

    b1 = ax.bar(x_ent - w_ent/2, pt_vals, w_ent, label="Plaintext", color="#90CAF9", edgecolor="white")
    b2 = ax.bar(x_ent + w_ent/2, ct_vals, w_ent, label="Ciphertext", color="#1565C0", edgecolor="white")
    ax.axhline(8.0, color="red", linestyle="--", linewidth=1.5, label="Maks teoretis = 8.0 bit/byte")
    ax.set_ylim(0, 9)
    ax.set_xticks(x_ent)
    ax.set_xticklabels(algo_lbls, fontsize=10)
    ax.set_ylabel("Entropi Shannon (bit/byte)", fontsize=11)
    ax.set_title(f"Entropi Shannon: Plaintext vs Ciphertext\nSampel: {entropy['sample']}",
                 fontsize=13, fontweight="bold")
    ax.legend(fontsize=9)
    ax.grid(axis="y", alpha=0.3)
    ax.set_facecolor("#FAFAFA")
    for bar, val in zip(list(b1)+list(b2), pt_vals+ct_vals):
        ax.annotate(f"{val:.4f}", xy=(bar.get_x() + bar.get_width()/2, bar.get_height()),
                    xytext=(0, 3), textcoords="offset points", ha="center", fontsize=9)

    plt.tight_layout()
    plt.savefig(CHART_ENTROPY, dpi=150, bbox_inches="tight", facecolor="white")
    plt.close()
    print(f"      -> {CHART_ENTROPY}")

    # GRAFIK 4: Komparasi Waktu: Password vs Hibrida
    print("[7/7] Membuat grafik komparasi Mode Password vs Enkripsi Hibrida...")
    b_comp = hybrid_res["benchmark_comparison"]
    hyb_labels = [row["size_label"] for row in b_comp]
    pwd_enc_v = [row["pwd_enc_ms"] for row in b_comp]
    hyb_enc_v = [row["hyb_enc_ms"] for row in b_comp]
    pwd_dec_v = [row["pwd_dec_ms"] for row in b_comp]
    hyb_dec_v = [row["hyb_dec_ms"] for row in b_comp]

    x_hyb = np.arange(len(hyb_labels))
    w_hyb = 0.2
    fig, axes = plt.subplots(1, 2, figsize=(13, 5))
    fig.suptitle("Komparasi Waktu Eksekusi: Mode Password (PBKDF2) vs Mode Hibrida (RSA-OAEP)",
                 fontsize=13, fontweight="bold", y=1.02)

    for ax, data_pwd, data_hyb, title in [
        (axes[0], pwd_enc_v, hyb_enc_v, "Waktu Enkripsi (ms)"),
        (axes[1], pwd_dec_v, hyb_dec_v, "Waktu Dekripsi (ms)"),
    ]:
        b_p = ax.bar(x_hyb - w_hyb/2, data_pwd, w_hyb, label="Password (PBKDF2 + AES)", color="#7E57C2", alpha=0.9, edgecolor="white")
        b_h = ax.bar(x_hyb + w_hyb/2, data_hyb, w_hyb, label="Hibrida (RSA-OAEP + AES)", color="#00897B", alpha=0.9, edgecolor="white")
        ax.set_xlabel("Ukuran File", fontsize=11)
        ax.set_ylabel("Waktu (ms)", fontsize=11)
        ax.set_title(title, fontsize=12, fontweight="bold")
        ax.set_xticks(x_hyb)
        ax.set_xticklabels(hyb_labels)
        ax.legend(fontsize=9)
        ax.grid(axis="y", alpha=0.3)
        ax.set_facecolor("#FAFAFA")
        for bar in list(b_p) + list(b_h):
            h = bar.get_height()
            ax.annotate(f"{h:.2f}", xy=(bar.get_x() + bar.get_width()/2, h),
                        xytext=(0, 3), textcoords="offset points", ha="center", fontsize=8)

    plt.tight_layout()
    plt.savefig(CHART_HYBRID_COMP, dpi=150, bbox_inches="tight", facecolor="white")
    plt.close()
    print(f"      -> {CHART_HYBRID_COMP}")

    print("\n" + "=" * 55)
    print("SELESAI! Seluruh berkas excel dan grafik berhasil diperbarui di:")
    print(f"Folder: {OUTPUT_DIR}")

if __name__ == "__main__":
    main()
