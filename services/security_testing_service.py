"""Security testing and empirical analysis for SecureDrop."""

from __future__ import annotations

import base64
import hashlib
import json
import math
import secrets
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from time import perf_counter
from typing import Any, Sequence

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from crypto.aes_gcm import decrypt_aes_gcm, encrypt_aes_gcm
from crypto.chacha20 import decrypt_chacha20, encrypt_chacha20
from crypto.kdf import derive_key, generate_salt
from services.encryption_service import ALGO_AES_GCM, ALGO_CHACHA20, encrypt_file_data
from services.sdrop_service import AuthenticationError, SdropFormatError, decrypt_sdrop, package_encryption_result

FULL_BENCHMARK_SIZES = (1024, 1024 * 1024, 10 * 1024 * 1024)
QUICK_BENCHMARK_SIZES = (1024, 16 * 1024)
_AVALANCHE_SAMPLE_SIZE = 512


@dataclass(frozen=True)
class SecuritySample:
    name: str
    description: str
    data: bytes


@dataclass(frozen=True)
class UploadedSecurityFile:
    name: str
    size: int
    data: bytes
    fingerprint: str


def _validate_uploaded_files(files: Sequence[Any]) -> list[UploadedSecurityFile]:
    if not isinstance(files, Sequence):
        raise TypeError("Daftar file harus berupa sequence.")

    uploaded_files: list[UploadedSecurityFile] = []
    seen_fingerprints: set[str] = set()
    for index, file_obj in enumerate(files, start=1):
        if file_obj is None:
            raise ValueError(f"File ke-{index} tidak valid.")

        filename = str(getattr(file_obj, "filename", "") or "").strip()
        if not filename:
            raise ValueError(f"File ke-{index} tidak memiliki nama yang valid.")

        file_bytes = file_obj.read()
        if not isinstance(file_bytes, (bytes, bytearray)):
            raise TypeError(f"File {filename} harus terbaca sebagai bytes.")

        raw_bytes = bytes(file_bytes)
        if not raw_bytes:
            raise ValueError(f"File {filename} tidak boleh kosong.")

        fingerprint = hashlib.sha256(raw_bytes).hexdigest()
        if fingerprint in seen_fingerprints:
            raise ValueError(f"File duplikat terdeteksi: {filename}. Corpus harus berisi file yang berbeda.")
        seen_fingerprints.add(fingerprint)

        uploaded_files.append(
            UploadedSecurityFile(
                name=filename,
                size=len(raw_bytes),
                data=raw_bytes,
                fingerprint=fingerprint,
            )
        )

    return uploaded_files


def build_security_corpus() -> list[SecuritySample]:
    """Return a corpus of 10 representative inputs, including PDF and image samples."""

    return [
        SecuritySample("text-basic", "Teks pendek untuk baseline entropy", b"SecureDrop O3 security testing sample."),
        SecuritySample("text-repeated", "Teks berulang untuk distribusi byte yang jelas", b"ABCD" * 128),
        SecuritySample("pdf-mini", "Struktur PDF minimal", b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF"),
        SecuritySample(
            "png-mini",
            "Header gambar PNG minimal",
            b"\x89PNG\r\n\x1a\n" + bytes(range(32)) + b"PNG-END",
        ),
        SecuritySample(
            "jpg-mini",
            "Header gambar JPEG minimal",
            b"\xff\xd8\xff\xe0" + b"JFIF\x00\x01\x02" + bytes(range(16)) + b"\xff\xd9",
        ),
        SecuritySample("json-structured", "Payload JSON terstruktur", b'{"project":"SecureDrop","stage":"O3","ok":true}'),
        SecuritySample("csv-tabular", "Payload CSV sederhana", b"id,value\n1,10\n2,20\n3,30\n"),
        SecuritySample("binary-range", "Byte berurutan 0-255", bytes(range(256))),
        SecuritySample("random-like", "Data biner acak sebagai pembanding", secrets.token_bytes(512)),
        SecuritySample("utf8-unicode", "Teks UTF-8 dengan karakter non-ASCII", "Keamanan Informasi - SecureDrop - O3".encode("utf-8")),
    ]


def _bit_difference_ratio(left: bytes, right: bytes) -> float:
    max_length = max(len(left), len(right))
    left_padded = left.ljust(max_length, b"\x00")
    right_padded = right.ljust(max_length, b"\x00")
    different_bits = sum((byte_left ^ byte_right).bit_count() for byte_left, byte_right in zip(left_padded, right_padded))
    total_bits = max_length * 8
    return 0.0 if total_bits == 0 else different_bits / total_bits


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0

    counts = [0] * 256
    for value in data:
        counts[value] += 1

    total = len(data)
    entropy = 0.0
    for count in counts:
        if count == 0:
            continue
        probability = count / total
        entropy -= probability * math.log2(probability)
    return entropy


def _byte_histogram(data: bytes) -> list[int]:
    counts = [0] * 256
    for value in data:
        counts[value] += 1
    return counts


def _serialize_package(result: Any) -> bytes:
    return package_encryption_result(result)


def _internal_suite_password(label: str) -> str:
    return f"securedrop-o3::{label}::{secrets.token_hex(16)}"


def run_round_trip_suite(files: Sequence[Any] | None = None, samples: Sequence[SecuritySample] | None = None) -> list[dict[str, Any]]:
    corpus: list[dict[str, Any]] = []

    if files is not None:
        uploaded_files = _validate_uploaded_files(files)
        if len(uploaded_files) < 1:
            raise ValueError("Minimal 1 file diperlukan untuk menjalankan Security Testing.")

        corpus = [
            {
                "name": uploaded_file.name,
                "description": f"Uploaded file: {uploaded_file.name}",
                "data": uploaded_file.data,
            }
            for uploaded_file in uploaded_files
        ]
    else:
        corpus = [
            {
                "name": sample.name,
                "description": sample.description,
                "data": sample.data,
            }
            for sample in (samples or build_security_corpus())
        ]

    rows: list[dict[str, Any]] = []
    internal_password = _internal_suite_password("round-trip")

    for sample in corpus:
        for algorithm in (ALGO_AES_GCM, ALGO_CHACHA20):
            result = encrypt_file_data(sample["data"], internal_password, algorithm=algorithm, original_filename=sample["name"])
            package_bytes = _serialize_package(result)
            plaintext, filename = decrypt_sdrop(package_bytes, internal_password)
            rows.append(
                {
                    "sample": sample["name"],
                    "description": sample["description"],
                    "algorithm": algorithm,
                    "file_size": len(sample["data"]),
                    "ciphertext_size": len(result.ciphertext),
                    "package_size": len(package_bytes),
                    "round_trip_ok": plaintext == sample["data"] and filename == sample["name"],
                }
            )

    return rows


def summarize_round_trip_rows(round_trip_rows: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}

    for row in round_trip_rows:
        entry = grouped.setdefault(
            str(row["sample"]),
            {
                "name": str(row["sample"]),
                "size": int(row["file_size"]),
                "statuses": [],
                "passed": True,
            },
        )
        entry["statuses"].append(str(row["algorithm"]))
        entry["passed"] = bool(entry["passed"]) and bool(row["round_trip_ok"])

    return [
        {
            "name": item["name"],
            "size": item["size"],
            "status": "PASS" if item["passed"] else "FAIL",
            "passed": item["passed"],
        }
        for item in grouped.values()
    ]


def benchmark_algorithms(
    sizes: Sequence[int] | None = None,
    repeats: int = 1,
) -> list[dict[str, Any]]:
    benchmark_sizes = tuple(sizes or FULL_BENCHMARK_SIZES)
    if repeats < 1:
        raise ValueError("repeats harus minimal 1.")

    benchmark_password = _internal_suite_password("benchmark")
    salt = generate_salt()
    key = derive_key(password=benchmark_password, salt=salt)
    rows: list[dict[str, Any]] = []

    for size in benchmark_sizes:
        plaintext = secrets.token_bytes(size)
        for algorithm in (ALGO_AES_GCM, ALGO_CHACHA20):
            encrypt_times: list[float] = []
            decrypt_times: list[float] = []
            ciphertext_size = 0

            for _ in range(repeats):
                start = perf_counter()
                if algorithm == ALGO_AES_GCM:
                    result = encrypt_aes_gcm(key=key, plaintext=plaintext)
                else:
                    result = encrypt_chacha20(key=key, plaintext=plaintext)
                encrypt_times.append((perf_counter() - start) * 1000)
                ciphertext_size = len(result.ciphertext)

                start = perf_counter()
                if algorithm == ALGO_AES_GCM:
                    decrypted = decrypt_aes_gcm(key=key, nonce=result.nonce, ciphertext=result.ciphertext, tag=result.tag)
                else:
                    decrypted = decrypt_chacha20(key=key, nonce=result.nonce, ciphertext=result.ciphertext, tag=result.tag)
                decrypt_times.append((perf_counter() - start) * 1000)

                if decrypted != plaintext:
                    raise RuntimeError("Benchmark decryption gagal memulihkan plaintext.")

            rows.append(
                {
                    "size_bytes": size,
                    "size_label": _format_size(size),
                    "algorithm": algorithm,
                    "encrypt_ms": round(sum(encrypt_times) / len(encrypt_times), 3),
                    "decrypt_ms": round(sum(decrypt_times) / len(decrypt_times), 3),
                    "ciphertext_size": ciphertext_size,
                }
            )

    return rows


def avalanche_analysis() -> list[dict[str, Any]]:
    base_plaintext = secrets.token_bytes(_AVALANCHE_SAMPLE_SIZE)
    base_key = secrets.token_bytes(32)
    base_nonce = bytes(12)

    rows: list[dict[str, Any]] = []
    for algorithm_name, cipher in ((ALGO_AES_GCM, AESGCM(base_key)), (ALGO_CHACHA20, ChaCha20Poly1305(base_key))):
        reference = cipher.encrypt(base_nonce, base_plaintext, None)

        mutated_plaintext = bytearray(base_plaintext)
        mutated_plaintext[0] ^= 0x01
        plaintext_flip = cipher.encrypt(base_nonce, bytes(mutated_plaintext), None)

        mutated_key = bytearray(base_key)
        mutated_key[0] ^= 0x01
        mutated_cipher = AESGCM(bytes(mutated_key)) if algorithm_name == ALGO_AES_GCM else ChaCha20Poly1305(bytes(mutated_key))
        key_flip = mutated_cipher.encrypt(base_nonce, base_plaintext, None)

        rows.append(
            {
                "algorithm": algorithm_name,
                "scenario": "plaintext-bit-flip",
                "bit_change_pct": round(_bit_difference_ratio(reference, plaintext_flip) * 100, 3),
                "reference_size": len(reference),
                "comparison_size": len(plaintext_flip),
            }
        )
        rows.append(
            {
                "algorithm": algorithm_name,
                "scenario": "key-bit-flip",
                "bit_change_pct": round(_bit_difference_ratio(reference, key_flip) * 100, 3),
                "reference_size": len(reference),
                "comparison_size": len(key_flip),
            }
        )

    return rows


def entropy_and_histogram_analysis() -> dict[str, Any]:
    sample = build_security_corpus()[0]
    rows: list[dict[str, Any]] = []
    internal_password = _internal_suite_password("entropy")

    for algorithm in (ALGO_AES_GCM, ALGO_CHACHA20):
        result = encrypt_file_data(sample.data, internal_password, algorithm=algorithm, original_filename=sample.name)
        plaintext_entropy = round(_shannon_entropy(sample.data), 4)
        ciphertext_entropy = round(_shannon_entropy(result.ciphertext), 4)
        rows.append(
            {
                "sample": sample.name,
                "algorithm": algorithm,
                "plaintext_entropy": plaintext_entropy,
                "ciphertext_entropy": ciphertext_entropy,
                "entropy_delta": round(ciphertext_entropy - plaintext_entropy, 4),
                "plaintext_histogram": _byte_histogram(sample.data),
                "ciphertext_histogram": _byte_histogram(result.ciphertext),
            }
        )

    return {"sample": sample.name, "results": rows}


def integrity_analysis() -> list[dict[str, Any]]:
    sample = build_security_corpus()[2]
    internal_password = _internal_suite_password("integrity")
    result = encrypt_file_data(sample.data, internal_password, algorithm=ALGO_AES_GCM, original_filename=sample.name)
    package_bytes = _serialize_package(result)
    document = json.loads(package_bytes.decode("utf-8"))

    checks: list[dict[str, Any]] = []

    try:
        decrypt_sdrop(package_bytes, f"{internal_password}-wrong")
        checks.append({"name": "wrong_password", "passed": False, "detail": "Dekripsi tidak seharusnya berhasil."})
    except AuthenticationError as exc:
        checks.append({"name": "wrong_password", "passed": True, "detail": str(exc)})

    tampered_document = dict(document)
    ciphertext_bytes = bytearray(base64.b64decode(tampered_document["ciphertext"]))
    ciphertext_bytes[0] ^= 0x01
    tampered_document["ciphertext"] = base64.b64encode(ciphertext_bytes).decode("ascii")
    tampered_payload = json.dumps(tampered_document, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    try:
        decrypt_sdrop(tampered_payload, internal_password)
        checks.append({"name": "tampered_ciphertext", "passed": False, "detail": "Paket yang dimodifikasi tidak seharusnya lolos."})
    except AuthenticationError as exc:
        checks.append({"name": "tampered_ciphertext", "passed": True, "detail": str(exc)})

    try:
        decrypt_sdrop(b'{"format":"SecureDrop","version":1,"mode":"password"}', internal_password)
        checks.append({"name": "corrupt_package", "passed": False, "detail": "Paket rusak tidak seharusnya lolos."})
    except (AuthenticationError, SdropFormatError, ValueError) as exc:
        checks.append({"name": "corrupt_package", "passed": True, "detail": str(exc)})

    return checks


def compare_algorithms(benchmark_rows: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[int, dict[str, dict[str, float]]] = {}
    for row in benchmark_rows:
        size = int(row["size_bytes"])
        grouped.setdefault(size, {})[str(row["algorithm"])] = {
            "encrypt_ms": float(row["encrypt_ms"]),
            "decrypt_ms": float(row["decrypt_ms"]),
        }

    comparisons: list[dict[str, Any]] = []
    for size in sorted(grouped):
        aes = grouped[size].get(ALGO_AES_GCM)
        chacha = grouped[size].get(ALGO_CHACHA20)
        if not aes or not chacha:
            continue

        encrypt_delta = aes["encrypt_ms"] - chacha["encrypt_ms"]
        decrypt_delta = aes["decrypt_ms"] - chacha["decrypt_ms"]
        comparisons.append(
            {
                "size_bytes": size,
                "size_label": _format_size(size),
                "aes_encrypt_ms": round(aes["encrypt_ms"], 3),
                "chacha_encrypt_ms": round(chacha["encrypt_ms"], 3),
                "aes_decrypt_ms": round(aes["decrypt_ms"], 3),
                "chacha_decrypt_ms": round(chacha["decrypt_ms"], 3),
                "faster_encrypt": ALGO_AES_GCM if encrypt_delta < 0 else ALGO_CHACHA20,
                "faster_decrypt": ALGO_AES_GCM if decrypt_delta < 0 else ALGO_CHACHA20,
                "encrypt_speedup_pct": round(abs(encrypt_delta) / max(aes["encrypt_ms"], chacha["encrypt_ms"], 1e-9) * 100, 3),
                "decrypt_speedup_pct": round(abs(decrypt_delta) / max(aes["decrypt_ms"], chacha["decrypt_ms"], 1e-9) * 100, 3),
            }
        )

    return comparisons


def hybrid_testing_analysis(quick: bool = False) -> dict[str, Any]:
    from services.sdrop_service import (
        create_hybrid_sdrop,
        decrypt_hybrid_sdrop,
        generate_rsa_key_pair,
        read_sdrop,
        AuthenticationError,
    )

    priv_bytes, pub_bytes = generate_rsa_key_pair(2048)
    corpus = build_security_corpus()[:3] if quick else build_security_corpus()

    round_trip_rows = []
    for s in corpus:
        pkg_bytes = create_hybrid_sdrop(s.data, pub_bytes, original_filename=s.name)
        plain, fname = decrypt_hybrid_sdrop(pkg_bytes, priv_bytes)
        pkg = read_sdrop(pkg_bytes)
        round_trip_rows.append({
            "sample": s.name,
            "algorithm": "RSA-OAEP + AES-GCM",
            "file_size": len(s.data),
            "wrapped_key_size": len(pkg.encrypted_key) if pkg.encrypted_key else 256,
            "ciphertext_size": len(pkg.ciphertext),
            "package_size": len(pkg_bytes),
            "round_trip_ok": plain == s.data and fname == s.name,
        })

    wrong_priv, _ = generate_rsa_key_pair(2048)
    sample_pkg = create_hybrid_sdrop(b"Security testing payload", pub_bytes, original_filename="test.bin")

    integrity_checks = []
    try:
        decrypt_hybrid_sdrop(sample_pkg, wrong_priv)
        integrity_checks.append({"name": "wrong_private_key", "passed": False, "detail": "Dekripsi dengan kunci privat salah tidak boleh berhasil."})
    except AuthenticationError as e:
        integrity_checks.append({"name": "wrong_private_key", "passed": True, "detail": str(e)})

    return {
        "round_trip": round_trip_rows,
        "round_trip_success": sum(1 for r in round_trip_rows if r["round_trip_ok"]),
        "round_trip_total": len(round_trip_rows),
        "integrity": integrity_checks,
    }


def run_security_testing_suite(
    files: Sequence[Any] | None = None,
    quick: bool = False,
    benchmark_sizes: Sequence[int] | None = None,
    benchmark_repeats: int = 1,
) -> dict[str, Any]:
    sizes = tuple(benchmark_sizes or (QUICK_BENCHMARK_SIZES if quick else FULL_BENCHMARK_SIZES))
    if files is not None and len(files) == 0:
        raise ValueError("Minimal 1 file diperlukan untuk menjalankan Security Testing.")
    round_trip_rows = run_round_trip_suite(files=files)
    benchmark_rows = benchmark_algorithms(sizes=sizes, repeats=benchmark_repeats)

    return {
        "quick_mode": quick,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "corpus": [
            {
                "name": sample.name,
                "description": sample.description,
                "size": len(sample.data),
            }
            for sample in build_security_corpus()
        ],
        "round_trip": round_trip_rows,
        "file_round_trip": summarize_round_trip_rows(round_trip_rows),
        "benchmark": benchmark_rows,
        "comparison": compare_algorithms(benchmark_rows),
        "avalanche": avalanche_analysis(),
        "entropy": entropy_and_histogram_analysis(),
        "integrity": integrity_analysis(),
        "hybrid": hybrid_testing_analysis(quick=quick),
        "round_trip_success": sum(1 for row in round_trip_rows if row["round_trip_ok"]),
        "round_trip_total": len(round_trip_rows),
    }


def _format_size(size_bytes: int) -> str:
    if size_bytes >= 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.0f} MB" if size_bytes % (1024 * 1024) == 0 else f"{size_bytes / (1024 * 1024):.2f} MB"
    if size_bytes >= 1024:
        return f"{size_bytes / 1024:.0f} KB" if size_bytes % 1024 == 0 else f"{size_bytes / 1024:.2f} KB"
    return f"{size_bytes} B"