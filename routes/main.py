"""
Main application routes handling UI rendering and encryption service integration.
"""

from flask import Blueprint, render_template, redirect, url_for, request, jsonify
from services.encryption_service import encrypt_file_data

main_bp = Blueprint("main", __name__)


@main_bp.route("/")
def index():
    """Redirect route utama ke halaman Encrypt & Send."""
    return redirect(url_for("main.encrypt"))


@main_bp.route("/encrypt", methods=["GET", "POST"])
def encrypt():
    """
    Halaman Encrypt & Send dan endpoint pemrosesan enkripsi file (Modul Orang 1).
    """
    if request.method == "GET":
        return render_template("encrypt.html", active_page="encrypt")

    # Handler POST: Proses enkripsi file
    try:
        if "file" not in request.files:
            return jsonify({"success": False, "error": "File tidak ditemukan."}), 400

        uploaded_file = request.files["file"]
        if not uploaded_file or uploaded_file.filename == "":
            return jsonify({"success": False, "error": "File tidak ditemukan."}), 400

        file_bytes = uploaded_file.read()
        password = request.form.get("password", "")
        algorithm = request.form.get("algorithm", "AES-256-GCM")

        # Panggil service enkripsi (PBKDF2 -> Derived Key -> Cipher AEAD)
        result = encrypt_file_data(
            file_bytes=file_bytes,
            password=password,
            algorithm=algorithm,
            original_filename=uploaded_file.filename
        )

        # Kembalikan response metadata non-secret untuk pratinjau hasil enkripsi UI
        return jsonify({
            "success": True,
            "message": "Enkripsi berhasil diproses.",
            "data": {
                "original_filename": result.original_filename,
                "algorithm": result.algorithm,
                "file_size": result.file_size,
                "encrypted_size": len(result.ciphertext),
                "salt_length": len(result.salt),
                "nonce_length": len(result.nonce),
                "tag_length": len(result.tag),
                "nonce_hex": result.nonce.hex(),
                "tag_hex": result.tag.hex()
            }
        }), 200

    except (ValueError, TypeError) as err:
        return jsonify({"success": False, "error": str(err)}), 400
    except Exception:
        # Error generic yang aman tanpa membocorkan trace/secret internal
        return jsonify({"success": False, "error": "Enkripsi gagal diproses."}), 500


@main_bp.route("/decrypt")
def decrypt():
    """Halaman Receive & Decrypt (Placeholder Modul Orang 2)."""
    return render_template("decrypt.html", active_page="decrypt")


@main_bp.route("/testing")
def testing():
    """Halaman Security Testing (Placeholder Modul Orang 3)."""
    return render_template("testing.html", active_page="testing")

