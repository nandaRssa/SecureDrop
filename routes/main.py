from flask import Blueprint, render_template, redirect, url_for, request, jsonify
from services.encryption_service import encrypt_file_data

main_bp = Blueprint("main", __name__)


# ROUTE UTAMA REDIRECT KE ENCRYPT
@main_bp.route("/")
def index():
    return redirect(url_for("main.encrypt"))


# HALAMAN DAN ENDPOINT ENCRYPT & SEND
@main_bp.route("/encrypt", methods=["GET", "POST"])
def encrypt():
    # jika get request tampilkan halaman
    if request.method == "GET":
        return render_template("encrypt.html", active_page="encrypt")

    # proses enkripsi file jika post request
    try:
        if "file" not in request.files:
            return jsonify({"success": False, "error": "File tidak ditemukan."}), 400

        uploaded_file = request.files["file"]
        if not uploaded_file or uploaded_file.filename == "":
            return jsonify({"success": False, "error": "File tidak ditemukan."}), 400

        # baca isi file biner
        file_bytes = uploaded_file.read()
        password = request.form.get("password", "")
        algorithm = request.form.get("algorithm", "AES-256-GCM")

        # jalankan enkripsi lewat service
        result = encrypt_file_data(
            file_bytes=file_bytes,
            password=password,
            algorithm=algorithm,
            original_filename=uploaded_file.filename
        )

        # kirim metadata hasil enkripsi ke frontend
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
        return jsonify({"success": False, "error": "Enkripsi gagal diproses."}), 500


# HALAMAN RECEIVE & DECRYPT (PLACEHOLDER)
@main_bp.route("/decrypt")
def decrypt():
    return render_template("decrypt.html", active_page="decrypt")


# HALAMAN TESTING (PLACEHOLDER)
@main_bp.route("/testing")
def testing():
    return render_template("testing.html", active_page="testing")
