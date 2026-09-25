import base64

from flask import Blueprint, render_template, redirect, url_for, request, jsonify
from services.encryption_service import encrypt_file_data
from services.sdrop_service import (
    AuthenticationError,
    SdropFormatError,
    decrypt_hybrid_sdrop,
    decrypt_sdrop,
    package_encryption_result,
)

main_bp = Blueprint("main", __name__)


@main_bp.route("/")
def index():
    return redirect(url_for("main.encrypt"))


@main_bp.route("/encrypt", methods=["GET", "POST"])
def encrypt():
    if request.method == "GET":
        return render_template("encrypt.html", active_page="encrypt")

    try:
        if "file" not in request.files:
            return jsonify({"success": False, "error": "File tidak ditemukan."}), 400

        uploaded_file = request.files["file"]
        if not uploaded_file or uploaded_file.filename == "":
            return jsonify({"success": False, "error": "File tidak ditemukan."}), 400

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
        sdrop_bytes = package_encryption_result(result)

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
                "tag_hex": result.tag.hex(),
                "sdrop_filename": f"{result.original_filename}.sdrop",
                "sdrop_base64": base64.b64encode(sdrop_bytes).decode("ascii")
            }
        }), 200

    except (ValueError, TypeError) as err:
        return jsonify({"success": False, "error": str(err)}), 400
    except Exception:
        return jsonify({"success": False, "error": "Enkripsi gagal diproses."}), 500


# HALAMAN RECEIVE & DECRYPT (PLACEHOLDER)
@main_bp.route("/decrypt", methods=["GET", "POST"])
def decrypt():
    if request.method == "GET":
        return render_template("decrypt.html", active_page="decrypt")

    try:
        if "file" not in request.files or not request.files["file"].filename:
            return jsonify({"success": False, "error": "File .sdrop tidak ditemukan."}), 400
        package_bytes = request.files["file"].read()
        private_key = request.files.get("private_key")
        if private_key and private_key.filename:
            plaintext, filename = decrypt_hybrid_sdrop(package_bytes, private_key.read())
        else:
            password = request.form.get("password", "")
            plaintext, filename = decrypt_sdrop(package_bytes, password)
        return jsonify({
            "success": True,
            "message": "Decryption berhasil dan authentication tag terverifikasi.",
            "data": {
                "original_filename": filename,
                "file_size": len(plaintext),
                "file_base64": base64.b64encode(plaintext).decode("ascii"),
            },
        }), 200
    except AuthenticationError as err:
        return jsonify({"success": False, "error": str(err)}), 400
    except (SdropFormatError, ValueError, TypeError) as err:
        return jsonify({"success": False, "error": str(err)}), 400
    except Exception:
        return jsonify({"success": False, "error": "Decryption gagal diproses."}), 500


# HALAMAN TESTING (PLACEHOLDER)
@main_bp.route("/testing")
def testing():
    return render_template("testing.html", active_page="testing")
