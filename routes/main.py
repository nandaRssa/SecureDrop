import base64
import json

from flask import Blueprint, current_app, render_template, redirect, url_for, request, jsonify
from services.encryption_service import encrypt_file_data
from services.sdrop_service import (
    AuthenticationError,
    SdropFormatError,
    create_hybrid_sdrop,
    decrypt_hybrid_sdrop,
    decrypt_sdrop,
    generate_rsa_key_pair,
    package_encryption_result,
)
from services.security_testing_service import run_security_testing_suite

main_bp = Blueprint("main", __name__)


@main_bp.route("/")
def index():
    return redirect(url_for("main.encrypt"))


@main_bp.route("/generate-keys", methods=["GET", "POST"])
def generate_keys():
    try:
        private_bytes, public_bytes = generate_rsa_key_pair(2048)
        return jsonify({
            "success": True,
            "private_key": private_bytes.decode("ascii"),
            "public_key": public_bytes.decode("ascii"),
        }), 200
    except Exception as err:
        return jsonify({"success": False, "error": str(err)}), 500


@main_bp.route("/encrypt", methods=["GET", "POST"])
def encrypt():
    if request.method == "GET":
        return render_template("encrypt.html", active_page="encrypt")

    try:
        if "file" not in request.files:
            return jsonify({"success": False, "error": "File tidak ditemukan"}), 400

        uploaded_file = request.files["file"]
        if not uploaded_file or uploaded_file.filename == "":
            return jsonify({"success": False, "error": "File tidak ditemukan"}), 400

        file_bytes = uploaded_file.read()
        mode = request.form.get("mode", "password")
        public_key_file = request.files.get("public_key")
        public_key_text = request.form.get("public_key_text", "").strip()

        # Cek apakah mode Enkripsi Hibrida
        if mode == "hybrid":
            pub_bytes = None
            if public_key_text and public_key_text.strip():
                pub_bytes = public_key_text.strip().encode("utf-8")
            elif public_key_file and getattr(public_key_file, "filename", ""):
                pub_bytes = public_key_file.read().strip()

            if not pub_bytes:
                return jsonify({"success": False, "error": "Public Key RSA (.pem) belum diunggah atau diisi"}), 400

            sdrop_bytes = create_hybrid_sdrop(
                file_bytes=file_bytes,
                public_key=pub_bytes,
                original_filename=uploaded_file.filename
            )
            sdrop_doc = json.loads(sdrop_bytes)
            raw_ciphertext = base64.b64decode(sdrop_doc["ciphertext"])
            raw_nonce = base64.b64decode(sdrop_doc["nonce"])
            raw_tag = base64.b64decode(sdrop_doc["tag"])

            return jsonify({
                "success": True,
                "message": "Enkripsi Hibrida (RSA-OAEP + AES-256-GCM) berhasil diproses",
                "data": {
                    "original_filename": uploaded_file.filename,
                    "algorithm": "AES-256-GCM (RSA-OAEP Wrapped)",
                    "file_size": len(file_bytes),
                    "encrypted_size": len(raw_ciphertext),
                    "salt_length": 0,
                    "nonce_length": len(raw_nonce),
                    "tag_length": len(raw_tag),
                    "nonce_hex": raw_nonce.hex(),
                    "tag_hex": raw_tag.hex(),
                    "ciphertext_base64": sdrop_doc["ciphertext"],
                    "ciphertext_hex": raw_ciphertext.hex(),
                    "sdrop_filename": f"{uploaded_file.filename}.sdrop",
                    "sdrop_base64": base64.b64encode(sdrop_bytes).decode("ascii")
                }
            }), 200

        # Mode standar berbasis password
        password = request.form.get("password", "")
        algorithm = request.form.get("algorithm", "AES-256-GCM")

        result = encrypt_file_data(
            file_bytes=file_bytes,
            password=password,
            algorithm=algorithm,
            original_filename=uploaded_file.filename
        )
        sdrop_bytes = package_encryption_result(result)

        return jsonify({
            "success": True,
            "message": "Enkripsi berhasil diproses",
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
                "ciphertext_base64": base64.b64encode(result.ciphertext).decode("ascii"),
                "ciphertext_hex": result.ciphertext.hex(),
                "sdrop_filename": f"{result.original_filename}.sdrop",
                "sdrop_base64": base64.b64encode(sdrop_bytes).decode("ascii")
            }
        }), 200

    except (ValueError, TypeError) as err:
        return jsonify({"success": False, "error": str(err)}), 400
    except Exception as exc:
        return jsonify({"success": False, "error": f"Enkripsi gagal diproses: {str(exc)}"}), 500


# HALAMAN RECEIVE & DECRYPT (PLACEHOLDER)
@main_bp.route("/decrypt", methods=["GET", "POST"])
def decrypt():
    if request.method == "GET":
        return render_template("decrypt.html", active_page="decrypt")

    try:
        if "file" not in request.files or not request.files["file"].filename:
            return jsonify({"success": False, "error": "File .sdrop tidak ditemukan"}), 400
        package_bytes = request.files["file"].read()
        private_key = request.files.get("private_key")
        if private_key and private_key.filename:
            plaintext, filename = decrypt_hybrid_sdrop(package_bytes, private_key.read())
        else:
            password = request.form.get("password", "")
            plaintext, filename = decrypt_sdrop(package_bytes, password)
        return jsonify({
            "success": True,
            "message": "Decryption berhasil dan authentication tag terverifikasi",
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
    except Exception as exc:
        return jsonify({"success": False, "error": f"Decryption gagal diproses: {str(exc)}"}), 500


# HALAMAN TESTING (PLACEHOLDER)
@main_bp.route("/testing")
def testing():
    return render_template("testing.html", active_page="testing")


@main_bp.route("/testing/run", methods=["POST"])
def testing_run():
    uploaded_files = request.files.getlist("files")
    if not uploaded_files and request.files.get("file") is not None:
        uploaded_files = [request.files.get("file")]
    try:
        report = run_security_testing_suite(
            quick=current_app.config.get("TESTING", False),
            files=uploaded_files,
        )
        return jsonify({"success": True, "message": "Security testing selesai", "data": report}), 200
    except (ValueError, TypeError) as err:
        return jsonify({"success": False, "error": str(err)}), 400
    except Exception:
        return jsonify({"success": False, "error": "Security testing gagal diproses"}), 500
