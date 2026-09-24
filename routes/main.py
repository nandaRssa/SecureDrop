"""
Main application routes handling UI rendering.
"""

from flask import Blueprint, render_template, redirect, url_for

main_bp = Blueprint("main", __name__)


@main_bp.route("/")
def index():
    """Redirect route utama ke halaman Encrypt & Send."""
    return redirect(url_for("main.encrypt"))


@main_bp.route("/encrypt")
def encrypt():
    """Halaman Encrypt & Send (Modul Orang 1)."""
    return render_template("encrypt.html", active_page="encrypt")


@main_bp.route("/decrypt")
def decrypt():
    """Halaman Receive & Decrypt (Placeholder Modul Orang 2)."""
    return render_template("decrypt.html", active_page="decrypt")


@main_bp.route("/testing")
def testing():
    """Halaman Security Testing (Placeholder Modul Orang 3)."""
    return render_template("testing.html", active_page="testing")
