"""
SecureDrop - Entry Point Aplikasi Flask.
"""

from flask import Flask
from routes.main import main_bp


def create_app() -> Flask:
    """Factory function untuk inisialisasi aplikasi Flask."""
    app = Flask(__name__)
    
    # Register blueprints
    app.register_blueprint(main_bp)

    return app


app = create_app()

if __name__ == "__main__":
    # Menjalankan server development lokal
    app.run(host="127.0.0.1", port=5000, debug=False)
