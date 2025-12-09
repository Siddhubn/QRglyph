"""
QRglyph Flask App Factory
"""
import os
from flask import Flask
from dotenv import load_dotenv

def create_app():
    load_dotenv()
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev')
    app.config['GSB_API_KEY'] = os.getenv('GSB_API_KEY')
    app.config['VT_API_KEY'] = os.getenv('VT_API_KEY')
    app.config['PHISHTANK_API_KEY'] = os.getenv('PHISHTANK_API_KEY')
    app.config['WHOIS_API_KEY'] = os.getenv('WHOIS_API_KEY')
    app.config['IPQS_API_KEY'] = os.getenv('IPQS_API_KEY')

    from .routes import main_bp
    app.register_blueprint(main_bp)
    return app


# Expose a top-level Flask instance for WSGI servers that reference `app:app`.
# Some hosts or existing start commands may still point to `app:app` instead
# of `wsgi:app`. Creating this at import-time ensures compatibility.
try:
    app = create_app()
except Exception:
    # If initialization fails at import time (missing env, optional deps),
    # avoid crashing module import. WSGI servers will raise errors on startup
    # anyway; this keeps import-time effects minimal.
    app = None

