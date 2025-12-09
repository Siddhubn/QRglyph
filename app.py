"""
QRglyph Flask App Entrypoint
"""
import os
from app import create_app

app = create_app()

if __name__ == '__main__':
    # Use PORT env var when provided (Render sets $PORT). Listen on 0.0.0.0.
    port = int(os.environ.get('PORT', 5000))
    debug_env = os.environ.get('FLASK_ENV', '').lower() != 'production'
    app.run(host='0.0.0.0', port=port, debug=debug_env)
