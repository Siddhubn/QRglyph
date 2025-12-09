"""WSGI entrypoint for Gunicorn/Render.

Expose a top-level `app` variable so Gunicorn can import `wsgi:app`.
This avoids ambiguity between the `app` package and the top-level `app.py` file.
"""
from app import create_app

app = create_app()


if __name__ == '__main__':
    # Simple local run for quick smoke testing
    app.run(host='0.0.0.0', port=5000, debug=True)
