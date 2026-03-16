# QRglyph

A modular, production-ready Flask web application for generating, decoding, and verifying QR codes with anti-scam trust checks.

## Features
- Single and multi QR generation with color and logo options
- QR decoding and anti-scam trust check (pattern-based, shortener expansion, Google Safe Browsing)
- QR verification via upload or camera
- Modern, hacker-inspired UI (responsive, accessible)
- Text-to-speech and sharing options for QR content
- Secure: uses environment variables for secrets
- Production-ready: Gunicorn, requirements.txt, render.yaml

## Setup
1. **Clone the repo:**
   ```bash
   git clone https://github.com/Siddhubn/QR-Gen.git
   cd QR-Gen
   ```
2. **Create a virtual environment and install dependencies:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```
    
   On Debian/Ubuntu you also need the `zbar` shared library for QR decoding:

   ```bash
   sudo apt update && sudo apt install -y libzbar0
   ```
3. **Configure environment variables:**
   - Copy `.env.example` to `.env` and set your `SECRET_KEY` (and `GSB_API_KEY` if available).

   If you don't install `zbar` the app will still run but QR image decoding (server-side) will be disabled.

4. **Run locally:**
   ```bash
   flask run
   # or
   python app.py
   ```

# QRglyph

QRglyph is a compact Flask web application for generating, sharing, and verifying QR codes. It prioritizes local-first trust checks and provides a mobile-friendly camera verification UI.

## Highlights / Features

- Single QR generator (color, background, optional embedded logo)
- Multi QR generation (batch labels, per-card controls)
- Image upload verification and camera-based scanning (jsQR client-side)
- Server-side trust analysis: local pattern checks for suspicious/dangerous content
- Camera verification API (`/api/verify_qr`) used by the camera UI to decide redirect/consent
- Responsive, modern UI with accessible controls, share/download helpers, and consent flows
- Lazy server-side QR decoding (graceful fallback if native zbar is missing)
- Landing page at `/home` and single QR generator at `/`

## System requirements

- Python 3.10 or newer (3.11 / 3.12 recommended)
- On Debian/Ubuntu: `libzbar0` is required for server-side decoding (pyzbar).
  - Install with: `sudo apt update && sudo apt install -y libzbar0`
- Modern browser for camera access (HTTPS required for camera on some platforms)

## Python dependencies

All Python dependencies are listed in `requirements.txt`. Key packages include:

- `Flask` — web framework
- `qrcode` and `Pillow` — QR generation and image handling
- `pyzbar` — server-side decoding (requires system `zbar`)
- `requests` — optional URL expansion
- `python-dotenv` — environment variable loading
- `gunicorn` — production WSGI server

Install dependencies:

```bash
python -m venv venv
venv/Scripts/activate
pip install -r requirements.txt
```

If you do not install `zbar` the application will still run; server-side decoding will be disabled but client-side scanning (jsQR) will continue to work.

## Environment configuration

- Copy `.env.example` → `.env` and set:
  - `SECRET_KEY` — Flask secret key
  - `GSB_API_KEY` — optional Google Safe Browsing API key (if you want external URL checks)

## Running locally

Start the development server:

```bash
python app.py
# or
flask run
```

Open these pages in your browser:

- Landing / Home: `http://127.0.0.1:5000/home`
- Single QR generator: `http://127.0.0.1:5000/`
- Multi QR: `http://127.0.0.1:5000/multi`
- Verify (upload): `http://127.0.0.1:5000/verify`
- Camera verify: `http://127.0.0.1:5000/verify/camera`

## Developer notes

- Server-side QR decoding uses a lazy import so the app won't crash if the system `zbar` library is missing. See `app/utils.py::decode_qr`.
- Logo embedding is handled in `app/utils.py::generate_qr`. If generated QRs fail to scan on some devices, reduce the `logo_ratio` variable in that function or remove the backing.
- The camera page scans client-side using `jsQR` and posts results to `/api/verify_qr` for a local trust assessment. The UI performs auto-redirects for safe URLs and presents consent flows for suspicious URLs.
- Landing page is `app/templates/landing.html` (route: `/home`); Single QR generator remains at `/`.

## File structure (important files)

```
app/
  ├─ __init__.py        # app factory + blueprint registration
  ├─ routes.py          # URL routes and API endpoints
  ├─ utils.py           # QR generation, decoding, trust logic
  ├─ templates/         # Jinja2 templates (index, multi, verify, camera, landing)
  └─ static/            # CSS, JS, images (qrglyph_logo.png)

app.py                 # entrypoint
requirements.txt       # Python deps
.env.example           # environment var template
render.yaml            # optional Render deployment config
README.md
```

## Troubleshooting

- If generated QR images with embedded logos aren't decoding, reduce `logo_ratio` in `app/utils.py` or remove the white backing.
- If server-side decoding fails, ensure `libzbar0` is installed; otherwise, the app will still run without server decode.

## Contributing

PRs welcome — open issues for UX bugs, accessibility, or feature requests.

## License

MIT
