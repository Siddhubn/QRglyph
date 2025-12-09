
"""
QRglyph Routes
"""
from flask import Blueprint, render_template, request, redirect, url_for, flash, send_file, jsonify, current_app
from .utils import generate_qr, decode_qr, trust_check, expand_url, gsb_check
import copy
from PIL import Image
import io
import base64

main_bp = Blueprint('main', __name__)

# Single QR Generation Route
@main_bp.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        data = request.form.get('qr-content')
        fill_color = request.form.get('qr-color', '#00ff00')
        back_color = request.form.get('bg-color', '#000000')
        logo_file = request.files.get('logo')
        logo_img = None
        if logo_file and logo_file.filename:
            try:
                logo_img = Image.open(logo_file.stream)
            except Exception:
                logo_img = None
        img = generate_qr(data, fill_color=fill_color, back_color=back_color, logo_path=logo_img)
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        buf.seek(0)
        img_b64 = base64.b64encode(buf.read()).decode('utf-8')
        decoded = decode_qr(img)
        # If decode_qr fails, use the original data for trust check and display
        if not decoded:
            decoded = data
        trust = trust_check(decoded or '')
        # Preserve the original local trust check so we can show both results
        trust_local = copy.deepcopy(trust)
        trust['local'] = trust_local
        # Mark whether GSB was checked and store results separately; do not overwrite local results unless GSB flags.
        trust['gsb_checked'] = False
        try:
                # Determine URL to check (supports bare domains detected by trust_check)
                url_to_check = None
                if isinstance(decoded, str):
                    s = decoded.strip()
                    if s.lower().startswith(('http://', 'https://')):
                        url_to_check = s
                    else:
                        details = trust_local.get('details', {})
                        canonical = details.get('canonical_urls') or []
                        if canonical:
                            url_to_check = canonical[0]
                if url_to_check and trust_local.get('score') != 'dangerous':
                    trust['gsb_checked'] = True
                    gsb_matches = gsb_check(url_to_check.strip())
                    # Always attach the raw GSB response (may be empty)
                    trust['gsb'] = gsb_matches or {}
                    trust['gsb_flagged'] = bool(gsb_matches)
                    if gsb_matches:
                        # annotate trust with GSB results and escalate the overall score
                        trust['reasons'] = list(trust_local.get('reasons', [])) + ['Flagged by Google Safe Browsing']
                        trust['details'] = dict(trust_local.get('details', {}))
                        trust['details']['gsb_matches'] = gsb_matches
                        trust['score'] = 'dangerous'
                        trust['icon'] = '\u274C'
        except Exception:
            # keep original trust if GSB check fails
            trust['gsb_checked'] = False
        return render_template('index.html',
            qr_image=img_b64,
            decoded=decoded,
            trust=trust,
            form_data={
                'qr-content': data,
                'qr-color': fill_color,
                'bg-color': back_color
            }
        )
    # On GET, do not pass any QR data (clears previous result)
    return render_template('index.html', qr_image=None, decoded=None, trust=None, form_data=None)

# Multi QR Generation Route
@main_bp.route('/multi', methods=['GET', 'POST'])
def multi_qr():
    qr_results = []
    form_data = []
    num_qrs = 1
    if request.method == 'POST':
        try:
            num_qrs = int(request.form.get('num_qrs', 1))
        except Exception:
            num_qrs = 1
        num_qrs = max(1, min(10, num_qrs))
        for i in range(1, num_qrs+1):
            label = request.form.get(f'label_{i}', f'QR {i}')
            data = request.form.get(f'qr-content_{i}', '')
            color = request.form.get(f'qr-color_{i}', '#00ff00')
            form_data.append({'label': label, 'qr-content': data, 'qr-color': color})
            if data:
                img = generate_qr(data, fill_color=color, back_color='#000000')
                buf = io.BytesIO()
                img.save(buf, format='PNG')
                buf.seek(0)
                img_b64 = base64.b64encode(buf.read()).decode('utf-8')
                decoded = decode_qr(img)
                if not decoded:
                    decoded = data
                trust = trust_check(decoded or '')
                trust_local = copy.deepcopy(trust)
                trust['local'] = trust_local
                trust['gsb_checked'] = False
                try:
                    # Determine URL to check (supports bare domains detected by trust_check)
                    url_to_check = None
                    if isinstance(decoded, str):
                        s = decoded.strip()
                        if s.lower().startswith(('http://', 'https://')):
                            url_to_check = s
                        else:
                            details = trust_local.get('details', {})
                            canonical = details.get('canonical_urls') or []
                            if canonical:
                                url_to_check = canonical[0]
                    if url_to_check and trust_local.get('score') != 'dangerous':
                        trust['gsb_checked'] = True
                        gsb_matches = gsb_check(url_to_check.strip())
                        trust['gsb'] = gsb_matches or {}
                        trust['gsb_flagged'] = bool(gsb_matches)
                        if gsb_matches:
                            trust['reasons'] = list(trust_local.get('reasons', [])) + ['Flagged by Google Safe Browsing']
                            trust['details'] = dict(trust_local.get('details', {}))
                            trust['details']['gsb_matches'] = gsb_matches
                            trust['score'] = 'dangerous'
                            trust['icon'] = '\u274C'
                except Exception:
                    trust['gsb_checked'] = False
                qr_results.append({
                    'label': label,
                    'qr_image': img_b64,
                    'decoded': decoded,
                    'trust': trust,
                    'color': color,
                    'qr-content': data
                })
        while len(form_data) < num_qrs:
            form_data.append({'label': f'QR {len(form_data)+1}', 'qr-content': '', 'qr-color': '#00ff00'})
        return render_template('multi.html', qr_results=qr_results, form_data=form_data)
    # GET: default to 1 QR
    form_data = [{'label': 'QR 1', 'qr-content': '', 'qr-color': '#00ff00'}]
    return render_template('multi.html', qr_results=None, form_data=form_data)

# QR Verification Route
@main_bp.route('/verify', methods=['GET', 'POST'])
def verify_qr():
    result = None
    if request.method == 'POST':
        qr_file = request.files.get('qr-image')
        if qr_file and qr_file.filename:
            try:
                img = Image.open(qr_file.stream)
                decoded = decode_qr(img)
                if not decoded:
                    decoded = ''
                trust = trust_check(decoded or '')
                trust_local = copy.deepcopy(trust)
                trust['local'] = trust_local
                trust['gsb_checked'] = False
                try:
                    # Determine URL to check (supports bare domains detected by trust_check)
                    url_to_check = None
                    if isinstance(decoded, str):
                        s = decoded.strip()
                        if s.lower().startswith(('http://', 'https://')):
                            url_to_check = s
                        else:
                            details = trust_local.get('details', {})
                            canonical = details.get('canonical_urls') or []
                            if canonical:
                                url_to_check = canonical[0]
                    if url_to_check and trust_local.get('score') != 'dangerous':
                        trust['gsb_checked'] = True
                        gsb_matches = gsb_check(url_to_check.strip())
                        trust['gsb'] = gsb_matches or {}
                        trust['gsb_flagged'] = bool(gsb_matches)
                        if gsb_matches:
                            trust['reasons'] = list(trust_local.get('reasons', [])) + ['Flagged by Google Safe Browsing']
                            trust['details'] = dict(trust_local.get('details', {}))
                            trust['details']['gsb_matches'] = gsb_matches
                            trust['score'] = 'dangerous'
                            trust['icon'] = '\u274C'
                except Exception:
                    trust['gsb_checked'] = False
                buf = io.BytesIO()
                img.save(buf, format='PNG')
                buf.seek(0)
                img_b64 = base64.b64encode(buf.read()).decode('utf-8')
                result = {
                    'qr_image': img_b64,
                    'decoded': decoded,
                    'trust': trust
                }
            except Exception as e:
                result = {'error': f'Could not process image: {e}'}
        else:
            result = {'error': 'No image uploaded.'}
    return render_template('verify.html', result=result)

# Camera-based QR Verification Route
@main_bp.route('/verify/camera', methods=['GET', 'POST'])
def verify_camera():
    result = None
    if request.method == 'POST':
        qr_content = request.form.get('qr-content')
        if qr_content:
            trust = trust_check(qr_content)
            trust_local = copy.deepcopy(trust)
            trust['local'] = trust_local
            trust['gsb_checked'] = False
            try:
                # Determine URL to check (supports bare domains detected by trust_check)
                url_to_check = None
                if isinstance(qr_content, str):
                    s = qr_content.strip()
                    if s.lower().startswith(('http://', 'https://')):
                        url_to_check = s
                    else:
                        details = trust_local.get('details', {})
                        canonical = details.get('canonical_urls') or []
                        if canonical:
                            url_to_check = canonical[0]
                if url_to_check and trust_local.get('score') != 'dangerous':
                    trust['gsb_checked'] = True
                    gsb_matches = gsb_check(url_to_check.strip())
                    trust['gsb'] = gsb_matches or {}
                    trust['gsb_flagged'] = bool(gsb_matches)
                    if gsb_matches:
                        trust['reasons'] = list(trust_local.get('reasons', [])) + ['Flagged by Google Safe Browsing']
                        trust['details'] = dict(trust_local.get('details', {}))
                        trust['details']['gsb_matches'] = gsb_matches
                        trust['score'] = 'dangerous'
                        trust['icon'] = '\u274C'
            except Exception:
                trust['gsb_checked'] = False
            result = {
                'decoded': qr_content,
                'trust': trust
            }
        else:
            result = {'error': 'No QR content received.'}
    return render_template('verify_camera.html', result=result)


@main_bp.route('/api/verify_qr', methods=['POST'])
def api_verify_qr():
    """API endpoint used by camera page to verify scanned QR content.
    Returns JSON with trust result and whether content looks like a URL.
    For safety, when the content is determined 'dangerous' the URL is not echoed back.
    """
    data = request.get_json(silent=True) or {}
    qr_content = data.get('qr_content') or request.form.get('qr_content')
    if not qr_content:
        return jsonify({'error': 'No qr_content provided.'}), 400

    trust = trust_check(qr_content)
    trust_local = copy.deepcopy(trust)
    trust['local'] = trust_local
    trust['gsb_checked'] = False
    try:
        # Determine URL to check (supports bare domains detected by trust_check)
        url_to_check = None
        if isinstance(qr_content, str):
            s = qr_content.strip()
            if s.lower().startswith(('http://', 'https://')):
                url_to_check = s
            else:
                details = trust_local.get('details', {})
                canonical = details.get('canonical_urls') or []
                if canonical:
                    url_to_check = canonical[0]
        if url_to_check and trust_local.get('score') != 'dangerous':
            trust['gsb_checked'] = True
            gsb_matches = gsb_check(url_to_check.strip())
            trust['gsb'] = gsb_matches or {}
            trust['gsb_flagged'] = bool(gsb_matches)
            if gsb_matches:
                trust['reasons'] = list(trust_local.get('reasons', [])) + ['Flagged by Google Safe Browsing']
                trust['details'] = dict(trust_local.get('details', {}))
                trust['details']['gsb_matches'] = gsb_matches
                trust['score'] = 'dangerous'
                trust['icon'] = '\u274C'
    except Exception:
        trust['gsb_checked'] = False
    # Basic URL detection
    is_url = False
    url_value = None
    if isinstance(qr_content, str) and qr_content.strip().lower().startswith(('http://', 'https://')):
        is_url = True
        url_value = qr_content.strip()

    resp = {
        'decoded': qr_content if trust.get('score') != 'dangerous' else None,
        'trust': trust,
        'is_url': is_url
    }
    # Only include the URL text for safe or suspicious; exclude for dangerous
    if is_url and trust.get('score') in ('safe', 'suspicious'):
        resp['url'] = url_value

    return jsonify(resp)


# Landing / Home page for product overview
@main_bp.route('/home', methods=['GET'])
def home_landing():
    return render_template('landing.html')
