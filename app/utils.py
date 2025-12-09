"""
QRglyph Utility Functions
"""
import qrcode
from PIL import Image
import requests
import re
import os
import logging
from urllib.parse import urlparse
from math import log2


def gsb_check(url, api_key=None, timeout=6.0):
    """
    Query Google Safe Browsing v4 API for the provided URL.

    Returns a dict with raw API response (matches) or an empty dict on no match/error.
    """
    if not url or not isinstance(url, str):
        return {}
    key = api_key or os.environ.get('GSB_API_KEY')
    if not key:
        logging.debug('GSB API key not configured; skipping GSB check')
        return {}

    endpoint = f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}'
    payload = {
        'client': {
            'clientId': 'qrglyph',
            'clientVersion': '1.0'
        },
        'threatInfo': {
            'threatTypes': [
                'MALWARE', 'SOCIAL_ENGINEERING', 'POTENTIALLY_HARMFUL_APPLICATION', 'UNWANTED_SOFTWARE'
            ],
            'platformTypes': ['ANY_PLATFORM'],
            'threatEntryTypes': ['URL'],
            'threatEntries': [{'url': url}]
        }
    }
    try:
        resp = requests.post(endpoint, json=payload, timeout=timeout)
        if resp.status_code != 200:
            logging.warning(f'GSB check failed status {resp.status_code}: {resp.text}')
            return {}
        data = resp.json()
        return data.get('matches', {}) or {}
    except Exception as e:
        logging.warning(f'GSB check exception: {e}')
        return {}


def generate_qr(data, fill_color='black', back_color='white', logo_path=None):
    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_H)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color=fill_color, back_color=back_color).convert('RGB')
    if logo_path is not None:
        try:
            if isinstance(logo_path, Image.Image):
                logo = logo_path
            else:
                logo = Image.open(logo_path)
            qr_w, qr_h = img.size
            logo_ratio = 0.22
            logo_size = max(16, int(min(qr_w, qr_h) * logo_ratio))
            logo = logo.convert('RGBA')
            logo = logo.resize((logo_size, logo_size), Image.LANCZOS)

            bg_pad = int(max(2, logo_size * 0.04))
            bg_size = logo_size + (bg_pad * 2)
            bg = Image.new('RGBA', (bg_size, bg_size), (255, 255, 255, 255))

            bg_pos = ((qr_w - bg_size) // 2, (qr_h - bg_size) // 2)
            logo_pos = ((qr_w - logo_size) // 2, (qr_h - logo_size) // 2)

            img = img.convert('RGBA')
            img.paste(bg, bg_pos, mask=bg)
            img.paste(logo, logo_pos, mask=logo)
            img = img.convert('RGB')
        except Exception as e:
            logging.warning(f"Logo embedding failed: {e}")
    return img


def decode_qr(image):
    try:
        from pyzbar.pyzbar import decode as _decode
    except Exception:
        logging.warning('pyzbar or zbar not available; QR decoding disabled')
        return None
    try:
        decoded = _decode(image)
        if decoded:
            return decoded[0].data.decode('utf-8')
    except Exception as e:
        logging.warning(f'QR decode failed: {e}')
    return None


def expand_url(url):
    try:
        resp = requests.head(url, allow_redirects=True, timeout=5)
        return resp.url
    except Exception:
        return url


def trust_check(content):
    """
    Enhanced local trust scoring algorithm (no external APIs).
    Returns a dict with keys: score ('safe'|'suspicious'|'dangerous'), icon, reasons, details.
    """
    def shannon_entropy(s: str) -> float:
        if not s:
            return 0.0
        prob = {}
        for ch in s:
            prob[ch] = prob.get(ch, 0) + 1
        probs = [v/len(s) for v in prob.values()]
        return -sum(p * log2(p) for p in probs)

    reasons = []
    score = 'safe'
    icon_map = {'safe': '\u2705', 'suspicious': '\u26a0', 'dangerous': '\u274C'}

    domain_like = r"\b(?:https?://)?(?:www\.)?[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?:/[^\s<>\"']*)?"
    url_candidates = re.findall(domain_like, content or '')

    suspicious_keywords = set([
        'login', 'verify', 'update', 'secure', 'account', 'bank', 'paypal', 'confirm', 'signin', 'webscr',
        'security', 'ebay', 'apple', 'amazon', 'dropbox', 'wallet', 'crypto', 'blockchain', 'password', 'reset',
        'admin', 'support', 'alert', 'invoice', 'payment', 'gift', 'bonus', 'free', 'prize', 'urgent', 'win', 'winner'
    ])
    shorteners = ['bit.ly', 'tinyurl', 't.co', 'goo.gl', 'ow.ly', 'buff.ly', 'is.gd', 'cutt.ly', 'shorte.st', 'adf.ly', 'rebrand.ly']
    homoglyphs = {'\u0430', '\u0435', '\u0456', '\u043e', '\u0440', '\u0441', '\u0445', '\u0443', '\u0451', '\u04cf'}

    urls = []
    canonical_urls = []

    ext_regex = re.compile(r'\.(exe|scr|zip|bat|js|vbs|jar|apk|msi|dll|php|asp|aspx|pif|cmd|cpl|gadget|wsf|lnk|sh|bin|dat|run|msu|ps1|vb|vbe|wsh)(?:$|[\?\/#\s])', re.I)

    for raw in url_candidates:
        had_scheme = bool(re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', raw or ''))
        parsed = urlparse(raw if had_scheme else ('http://' + raw))
        host = parsed.hostname or ''
        path = parsed.path or ''
        query = parsed.query or ''
        scheme = parsed.scheme or ''

        urls.append(raw)
        if had_scheme:
            # preserve provided scheme when present
            canonical_urls.append(f"{scheme}://{host}{path or ''}{'?' + query if query else ''}")
        else:
            # prefer https for canonicalized bare domains
            canonical_urls.append('https://' + host + (path or ''))

        for s in shorteners:
            if host and host.lower() == s:
                reasons.append('Shortened URL detected')
                score = 'suspicious' if score != 'dangerous' else score

        if scheme != 'https':
            reasons.append('Non-HTTPS URL')
            score = 'suspicious' if score != 'dangerous' else score

        if parsed.username or parsed.password:
            reasons.append('Credentials present in URL')
            score = 'dangerous'

        if ext_regex.search(raw) or ext_regex.search(path):
            reasons.append('Suspicious file extension in URL or token')
            score = 'dangerous'

        if 'http://' in raw[7:] or 'https://' in raw[8:]:
            reasons.append('Nested URL detected inside path')
            score = 'dangerous'

        if re.match(r'^\d+\.\d+\.\d+\.\d+$', host or ''):
            reasons.append('URL uses IP address instead of domain')
            score = 'suspicious'

        parts = (host or '').split('.')
        if len(parts) > 4:
            reasons.append('Excessive subdomains (possible masking)')
            score = 'suspicious' if score != 'dangerous' else score

        combined = (host + path + query).lower()
        if any(kw in combined for kw in suspicious_keywords):
            reasons.append('Suspicious keyword found in URL')
            score = 'suspicious' if score != 'dangerous' else score

        if any(ch in raw for ch in homoglyphs):
            reasons.append('Possible homograph (unicode lookalike)')
            score = 'dangerous'

        if len(raw) > 120:
            reasons.append('Unusually long URL')
            score = 'suspicious' if score != 'dangerous' else score

        ent = shannon_entropy(host or '')
        if ent and ent > 4.0:
            reasons.append(f'High entropy hostname ({ent:.2f}) — random-looking domain')
            score = 'suspicious' if score != 'dangerous' else score

    if not urls:
        txt = (content or '').lower()
        if any(kw in txt for kw in suspicious_keywords):
            reasons.append('Suspicious keyword found in content')
            score = 'suspicious'
        if len(txt) > 200 and (txt.count(' ') < max(1, len(txt)//30)):
            reasons.append('Long single-line content (possible obfuscated link)')
            score = 'suspicious'

    if not reasons:
        reasons.append('No issues detected')

    details = {'urls': urls, 'canonical_urls': canonical_urls, 'reasons': reasons}
    return {'score': score, 'icon': icon_map[score], 'reasons': reasons, 'details': details}

