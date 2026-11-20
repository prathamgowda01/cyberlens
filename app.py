import os
import re
import joblib
from urllib.parse import urlparse
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# Load pre-trained models
text_model = joblib.load("text_model.joblib")
url_model = joblib.load("url_model.joblib")

TRUSTED_DOMAINS = {
    'google.com', 'github.com', 'wikipedia.org', 'stackoverflow.com',
    'mozilla.org', 'microsoft.com', 'apple.com', 'amazon.com', 'amazon.in',
    'youtube.com', 'linkedin.com', 'openai.com', 'python.org', 'kaggle.com'
}

SUSPICIOUS_TLDS = ('.xyz', '.tk', '.top', '.ru', '.cn', '.pw', '.cc', '.ga', '.cf', '.ml')
URL_RED_FLAGS = [
    'login', 'verify', 'secure', 'banking', 'account', 'update', 'suspended',
    'kyc', 'signin', 'password', 'paypal', 'amaz0n', 'crack', 'free-software',
    'wp-includes', 'auth-reset', '.exe', '.zip', '.scr'
]
TEXT_RED_FLAGS = [
    'urgent', 'suspended', 'verify', 'password', 'kyc', 'credit card', 'otp',
    'gift card', 'winner', 'claim your prize', 'payment failed', 'billing',
    'payroll', 'credentials', 'final warning', 'unclaimed', 'tax refund',
    'bank account', 'routing number', 'click the link', 'permanent closure'
]

def is_url(text):
    text = text.strip()
    if " " in text:
        return False
    return bool(re.match(r'^(https?://|www\.)', text, re.IGNORECASE)) or ('.' in text and len(text) < 250)

def get_base_domain(url):
    if not re.match(r'^https?://', url, re.IGNORECASE):
        url = 'http://' + url
    host = urlparse(url).netloc.lower().split(':')[0]
    parts = host.split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return host

@app.route('/')
def home():
    return send_from_directory('.', 'index.html')

@app.route('/api/scan', methods=['POST'])
def scan_input():
    data = request.get_json()
    user_input = data.get('input', '').strip()
    mode = data.get('mode', '').lower()

    if not user_input:
        return jsonify({'error': 'No input provided'}), 400

    # --- URL SCANNER ---
    if 'url' in mode or 'malware' in mode or is_url(user_input):
        lower_url = user_input.lower()
        base_domain = get_base_domain(lower_url)

        # 1. Strip http(s):// and www. so the ML model doesn't overreact to https://
        clean_url = re.sub(r'^https?://(www\.)?', '', lower_url)
        probabilities = url_model.predict_proba([clean_url])[0]
        classes = [str(c).lower() for c in url_model.classes_]

        safe_labels = ['benign', 'good', 'safe', 'legitimate', '0']
        safe_prob = sum(probabilities[i] for i, c in enumerate(classes) if c in safe_labels)
        ml_risk = int((1.0 - safe_prob) * 100)

        # 2. Check trusted domains
        if base_domain in TRUSTED_DOMAINS and not any(flag in lower_url for flag in ['.exe', 'verify-now', 'suspended']):
            risk_score = min(ml_risk, 12)
            return jsonify({
                'input': user_input,
                'model_used': 'URL Scanner Model',
                'prediction': 'benign',
                'risk_score': risk_score,
                'status': 'Safe'
            })

        # 3. Hybrid heuristic boost for obvious malicious patterns
        boost = 0
        if re.search(r'https?://\d{1,3}(\.\d{1,3}){3}', lower_url):  # Raw IP address
            boost += 45
        if any(base_domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
            boost += 30
        matched_flags = sum(1 for flag in URL_RED_FLAGS if flag in lower_url)
        boost += min(matched_flags * 18, 50)
        if lower_url.startswith('http://'):
            boost += 10

        risk_score = min(99, max(ml_risk, ml_risk // 2 + boost))
        is_threat = risk_score >= 55

        return jsonify({
            'input': user_input,
            'model_used': 'URL Scanner Model',
            'prediction': 'malware/phishing' if is_threat else 'benign',
            'risk_score': risk_score,
            'status': 'Threat Detected' if is_threat else 'Safe'
        })

    # --- EMAIL / TEXT PHISHING SCANNER ---
    else:
        lower_text = user_input.lower()
        probabilities = text_model.predict_proba([user_input])[0]
        classes = list(text_model.classes_)
        threat_prob = probabilities[classes.index(1)] if 1 in classes else 0.0
        ml_risk = int(threat_prob * 100)

        matched_flags = sum(1 for flag in TEXT_RED_FLAGS if flag in lower_text)

        if matched_flags == 0:
            # Dampen false positives on short, normal everyday messages
            risk_score = min(ml_risk, 28) if ml_risk < 75 else ml_risk - 25
        else:
            risk_score = min(99, max(ml_risk, 55 + matched_flags * 14))

        is_threat = risk_score >= 60

        return jsonify({
            'input': user_input,
            'model_used': 'Email/Text Phishing Model',
            'prediction': 'phishing' if is_threat else 'benign',
            'risk_score': risk_score,
            'status': 'Threat Detected' if is_threat else 'Safe'
        })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
