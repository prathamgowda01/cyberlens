import os
import re
import joblib
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# Load pre-trained models directly (no CSVs needed on the server)
text_model = joblib.load("text_model.joblib")
url_model = joblib.load("url_model.joblib")

def is_url(text):
    text = text.strip()
    if " " in text:
        return False
    return bool(re.match(r'^(https?://|www\.)', text, re.IGNORECASE)) or ('.' in text and len(text) < 250)

# Serve index.html as the homepage
@app.route('/')
def home():
    return send_from_directory('.', 'index.html')

# API Endpoint for CyberLens
@app.route('/api/scan', methods=['POST'])
def scan_input():
    data = request.get_json()
    user_input = data.get('input', '').strip()
    mode = data.get('mode', '').lower()

    if not user_input:
        return jsonify({'error': 'No input provided'}), 400

    if 'url' in mode or 'malware' in mode or is_url(user_input):
        prediction = str(url_model.predict([user_input])[0]).lower()
        probabilities = url_model.predict_proba([user_input])[0]
        classes = [str(c).lower() for c in url_model.classes_]

        safe_labels = ['benign', 'good', 'safe', 'legitimate', '0']
        safe_prob = sum(probabilities[i] for i, c in enumerate(classes) if c in safe_labels)
        risk_score = int((1.0 - safe_prob) * 100)
        is_safe = prediction in safe_labels

        return jsonify({
            'input': user_input,
            'model_used': 'URL Scanner Model',
            'prediction': 'benign' if is_safe else prediction,
            'risk_score': risk_score,
            'status': 'Safe' if is_safe else 'Threat Detected'
        })
    else:
        prediction = int(text_model.predict([user_input])[0])
        probabilities = text_model.predict_proba([user_input])[0]
        classes = list(text_model.classes_)

        threat_prob = probabilities[classes.index(1)] if 1 in classes else 0.0
        risk_score = int(threat_prob * 100)

        return jsonify({
            'input': user_input,
            'model_used': 'Email/Text Phishing Model',
            'prediction': 'phishing' if prediction == 1 else 'benign',
            'risk_score': risk_score,
            'status': 'Threat Detected' if prediction == 1 else 'Safe'
        })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)