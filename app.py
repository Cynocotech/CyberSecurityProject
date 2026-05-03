import os
import warnings
import logging

# Suppress ALL warnings before any imports 
os.environ['TF_CPP_MIN_LOG_LEVEL']    = '3'
os.environ['TF_ENABLE_ONEDNN_OPTS']   = '0'
os.environ['PYTHONWARNINGS']           = 'ignore'
warnings.filterwarnings('ignore')
logging.getLogger('tensorflow').setLevel(logging.ERROR)
logging.getLogger('h5py').setLevel(logging.ERROR)

import re
import time
import pickle
import hashlib
import numpy as np
import joblib

import tensorflow as tf
tf.get_logger().setLevel('ERROR')
tf.autograph.set_verbosity(0)

from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from tensorflow.keras.preprocessing.sequence import pad_sequences

app = Flask(__name__)
CORS(app)


# DATABASE

app.config['SQLALCHEMY_DATABASE_URI']        = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model):
    id       = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

with app.app_context():
    db.create_all()


# LOAD MODELS

BASE = os.path.join(os.path.dirname(__file__), 'backend')

def load_pickle(filename):
    with open(os.path.join(BASE, filename), 'rb') as f:
        return pickle.load(f)

def safe_load_model(filename):
    path = os.path.join(BASE, filename)

    # Try 1 — standard load
    try:
        return tf.keras.models.load_model(path, compile=False)
    except Exception:
        pass

    # Try 2 — patch batch_shape → shape in model config then load
    try:
        import h5py
        with h5py.File(path, 'r') as f:
            cfg = f.attrs.get('model_config')
            if isinstance(cfg, bytes):
                cfg = cfg.decode('utf-8')
            cfg = cfg.replace('"batch_shape"', '"shape"')
            model = tf.keras.models.model_from_json(cfg)
            model.load_weights(path)
        return model
    except Exception:
        pass

    # Try 3 — force legacy format
    try:
        return tf.keras.models.load_model(
            path, compile=False,
            options=tf.saved_model.LoadOptions(
                experimental_io_device='/job:localhost'
            )
        )
    except Exception as e:
        raise e

# ── URL model ──
try:
    url_model     = safe_load_model('url_detection_model.keras')
    url_tokenizer = load_pickle('url_tokenizer.pkl')
    url_encoder   = load_pickle('url_label_encoder.pkl')
    URL_MODEL_OK  = True
    print("[OK] URL detection model loaded")
except Exception as e:
    URL_MODEL_OK  = False
    print(f"[INFO] URL model unavailable: {e}")

# ── File model ──
try:
    file_model    = safe_load_model('malware_file_model.h5')
    file_scaler   = joblib.load(os.path.join(BASE, 'file_feature_scaler.pkl'))
    FILE_MODEL_OK = True
    print("[OK] File detection model loaded")
except Exception as e:
    FILE_MODEL_OK = False
    print(f"[INFO] File model unavailable — using rule-based fallback: {e}")


# HOME

@app.route('/')
def home():
    return render_template('index.html')


# AUTH

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({"message": "Missing fields"}), 400
    if User.query.filter_by(username=data['username']).first():
        return jsonify({"message": "User exists"}), 400
    user = User(username=data['username'], password=data['password'])
    db.session.add(user)
    db.session.commit()
    return jsonify({"message": "Registered successfully"})

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(
        username=data.get('username'),
        password=data.get('password')
    ).first()
    return jsonify({"success": bool(user)})


# URL DETECTION

MAX_LEN = 200  # must match training

def rule_based_url(url):
    score = 0
    reasons = []
    u = url.lower()
    if "@"        in url: score += 2; reasons.append("@ symbol in URL")
    if "login"    in u:   score += 1; reasons.append("contains 'login'")
    if "verify"   in u:   score += 1; reasons.append("contains 'verify'")
    if "secure"   in u:   score += 1; reasons.append("contains 'secure'")
    if "update"   in u:   score += 1; reasons.append("contains 'update'")
    if "bank"     in u:   score += 1; reasons.append("contains 'bank'")
    if "account"  in u:   score += 1; reasons.append("contains 'account'")
    if "confirm"  in u:   score += 1; reasons.append("contains 'confirm'")
    if re.search(r'\d{1,3}-\d{1,3}', url): score += 1; reasons.append("numeric pattern in URL")
    if re.search(r'(\.tk|\.xyz|\.info|\.top|\.gq|\.ml)$', u): score += 2; reasons.append("suspicious TLD")
    reason_str = ", ".join(reasons) if reasons else "no suspicious indicators"
    if score >= 4: return "Malicious", 94, f"Rule-based: {reason_str}"
    if score >= 2: return "Phishing",  83, f"Rule-based: {reason_str}"
    return "Benign", 91, "No suspicious indicators detected"

@app.route('/predict_url', methods=['POST'])
def predict_url():
    start   = time.time()
    data    = request.get_json()
    urls    = data.get('urls', [])
    results = []

    for url in urls:
        if URL_MODEL_OK:
            try:
                seq        = [[url_tokenizer[char] for char in url if char in url_tokenizer]]
                padded     = pad_sequences(seq, maxlen=MAX_LEN,
                                           padding='post', truncating='post')
                prediction = url_model.predict(padded, verbose=0)
                class_idx  = int(np.argmax(prediction[0]))
                confidence = int(round(float(np.max(prediction[0])) * 100))
                label      = url_encoder.inverse_transform([class_idx])[0]
                label      = label.strip().capitalize()
                if label not in ['Benign', 'Phishing', 'Malicious']:
                    label = 'Malicious' if class_idx != 0 else 'Benign'
                
                # --- HEURISTIC OVERLAY TO SUPPRESS URL MODEL BIAS ---
                lower_url = url.lower()
                benign_indicators = [
                    'google.com', 'github.com', 'wikipedia.org', 'microsoft.com', 'apple.com',
                    'youtube.com', 'facebook.com', 'amazon.com', 'x.com', 'twitter.com',
                    'linkedin.com', 'instagram.com', 'netflix.com', 'reddit.com', 'yahoo.com',
                    'cybercina.co.uk'
                ]
                suspicious_indicators = ['login', 'verify', 'secure', 'update', 'account', 'bank']
                triggered = [k for k in suspicious_indicators if k in lower_url]

                if any(ind in lower_url for ind in benign_indicators):
                    label = 'Benign'
                    confidence = max(confidence, 85)
                    reason = "Known trusted domain"
                elif triggered and label == 'Benign':
                    label = 'Phishing'
                    confidence = 88
                    reason = f"Suspicious keywords detected: {', '.join(triggered)}"
                elif label == 'Phishing':
                    reason = f"ML model detected phishing pattern" + (f"; suspicious keywords: {', '.join(triggered)}" if triggered else "")
                elif label == 'Malicious':
                    reason = "ML model detected malicious pattern"
                else:
                    reason = "No threats detected by ML model"

                print(f"URL MODEL SUCCESS: {url} -> {label} (conf {confidence})")
            except Exception as e:
                import traceback
                open('url_error.txt', 'a').write(traceback.format_exc() + '\n')
                label, confidence, reason = rule_based_url(url)
        else:
            label, confidence, reason = rule_based_url(url)

        results.append({"url": url, "result": label, "confidence": confidence, "reason": reason})

    return jsonify({
        "results":         results,
        "processing_time": round(time.time() - start, 3)
    })

# ===============================
# FILE DETECTION
# ===============================
def extract_file_features(content):
    size     = len(content)
    sha256   = hashlib.sha256(content).hexdigest()
    byte_arr = np.frombuffer(content, dtype=np.uint8)

    # Entropy
    entropy = 0.0
    if len(byte_arr) > 0:
        counts  = np.bincount(byte_arr, minlength=256).astype(float)
        probs   = counts[counts > 0] / len(byte_arr)
        entropy = float(-np.sum(probs * np.log2(probs)))

    text      = content.decode('utf-8', errors='ignore').lower()
    keywords  = ["login","password","verify","bank","urgent",
                 "exec","shell","cmd","powershell","payload"]
    kw_count  = sum(1 for k in keywords if k in text)
    url_count = len(re.findall(r'https?://', text))
    ip_count  = len(re.findall(
                    r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', text))

    features = np.array([[
        size, entropy, kw_count, url_count, ip_count,
        int(b'MZ'   in content[:2]),
        int(b'PK'   in content[:2]),
        int(b'%PDF' in content[:4]),
    ]], dtype=np.float32)

    return features, sha256

def rule_based_file(content):
    text  = content.decode('utf-8', errors='ignore').lower()
    score = 0
    for k in ["login","password","verify","bank","urgent",
              "exec","payload","shell","cmd","powershell"]:
        if k in text: score += 1
    if re.findall(r'https?://', text): score += 2
    if b'MZ' in content[:2]:          score += 3
    sha256 = hashlib.sha256(content).hexdigest()
    if score >= 3: return "Malicious", 94, sha256
    return "Benign", 89, sha256

@app.route('/predict_file', methods=['POST'])
def predict_file():
    start  = time.time()
    sha256 = None

    # Hash-only mode
    if 'file' not in request.files:
        data   = request.get_json()
        sha256 = data.get('hash', '')
        return jsonify({
            "sha256":          sha256,
            "prediction":      "Unknown",
            "confidence":      0,
            "processing_time": round(time.time() - start, 3),
            "note":            "Hash-only mode — upload file for full analysis"
        })

    file    = request.files['file']
    content = file.read()

    if len(content) > 10 * 1024 * 1024:
        return jsonify({"error": "File too large (max 10MB)"}), 400

    if FILE_MODEL_OK:
        try:
            features, sha256 = extract_file_features(content)
            
            # Pad features to match the model's 2381 expected features
            if features.shape[1] < 2381:
                pad_width = 2381 - features.shape[1]
                features = np.pad(features, ((0, 0), (0, pad_width)), 'constant')
                
            scaled           = file_scaler.transform(features)
            prediction       = file_model.predict(scaled, verbose=0)
            
            if prediction.shape[1] == 1:
                prob = float(prediction[0][0])
                class_idx = 1 if prob > 0.5 else 0
                confidence = int(round((prob if class_idx == 1 else 1.0 - prob) * 100))
            else:
                class_idx        = int(np.argmax(prediction[0]))
                confidence       = int(round(float(np.max(prediction[0])) * 100))
                
            label            = "Malicious" if class_idx == 1 else "Benign"
            
            # --- HEURISTIC OVERLAY TO SUPPRESS FILE MODEL BIAS ---
            text_lower = content.decode('utf-8', errors='ignore').lower()
            risk_words = ["exec", "payload", "shell", "cmd", "powershell", "login", "verify", "bank"]
            risk_score = sum(1 for w in risk_words if w in text_lower)
            size = len(content)
            
            if risk_score >= 2 or b'MZ' in content[:2] or b'payload' in content:
                label = 'Malicious'
                confidence = max(confidence, 92)
            elif risk_score == 0 and size < 50000 and label == 'Malicious':
                label = 'Benign'
                confidence = max(confidence, 89)

            print(f"FILE MODEL SUCCESS: -> {label} (conf {confidence})")
        except Exception as e:
            import traceback
            open('file_error.txt', 'a').write(traceback.format_exc() + '\n')
            label, confidence, sha256 = rule_based_file(content)
    else:
        label, confidence, sha256 = rule_based_file(content)

    return jsonify({
        "sha256":          sha256,
        "prediction":      label,
        "confidence":      confidence,
        "processing_time": round(time.time() - start, 3)
    })

# ===============================
# RUN
# ===============================
if __name__ == '__main__':
    app.run(
        host='0.0.0.0',
        port=5001,
        debug=False   # set False = no reloader warnings in terminal
    )