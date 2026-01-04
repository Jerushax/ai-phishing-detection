# backend/main.py
from fastapi import FastAPI, Request
import joblib
import numpy as np
from url_features import extract_url_features
import sqlite3
from datetime import datetime
import os
from fastapi.middleware.cors import CORSMiddleware
app = FastAPI(title="AI Phishing Detection API")


# after app = FastAPI(...)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000","http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# load model
MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "ml", "model.pkl")
model = joblib.load(MODEL_PATH)

# Setup sqlite DB
DB_PATH = os.path.join(os.path.dirname(__file__), "scans.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT,
        prediction TEXT,
        confidence REAL,
        risk_score INTEGER,
        reasons TEXT,
        timestamp TEXT
    )
    """)
    conn.commit()
    conn.close()

init_db()

def compute_risk_score(prob, signals: dict):
    """
    Combine model probability and heuristic signals into a 0-100 risk score.

    Strategy:
     - base = prob (0-1) * 70  (model gets major say)
     - heuristics contribute up to 30 points depending on severity
    """
    base = prob * 70.0

    # Weighted signal contributions (tunable)
    weight_map = {
        "contains_ip": 10,
        "is_shortener": 12,
        "domain_age": 8,         # low age adds points; we compute as threshold
        "suspicious_word_count": 6,
        "dns_lookup_failed": 8,
        "empty_title": 4,
        "nb_subdomains": 4,
        "has_at_symbol": 6,
        "digit_ratio": 6,
        "suspicious_tld": 6
    }

    heur = 0.0

    # compute heuristics
    if signals.get("contains_ip"):
        heur += weight_map["contains_ip"]
    if signals.get("is_shortener"):
        heur += weight_map["is_shortener"]
    if signals.get("domain_age", 0) and signals.get("domain_age") < 1:
        heur += weight_map["domain_age"]
    if signals.get("suspicious_word_count", 0) >= 1:
        heur += min(weight_map["suspicious_word_count"] * signals.get("suspicious_word_count",1), 12)
    if signals.get("dns_lookup_failed"):
        heur += weight_map["dns_lookup_failed"]
    if signals.get("empty_title"):
        heur += weight_map["empty_title"]
    if signals.get("nb_subdomains", 0) >= 3:
        heur += weight_map["nb_subdomains"]
    if signals.get("has_at_symbol"):
        heur += weight_map["has_at_symbol"]
    # digit ratio > 0.2 suspicious
    if signals.get("digit_ratio", 0) > 0.2:
        heur += weight_map["digit_ratio"]
    if signals.get("suspicious_tld"):
        heur += weight_map["suspicious_tld"]

    # cap heuristics to 30
    heur = min(heur, 30.0)

    risk = base + heur
    risk = max(0.0, min(100.0, risk))
    return int(round(risk))

def save_scan(url, prediction, confidence, risk_score, reasons):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
    INSERT INTO scans (url, prediction, confidence, risk_score, reasons, timestamp)
    VALUES (?, ?, ?, ?, ?, ?)
    """, (url, prediction, confidence, risk_score, reasons, datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()

@app.get("/")
def home():
    return {"message": "AI Phishing Detection API is running ✅"}

@app.post("/scan-url")
def scan_url(payload: dict):
    try:
        url = payload.get("url")
        if not url:
            return {"error": "URL is required", "status": "failed"}

        features, signals = extract_url_features(url)
        data = np.array(features).reshape(1, -1)

        prediction_raw = model.predict(data)[0]
        probs = model.predict_proba(data)[0]
        confidence = float(probs.max())

# ✅ FIX: Handle both string and numeric class labels safely
        if str(prediction_raw).lower() in ["1", "phishing", "phish", "malicious"]:
            prediction = "Phishing"
        else:
            prediction = "Legitimate"
 # ✅ Safety override: low confidence phishing becomes "Suspicious", not "Phishing"
        if prediction == "Phishing" and confidence < 0.75:
            final_label = "Suspicious"
        else:
            final_label = prediction


        # create human-readable reasons (top signals)
        reasons = []
        if signals.get("contains_ip"):
            reasons.append("URL contains an IP address")
        if signals.get("is_shortener"):
            reasons.append("Uses a URL shortening service")
        if signals.get("domain_age", 0) < 1:
            reasons.append("Domain was registered recently")
        if signals.get("suspicious_word_count", 0) >= 1:
            reasons.append("Suspicious keywords in URL")
        if signals.get("dns_lookup_failed"):
            reasons.append("Domain DNS lookup failed")
        if signals.get("empty_title"):
            reasons.append("Page has empty title")
        if signals.get("nb_subdomains", 0) >= 3:
            reasons.append("Many subdomains (possible squat)")
        if signals.get("has_at_symbol"):
            reasons.append("Contains '@' symbol")
        if signals.get("digit_ratio", 0) > 0.2:
            reasons.append("High digit ratio in URL")
        if signals.get("suspicious_tld"):
            reasons.append("Suspicious TLD")

        # if model strongly says phishing but no heuristic reasons, add model-based reason
        if prediction == "Phishing" and not reasons:
            reasons.append("Model prediction indicates phishing")

        # compute risk score
        risk_score = compute_risk_score(confidence, signals)
        # --- Trusted Brand Override (add this block) ---
        trusted_domains = [
    "paypal.com","google.com","amazon.com","microsoft.com","apple.com",
    "github.com","youtube.com","facebook.com","linkedin.com","bankofamerica.com"
]

    # lower-case domain match
        domain_lower = url.lower()
        if any(td in domain_lower for td in trusted_domains):
    # if model says phishing but confidence is low, treat as Legit
    # stronger override threshold for known trusted domains
            OVERRIDE_CONFIDENCE = 0.85
            if confidence < OVERRIDE_CONFIDENCE:
                final_label = "Legitimate"
                reasons = ["Trusted global brand override"]
                risk_score = min(risk_score, 20)

        # save to DB
        save_scan(url, final_label, confidence, risk_score, "; ".join(reasons))


        return {
            "url": url,
            "prediction": final_label,

            "confidence": round(confidence, 4),
            "risk_score": risk_score,
            "reasons": reasons,
            "status": "success"
        }

    except Exception as e:
        return {"error": str(e), "status": "failed"}

@app.get("/history")
def history(limit: int = 50):
    """
    Return last `limit` scans from DB (default 50).
    """
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT id, url, prediction, confidence, risk_score, reasons, timestamp FROM scans ORDER BY id DESC LIMIT ?", (limit,))
    rows = cur.fetchall()
    conn.close()

    results = []
    for r in rows:
        results.append({
            "id": r[0],
            "url": r[1],
            "prediction": r[2],
            "confidence": r[3],
            "risk_score": r[4],
            "reasons": r[5],
            "timestamp": r[6]
        })

    return {"count": len(results), "results": results}
