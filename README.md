# AI Phishing Detection — Research & Product

**What:** End-to-end AI-powered phishing detection system (URL + planned email integration).  
**Stack:** Python (FastAPI, scikit-learn), SQLite, React, Chrome extension.

## Features
- Trained RandomForest model on research-grade phishing dataset (11,430 URLs, 87 features). Achieved ~96.7% accuracy.
- Real-time REST API (`/scan-url`) providing: prediction, confidence, risk_score (0–100), and human-readable reasons.
- Heuristic fusion layer combining ML probability with explainable signals (WHOIS age, IP-in-URL, shortener detection).
- Trusted-brand override to prevent false positives on major domains (PayPal, Google, Amazon).
- SQLite-backed audit log and `/history` API for SOC dashboard integration.
- Frontend React dashboard for scanning and visualizing scan history.
- Chrome extension for quick client-side checks.
- Planned: Email phishing module (NLP for subjects/body, attachment analysis), caching of WHOIS, cloud deployment.

## Quickstart (local)
1. Backend
```bash
cd backend
pip install -r ../requirements.txt
uvicorn main:app --reload
cd frontend
npm install
npm start
```
2. Frontend
```bash
cd frontend
npm install
npm start
```
## Chrome Extension
```bash
Open chrome://extensions

Enable Developer mode

Click Load unpacked

Select chrome-extension/
```
## ⚠️ Known Limitations

Legitimate brand websites may occasionally be flagged as suspicious
This is expected behavior in ML-based security systems
Future improvements include brand whitelisting and reputation scoring
