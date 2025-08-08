# Threat Aware

Threat Aware is a utility written in Python to analyze online components, including 
IP-address, URLs, files, ports, and hashes for vulnerability and/or compromise indications.

## Features
- ML phishing detection with robust feature engineering (`src/utils.py`) using `tldextract`, path normalization, `subdomain_abnormality`, `domain/subdomain` complexity, and `subdomain_label_count`.
- Conservative heuristics reduce false positives for clean personal domains and alphabetic subdomains at root while returning both raw and adjusted probabilities (`src/threat_aware.py`).
- External scanners: Sucuri SiteCheck, VirusTotal (URL & hash), and PhishTank (`src/scanners.py`).
- AI Security Analysis (Gemini) with structured, styled frontend reports; LLM cards merged with synthesized scanner cards (hacker theme UI).

## Environment Setup
```shell script
# Clone the repo
git clone https://github.com/sunny-benn/threat_aware.git

cd threat_aware

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# install requirements
pip3 install -r requirements.txt
```

## CLI usage
```bash
# Always activate the venv first
source venv/bin/activate

# URL scan (Sucuri + VT + PhishTank + local ML + AI report)
python src/threat_aware.py -v \
  -k1 "$SUCURI_API_KEY" -k "$VT_API_KEY" -k2 "$PHISHTANK_API_KEY" -k3 "$GEMINI_API_KEY" \
  --urls "https://www.google.com"

# Hash scan (VirusTotal)
python src/threat_aware.py -k "$VT_API_KEY" --hashes "<sha256>"

# Analyze a raw email file (.eml)
python src/threat_aware.py -v -k1 "$SUCURI_API_KEY" -k "$VT_API_KEY" -k2 "$PHISHTANK_API_KEY" -k3 "$GEMINI_API_KEY" \
  --email-file sample_email.eml
```

## Web UI
I have created a flask web app to serve the UI. This would be a good way to conviniently access the scanner from a browser. It is in the `src/web_app.py` file.
```bash
source venv/bin/activate
export URL_SCAN_API_KEY=... VT_API_KEY=... PHISHTANK_API_KEY=... GEMINI_API_KEY=...
python src/web_app.py
# Open http://127.0.0.1:5000
```

## Train the ML model
```bash
source venv/bin/activate
python src/threat_analyzer.py
# Outputs: phishing_model.joblib, model_features.joblib (project root)
# ThreatAware loads these automatically if present.
```

## External services
- Sucuri SiteCheck (URL scans): set `URL_SCAN_API_KEY` (web) or pass `-k1` (CLI).
- VirusTotal (URL & hash): set `VT_API_KEY` (web) or pass `-k` (CLI).
- PhishTank (URL reputation): set `PHISHTANK_API_KEY` (web) or pass `-k2` (CLI).
- Gemini (AI analysis): set `GEMINI_API_KEY` (web) or pass `-k3` (CLI).

## Frontend
- UI: `templates/index.html`, styles in `static/hacker.css`.
- The app renders structured AI reports with status badges and merges LLM output with scanner cards (VirusTotal, Sucuri, PhishTank, ML) for completeness.

## Notes
- Do not commit large model artifacts. `.gitignore` excludes `*.joblib`/`*.pkl`.
- Prefer release assets, cloud storage, or Git LFS for large binaries.
- Run tests: `source venv/bin/activate && python tests/test_ml_model.py`.