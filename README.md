# Tridetect — Tri-vector Phishing Detection System

**MBC Telkom University Cybersecurity Lab | Project #7**

Tridetect detects phishing across three attack vectors common in Indonesia:

| Module | Vector | Status |
|--------|--------|--------|
| 🌐 Web | Phishing URLs & fake websites | ✅ Phase 1 Active |
| 📱 SMS | Smishing / WhatsApp phishing | ✅ Phase 1 Active |
| 🎤 Voice | Vishing / phone scams | 🔜 Phase 2 Roadmap |

---

## Architecture

```
                  ┌─────────────────────────────┐
                  │   API GATEWAY (FastAPI)     │
                  │   POST /v1/classify/web     │
                  │   POST /v1/classify/sms     │
                  │   POST /v1/classify/voice   │
                  └──────────────┬──────────────┘
                                 │
              ┌──────────────────┼──────────────────┐
              ▼                  ▼                  ▼
   ┌──────────────────┐ ┌──────────────────┐ ┌──────────────────┐
   │  WEB MODULE      │ │ SMISHING MODULE  │ │  VISHING MODULE  │
   ├──────────────────┤ ├──────────────────┤ ├──────────────────┤
   │ 1. URL Features  │ │ 1. Text Preproc  │ │  [Phase 2 stub]  │
   │ 2. RF + XGBoost  │ │ 2. IndoBERT NLP  │ │ 1. Whisper STT   │
   │ 3. Brand Detect  │ │ 3. URL Extract   │ │ 2. Transcript    │
   │ 4. SSL Check     │ │ 4. Urgency Score │ │ 3. Voice Anomaly │
   └────────┬─────────┘ │ 5. # Reputation  │ └────────┬─────────┘
            └───────────┴──────────┬────────┴──────────┘
                                   ▼
                  ┌─────────────────────────────┐
                  │  AGGREGATOR + RESPONSE      │
                  │  label: safe/suspicious/    │
                  │          malicious          │
                  │  confidence: 0.0-1.0        │
                  │  reasons: [...]             │
                  └──────────────┬──────────────┘
                                 ▼
                  ┌─────────────────────────────┐
                  │  SQLite (dev) / PostgreSQL  │
                  │  In-memory TTL cache        │
                  └──────────────┬──────────────┘
                                 ▼
                  ┌─────────────────────────────┐
                  │  Streamlit Dashboard        │
                  │  REST API (/docs)           │
                  └─────────────────────────────┘
```

---

## Quick Start

### 1. Install

```bash
pip install -e .
```

### 2. Generate training data

```bash
python scripts/generate_synthetic_sms.py
python scripts/seed_brands.py
```

### 3. (Optional) Train models

```bash
# Web phishing classifier (RF + XGB)
python scripts/train_web.py

# Smishing IndoBERT fine-tune (requires GPU for speed)
tridetect train smishing --epochs 3
```

If you skip training, the system falls back to rule-based heuristics automatically.

### 4. Start API server

```bash
tridetect serve --port 8000
```

### 5. Test endpoints

```bash
# Web phishing test
curl -s -X POST http://localhost:8000/v1/classify/web \
  -H "Content-Type: application/json" \
  -d '{"url": "http://g0pay-verify.tk/check", "check_ssl": false}' | python -m json.tool

# Smishing test
curl -s -X POST http://localhost:8000/v1/classify/sms \
  -H "Content-Type: application/json" \
  -d '{"text": "AKUN GOPAY ANDA AKAN DIBEKUKAN. Verifikasi sekarang: bit.ly/xxx"}' | python -m json.tool
```

### 6. Launch Dashboard

```bash
tridetect dashboard
# Opens: http://localhost:8501
```

---

## CLI Reference

```
tridetect serve --port 8000          # Start API gateway
tridetect classify-web <url>         # Classify single URL
tridetect classify-sms "<text>"      # Classify SMS text
tridetect classify-sms "<text>" --sender +62811xxx
tridetect train smishing --epochs 3  # Fine-tune IndoBERT
tridetect train web                  # Train RF+XGB classifier
tridetect dashboard                  # Open Streamlit dashboard
```

---

## API Reference

**POST /v1/classify/web**
```json
{
  "url": "https://suspicious-site.tk/login",
  "check_ssl": true,
  "check_brand": true
}
```

**POST /v1/classify/sms**
```json
{
  "text": "AKUN BCA ANDA AKAN DIBEKUKAN...",
  "sender_number": "+6281234567890",
  "timestamp": "2025-01-01T10:00:00"
}
```

**Response format (all modules):**
```json
{
  "label": "malicious",
  "confidence": 0.87,
  "reasons": ["Typosquat of GoPay detected", "Suspicious TLD .tk"],
  "module": "web",
  "latency_ms": 45
}
```

Interactive API docs: **http://localhost:8000/docs**

---

## Docker Deployment (Lab Server)

```bash
cd docker
docker compose up --build
```

Services:
- API: http://localhost:8000
- Dashboard: http://localhost:8501
- PostgreSQL: port 5432
- Redis: port 6379

---

## Vishing Module — Phase 2 Roadmap

The voice module returns `HTTP 501` in Phase 1. Phase 2 implementation plan:

```
Week 5-7:
  1. Audio input: WAV/MP3/M4A file or bytes
  2. Resample to 16kHz mono (librosa)
  3. Whisper STT (model: small/medium)
  4. Transcript → SmishingClassifier (reuse)
  5. Return {label, confidence, transcript, reasons}

Phase 3:
  6. Voice clone / deepfake detection
  7. Speaker diarization (pyannotate)
```

Install Phase 2 dependencies:
```bash
pip install "tridetect[vishing]"
```

---

## Detection Logic

### Web Module — Score Weights
| Component | Weight |
|-----------|--------|
| ML Classifier (RF+XGB) | 50% |
| Brand typosquat detector | 30% |
| SSL certificate check | 20% |

### Smishing Module — Score Weights
| Component | Weight |
|-----------|--------|
| IndoBERT NLP classifier | 45% |
| Urgency score (keyword rules) | 25% |
| URL risk score | 15% |
| Sender number reputation | 15% |

### Label Thresholds
| Score | Label |
|-------|-------|
| ≥ 0.65 | 🔴 malicious |
| 0.35 – 0.64 | 🟡 suspicious |
| < 0.35 | 🟢 safe |

---

## Ethical Considerations

1. **Dataset**: All training data is synthetic — no real user SMS is collected or stored
2. **False positives**: Aggressive promos from legitimate brands may be flagged as suspicious
3. **Privacy**: Only a hash fingerprint of input is logged, never plain text content  
4. **Scope**: This tool is for defensive cybersecurity research and education only
5. **Blocklist**: Phone number blocklist is community-sourced; disputed entries should be reviewed

---

## Project Structure

```
tridetect/
├── tridetect/              # Main Python package
│   ├── gateway/            # FastAPI API gateway
│   ├── modules/
│   │   ├── web_phishing/   # URL + brand + SSL detection
│   │   ├── smishing/       # IndoBERT + urgency + reputation
│   │   └── vishing/        # Phase 2 stub
│   ├── shared/             # DB, cache, logger
│   └── data/               # brands.json, blocklist, sms_synthetic.csv
├── scripts/                # Training & data generation scripts
├── dashboard/              # Streamlit dashboard
├── tests/                  # pytest test suite
└── docker/                 # Docker + docker-compose
```

---

## Citation

```
MBC Telkom University Cybersecurity Lab (2025).
Tridetect: Tri-Vector Phishing Detection for Indonesian Digital Identity Protection.
```
