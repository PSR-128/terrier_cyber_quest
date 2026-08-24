# Terrier Cyber Quest — AI Web Vulnerability Detection & Cyber-Reasoning Platform

An autonomous, multi-stage cyber-reasoning web security auditing, machine-learning vulnerability classification, automated staging patching, and regression verification platform designed for authorized cybersecurity competition environments.

---

## 🚀 Key Highlights & Capabilities

- **Strict Authorization & Scope Control**: Enforces strict URL domain/subdomain whitelisting, crawl depth boundaries, max page limits, and request throttling. Automatically intercepts and prompts before scanning out-of-scope targets.
- **Autonomous Crawler & Attack Surface Discovery**: Automatically parses HTML, forms, input fields, URL query parameters, inline/external scripts, and dynamic API endpoints without requiring manual URL enumeration.
- **Client-Side Static Analysis Engine**: Inspects exposed client-side HTML, JavaScript, and response headers for hardcoded credentials, API keys, JWT tokens, dangerous DOM sinks (`innerHTML`, `eval`, `document.write`), and missing security headers (`CSP`, `HSTS`, `X-Frame-Options`, `CORS`).
- **Non-Destructive Dynamic Fuzzing & Differential Analysis**: Generates benign, non-destructive probe payloads with verifiable canary tokens across multiple vulnerability classes (SQLi, XSS, Path Traversal, SSTI, Command Injection, CRLF, Open Redirect, NoSQLi). Analyzes response differentials, status codes, and DBMS error signatures without damaging target state.
- **High-Accuracy ML Vulnerability Classifier**: Trained and evaluated on Hugging Face dataset `vyykaaa/dataset-v2`. Uses a dual-vectorizer sub-word character & token n-gram pipeline with calibrated multi-class probability estimation across 16 canonical attack categories.
- **Local Cyber-Reasoning Layer**: Multi-modal evidence synthesizer that correlates static findings, dynamic probe reflection, HTTP error differentials, and ML statistical predictions. Computes calibrated confidence scores, CVSS-aligned severity ratings, detailed explanatory narratives, and explicit uncertainty / false-positive warnings.
- **Automated Staging Patching & Regression Test Harness**: Generates secure defense patches (parameterized queries, HTML entity escaping, path sanitization, whitelist validation) for local staging copies, computes diffs, applies patches, reruns targeted security probes, executes baseline regression tests, and certifies verification verdicts (`FIXED`, `NOT_FIXED`, `INCONCLUSIVE`).
- **Real-Time Interactive Dashboard & Export**: FastAPI backend with WebSocket live streaming, dark-mode cybersecurity UI, interactive findings explorer, patch diff inspector, SQLite scan history, and competition-grade PDF & JSON report exports.

---

## 🏗️ System Architecture

```
                                  [ Authorized Target URL ]
                                              │
                                              ▼
                                   [ Scope & Auth Controller ]
                                              │
                                              ▼
                             [ Autonomous Web Crawler & Discovery ]
                                              │
                       ┌──────────────────────┴──────────────────────┐
                       ▼                                             ▼
          [ Client-Side Static Analysis ]               [ Dynamic Non-Destructive Fuzzing ]
          (DOM Sinks, Secrets, Headers)                  (Canary Probes, Error Signatures)
                       │                                             │
                       │                                             ▼
                       │                                [ ML Vulnerability Classifier ]
                       │                                (Sub-word N-Grams + Calibrated SGD)
                       │                                             │
                       └──────────────────────┬──────────────────────┘
                                              ▼
                                 [ Local Cyber-Reasoning Engine ]
                              (Multi-Source Evidence Correlation)
                                              │
                                              ▼
                            [ Vulnerability Verdict & Severity ]
                            (Confidence, Evidence & Uncertainty)
                                              │
                       ┌──────────────────────┴──────────────────────┐
                       ▼                                             ▼
             [ Dashboard UI / PDF / JSON ]               [ Automated Staging Patching ]
                                                                     │
                                                                     ▼
                                                        [ Regression Test Harness ]
                                                                     │
                                                                     ▼
                                                        [ Verification Certificate ]
```

---

## 📊 Dataset & ML Model Details

- **Dataset Source**: [`vyykaaa/dataset-v2`](https://huggingface.co/datasets/vyykaaa/dataset-v2)
- **Training Samples**: 300,168 HTTP requests
- **Test Samples**: 5,000 HTTP requests
- **Canonical Categories Learned**:
  1. `Normal` (Benign baseline traffic)
  2. `SQL_Injection`
  3. `Cross_Site_Scripting`
  4. `Directory_Traversal`
  5. `Command_Injection`
  6. `XML_External_Entity`
  7. `Server_Side_Request_Forgery`
  8. `Cross_Site_Request_Forgery`
  9. `Server_Side_Template_Injection`
  10. `LDAP_Injection`
  11. `CRLF_Injection`
  12. `NoSQL_Injection`
  13. `Open_Redirect`
  14. `Web_Cache_Deception`
  15. `Server_Side_Include_Injection`
  16. `Advanced_Vulnerability_Scan`

---

## 🛠️ Installation & Setup

### 1. Requirements
- Python 3.10+
- Modern Web Browser (Chrome / Firefox / Edge)

### 2. Install Dependencies
```bash
python -m pip install -r requirements.txt
```

### 3. Train & Evaluate ML Model (Pre-trained artifacts saved in `models/`)
```bash
python -m training.train
python -m training.evaluate
```

### 4. Launch the Platform (Dashboard + Staging Target)
```bash
python run_server.py
```
- **Dashboard UI**: [http://127.0.0.1:8000](http://127.0.0.1:8000)
- **Local Staging Target**: [http://127.0.0.1:5000](http://127.0.0.1:5000)

---

## 🧪 Running Automated Tests

```bash
pytest tests/ -v
```

---

