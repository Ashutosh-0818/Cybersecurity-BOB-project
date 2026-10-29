# 🔍 WebGuard — Automated Web Security Scanner

A beginner-friendly Python tool that scans any website for missing security headers,
CORS misconfigurations, cookie flaws, and server information leaks.  
No machine learning. No external APIs. No paid accounts. Just Python.

---

## Features

| Feature | Description |
|---|---|
| 🛡️ Security Score | 0–100 score with colour-coded rating (Good / Fair / Poor) |
| 📋 Header Checks | 7 critical HTTP security headers checked |
| 🌐 CORS Check | Detects dangerous `Access-Control-Allow-Origin: *` |
| 🔒 HTTPS Check | Verifies HTTP redirects to HTTPS |
| 🍪 Cookie Check | Checks for `Secure` and `HttpOnly` cookie flags |
| 🕵️ Server Info Leak | Detects exposed server version in response headers |
| 💡 Recommendations | Lists every failed check with its risk level |
| 🗂️ Raw Headers | Expandable section showing all raw response headers |
| 🌑 Dark Theme | Clean GitHub-dark style UI |

---

## Security Checks Performed

| Check | What it looks for | Risk if missing |
|---|---|---|
| Strict-Transport-Security | Forces HTTPS | HIGH |
| Content-Security-Policy | Prevents XSS | HIGH |
| X-Frame-Options | Prevents Clickjacking | MEDIUM |
| X-Content-Type-Options | Prevents MIME sniffing | MEDIUM |
| Referrer-Policy | Stops URL leaking | LOW |
| Permissions-Policy | Restricts device access | LOW |
| X-XSS-Protection | Browser XSS filter | LOW |
| CORS Header | Open cross-origin access | HIGH |
| HTTPS Redirect | Unencrypted connections | HIGH |
| Cookie Security Flags | Cookie theft via XSS/HTTP | MEDIUM |
| Server Info Leak | Exposes software version | LOW |

---

## Project Structure

```
cybersecurity/
├── scanner.py                  # Main application — all code in one file
├── scanner_requirements.txt    # Python dependencies
├── scanner_README.md           # This file
└── scanner_REPORT.md           # Project report
```

---

## Requirements

- Python 3.8 or higher
- Streamlit 1.66.1
- No other libraries — uses only Python built-ins (`urllib`, `ssl`, `json`, `time`)

> **Note:** On machines with Application Control policies, use `python -m streamlit` instead of `streamlit`.

---

## Installation

```powershell
python -m pip install -r scanner_requirements.txt
```

---

## How to Run

```powershell
cd "C:\Users\mahim\OneDrive\Documents\cybersecurity"
python -m streamlit run scanner.py
```

Open **http://localhost:8501** in your browser.

---

## How to Use

1. Open **http://localhost:8501**
2. Type a website URL in the input box (e.g. `https://example.com`)
3. Click **🔍 Run Security Scan**
4. View the security score, pass/fail results, and recommendations
5. Expand **🗂️ View Raw Response Headers** to see all headers

---

## Scoring System

| Result | Points |
|---|---|
| ✅ PASS | 2 points |
| ⚠️ WARN | 1 point |
| ❌ FAIL | 0 points |
| ℹ️ INFO | 0 points |

Final score = (total points ÷ max possible points) × 100

| Score Range | Rating |
|---|---|
| 80–100 | 🟢 Good |
| 50–79 | 🟡 Fair |
| 0–49 | 🔴 Poor |

---

## Important Notice

> ⚠️ Only scan websites you **own** or have **explicit permission** to test.  
> This tool is for **educational purposes only**.
