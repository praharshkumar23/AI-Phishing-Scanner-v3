# 🛡️ AI Phishing Link Scanner v3.0

> Multi-layer phishing detection combining static analysis, WHOIS domain age check, VirusTotal + AbuseIPDB reputation, and AI semantic analysis (Gemini / GPT-4o). Now with a **Streamlit web UI**, **bulk CSV scanning**, and an **email header phishing analyzer**.

Built by **Praharsh Kumar** — SOC Analyst | Detection Engineering | SC-200 Certified

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-active-brightgreen)
![Version](https://img.shields.io/badge/version-3.0-orange)
![Made by](https://img.shields.io/badge/made%20by-Praharsh%20Kumar-blueviolet)

---

## 📋 Table of Contents

- [Overview](#-overview)
- [What's New in v3.0](#-whats-new-in-v30)
- [How It Works](#-how-it-works)
- [Project Structure](#-project-structure)
- [Requirements](#-requirements)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Usage](#-usage)
- [Web UI — Streamlit](#-web-ui--streamlit)
- [Email Header Scanner](#-email-header-scanner)
- [Detection Logic](#-detection-logic)
- [Risk Score Calculation](#-risk-score-calculation)
- [Example Output](#-example-output)
- [API Rate Limits](#-api-rate-limits)
- [Troubleshooting](#-troubleshooting)
- [Security Notes](#-security-notes)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🔎 Overview

Most phishing detection tools rely on a single source. That's not enough.

This scanner runs every URL through **5 independent detection layers** and combines their signals into a single weighted risk score out of 100. Version 3.0 adds a full **Streamlit web UI**, **WHOIS domain age check**, **bulk CSV scanning**, and a dedicated **email header phishing analyzer**.

**The question it answers:**

> Is this link safe, suspicious, or malicious — and why?

---

## ✨ What's New in v3.0

| Feature | v2.0 | v3.0 |
|---|---|---|
| Streamlit Web UI | ❌ | ✅ |
| WHOIS domain age check | ❌ | ✅ |
| CSV bulk scan (CLI + UI) | ❌ | ✅ |
| Email header phishing analyzer | ❌ | ✅ |
| SPF / DKIM / DMARC analysis | ❌ | ✅ |
| Reply-To mismatch detection | ❌ | ✅ |
| Brand spoofing in display name | ❌ | ✅ |
| JSON download from web UI | ❌ | ✅ |
| AbuseIPDB reputation | ✅ | ✅ |
| VirusTotal 70+ AV engines | ✅ | ✅ |
| MITRE ATT&CK mapping | ✅ | ✅ |
| Scan history log | ✅ | ✅ |

---

## 🔬 How It Works

```
URL Input
   │
   ├── [1] URL Validation
   │       → Regex structure check
   │       → Rejects malformed input early
   │
   ├── [2] Static Analysis
   │       → IP address in URL
   │       → Typosquatting patterns (amaz0n, g00gle, paypa1...)
   │       → Suspicious TLD detection (.tk .ml .ga .cf .gq .pw .xyz)
   │       → Keyword scanning (login, verify, suspend, urgent...)
   │       → HTTP vs HTTPS, URL length, subdomains, hex encoding
   │       → Risk score: 0–100
   │
   ├── [3] WHOIS Domain Age Check
   │       → Looks up domain registration date
   │       → Flags domains < 30 days old as HIGH risk
   │       → Flags domains < 90 days old as MEDIUM risk
   │       → Phishing domains are almost always newly registered
   │
   ├── [4] VirusTotal Reputation Check
   │       → Submits URL to VirusTotal API v3
   │       → Waits for 70+ AV engine analysis
   │       → Returns malicious / suspicious / harmless counts
   │
   ├── [5] AbuseIPDB Check (if URL contains an IP address)
   │       → Checks IP abuse confidence score
   │       → Returns total reports, country, ISP, Tor node status
   │
   ├── [6] AI Semantic Analysis
   │       → Sends URL + static results + domain age to Gemini / GPT-4o
   │       → Returns VERDICT, CONFIDENCE, RED FLAGS, MITRE technique, REASONING
   │
   └── Final Verdict
           → Weighted risk score out of 100
           → SAFE (0–39) / SUSPICIOUS (40–69) / MALICIOUS (70–100)
           → Saved to scan_history.json
           → Exportable as JSON or CSV
```

---

## 📁 Project Structure

```
AI-Phishing-Scanner-v3/
│
├── phishing_scanner.py       # Main scanner — all 5 detection layers
├── app.py                    # Streamlit web UI
├── email_scanner.py          # Email header phishing analyzer
├── requirements.txt          # All Python dependencies
├── .env.example              # API key template — rename to .env
├── .gitignore                # Excludes .env, venv, reports, cache
├── sample_urls.csv           # Sample CSV for bulk scan testing
├── README.md                 # This file
│
└── (auto-generated on use)
    ├── scan_history.json              # Logs every scan
    ├── scan_report_TIMESTAMP.json     # Per-scan JSON export
    ├── bulk_scan_TIMESTAMP.csv        # Bulk scan CSV output
    └── email_scan_TIMESTAMP.json      # Email scan JSON export
```

---

## 📦 Requirements

### Software

- Python 3.8 or higher
- pip
- Internet connection for API calls

### API Keys

| Service | Purpose | Cost | Get Key |
|---|---|---|---|
| **VirusTotal** | URL reputation — 70+ AV engines | Free (4 req/min) | [virustotal.com](https://www.virustotal.com/gui/join-us) |
| **Google Gemini** | AI semantic analysis | Free tier available | [aistudio.google.com](https://aistudio.google.com/app/apikey) |
| **OpenAI** | AI analysis (alternative to Gemini) | ~$0.01–0.03/scan | [platform.openai.com](https://platform.openai.com/api-keys) |
| **AbuseIPDB** | IP reputation check | Free (1,000/day) | [abuseipdb.com](https://www.abuseipdb.com/register) |

> You only need **one** LLM provider — Gemini or OpenAI.
> AbuseIPDB is optional — the scanner skips it automatically if no key is provided.
> WHOIS domain age check is **free with no API key**.

### Python Packages

| Package | Version | Purpose |
|---|---|---|
| `requests` | 2.31.0+ | HTTP calls to APIs |
| `python-dotenv` | 1.0.0+ | Load `.env` config |
| `colorama` | 0.4.6+ | Colored terminal output |
| `google-generativeai` | 0.3.0+ | Gemini AI integration |
| `openai` | 1.12.0+ | OpenAI GPT integration |
| `streamlit` | 1.32.0+ | Web UI |
| `pandas` | 2.0.0+ | CSV processing in web UI |
| `python-whois` | 0.9.0+ | WHOIS domain age lookup |

---

## 🚀 Installation

### Step 1 — Clone the repository

```bash
git clone https://github.com/praharshkumar23/AI-Phishing-Scanner-v3.git
cd AI-Phishing-Scanner-v3
```

### Step 2 — Create a virtual environment

```bash
python -m venv venv
```

**Windows:**
```bash
venv\Scripts\activate
```

**Linux / macOS:**
```bash
source venv/bin/activate
```

### Step 3 — Install dependencies

```bash
pip install -r requirements.txt
```

### Step 4 — Verify installation

```bash
python --version
pip list
```

You should see all 8 packages listed.

---

## ⚙️ Configuration

### Step 1 — Create your `.env` file

**Windows:**
```bash
copy .env.example .env
```

**Linux / macOS:**
```bash
cp .env.example .env
```

### Step 2 — Add your API keys

Open `.env` and fill in your keys:

```ini
# VirusTotal API Key (required)
VIRUSTOTAL_API_KEY=your_virustotal_key_here

# AbuseIPDB API Key (optional)
ABUSEIPDB_API_KEY=your_abuseipdb_key_here

# LLM Provider — write: gemini or openai
LLM_PROVIDER=gemini

# Google Gemini API Key (recommended — free)
GOOGLE_API_KEY=your_gemini_key_here

# OpenAI API Key (alternative — paid)
OPENAI_API_KEY=your_openai_key_here
```

> ⚠️ Never push `.env` to GitHub. Already blocked in `.gitignore`.

---

## 💻 Usage

### Terminal — single URL

```bash
python phishing_scanner.py "https://example.com"
```

### Terminal — interactive menu

```bash
python phishing_scanner.py
```

Menu options:
```
  1  Scan a single URL
  2  Batch scan (multiple URLs)
  3  Scan from CSV file
  4  View scan history
  q  Quit
```

### Terminal — CSV bulk scan

```bash
python phishing_scanner.py sample_urls.csv
```

CSV must have a column named `url`. Output saved as `bulk_scan_TIMESTAMP.csv`.

---

## 🌐 Web UI — Streamlit

Run the web interface:

```bash
streamlit run app.py
```

Opens at `http://localhost:8501` in your browser.

**Tabs:**

- **Single URL Scan** — enter any URL, see color-coded verdict with full breakdown
- **Bulk CSV Scan** — upload a CSV file, scan all URLs, download report
- **Scan History** — view all previous scans, export as CSV

**Deploy free on Streamlit Cloud:**

1. Push project to GitHub.
2. Go to [share.streamlit.io](https://share.streamlit.io).
3. Connect your GitHub repo.
4. Add API keys in the Streamlit Secrets section.
5. Deploy — you get a live public URL to share on your resume.

---

## 📧 Email Header Scanner

Analyzes raw email headers and body for phishing indicators.

```bash
python email_scanner.py
```

Paste the raw email content when prompted. Type `END` on a new line to start the scan.

**What it checks:**

- Extracts all URLs from the email and scans each one
- SPF authentication (pass / fail)
- DKIM signature presence and validation
- DMARC policy check
- Reply-To domain mismatch vs From domain
- Brand spoofing in display name (Amazon, PayPal, Apple, etc.)
- Urgency keywords in subject line
- Number of received hops

**Example verdict:**

```
🚨 HIGH RISK — This email is likely a phishing attack
Risk Score : 85/100
Action     : DO NOT click any links. Report to security team immediately.

SENDER ANALYSIS
  From         : support@amaz0n-update.com
  Display Name : Amazon Customer Service
  Reply-To     : harvest@evil.ml
  Subject      : URGENT: Your account has been suspended

AUTHENTICATION
  SPF          : FAIL
  DKIM Signed  : NO
  DMARC        : FAIL

RISK FACTORS
  [+35] Brand spoofing: amazon
  [+30] SPF failed
  [+25] Reply-To mismatch
  [+20] Urgency keywords: urgent, suspended, account
  [+50] 2 malicious URL(s) found
```

---

## 🔍 Detection Logic

### Static Analysis Indicators

| Indicator | Risk Points | Example |
|---|---|---|
| IP address in URL | 30 | `http://192.168.1.1/login` |
| Typosquatting pattern | 30 | `amaz0n.com`, `paypa1.com` |
| Suspicious TLD | 25 | `.tk`, `.ml`, `.ga`, `.cf`, `.gq`, `.pw`, `.xyz` |
| Excessive subdomains | 20 | `secure.verify.login.paypal.com` |
| `@` symbol in URL | 20 | `http://safe.com@evil.com` |
| Double slash in path | 15 | `https://site.com//redirect` |
| URL length > 75 chars | 15 | Long obfuscated URLs |
| HTTP instead of HTTPS | 10 | `http://` |
| Hex encoding | 10 | `%2F`, `%40` in path |
| Suspicious keyword | 5 each | `login`, `verify`, `urgent`, `suspend` |

### Typosquatting Patterns Detected

`amaz[o0]n` · `g[o0]{2}gle` · `faceb[o0]{2}k` · `micr[o0]s[o0]ft` · `paypa[l1]` · `app[l1]e` · `netf[l1]ix` · `tw[i1]tter` · `ins[t7]agram` · `[l1]inked[i1]n` · `dropb[o0]x` · `[o0]ff[i1]ce365`

### WHOIS Domain Age Check

Phishing domains are almost always registered within the last 30 days.

| Age | Risk Flag |
|---|---|
| < 30 days | HIGH — domain is brand new |
| 30–90 days | MEDIUM — domain is recently registered |
| > 90 days | LOW — domain age is normal |

---

## 📊 Risk Score Calculation

| Layer | Weight | Source |
|---|---|---|
| Static Analysis | 20% | URL structure and pattern matching |
| WHOIS Domain Age | 15% | Domain registration date |
| VirusTotal | 35% | AV engine malicious + suspicious votes |
| AbuseIPDB | 10% | IP abuse confidence score |
| AI Semantic Analysis | 20% | LLM phishing confidence |

**Final Verdict:**

| Score | Verdict |
|---|---|
| `0 – 39` | ✅ SAFE — URL appears legitimate |
| `40 – 69` | ⚠️ SUSPICIOUS — verify before clicking |
| `70 – 100` | 🚨 MALICIOUS — do not visit |

---

## 📊 Example Output

### Terminal Output — Phishing URL

```
======================================================================
  SCANNING: http://amaz0n-security-update.com/verify-account
======================================================================

[1/5] Static analysis...
  [+] Risk score: 75/100

[2/5] WHOIS domain age check...
  [!] Domain age: 4 days — HIGH — domain < 30 days old

[3/5] VirusTotal check...
  [+] Done

[4/5] AbuseIPDB check...
  [!] No IP in URL — AbuseIPDB skipped

[5/5] AI semantic analysis...
  [+] Done — 95% confidence

======================================================================
  SCAN REPORT
======================================================================

  STATIC ANALYSIS
  Risk Score      : 75/100
  HTTP (no HTTPS) : YES
  Keywords        : security, update, verify, account
  Typosquatting   : amaz[o0]n

  WHOIS DOMAIN AGE
  Domain Age      : 4 days (created 2026-05-01)
  Risk Flag       : HIGH — domain < 30 days old

  VIRUSTOTAL REPUTATION
  Malicious  : 12/89
  Suspicious : 8/89
  Harmless   : 69/89

  AI ANALYSIS (gemini-2.5-flash)
  Verdict         : PHISHING
  Confidence      : 95%
  MITRE Technique : T1566.002 - Phishing: Spearphishing Link

  ============================================================
  FINAL VERDICT: MALICIOUS — HIGH RISK
  Overall Risk : 91/100
  Action       : DO NOT VISIT. Strong phishing indicators detected.
  ============================================================
```

---

## ⏱️ API Rate Limits

| Service | Free Tier Limit | Notes |
|---|---|---|
| VirusTotal | 4 req/min, 500/day | Scanner waits 15s between submit and retrieve |
| Google Gemini | 60 req/min | Free tier, no credit card needed |
| OpenAI GPT-4o | ~$0.01–0.03/scan | Paid per token |
| AbuseIPDB | 1,000 checks/day | Only triggers when URL has an IP address |
| WHOIS | Unlimited | Free, no API key needed |

---

## 🐛 Troubleshooting

| Issue | Cause | Fix |
|---|---|---|
| `VIRUSTOTAL_API_KEY not found` | `.env` missing or wrong | Create `.env` from `.env.example`. No spaces around `=`. |
| `GOOGLE_API_KEY not found` | Wrong provider set | Set `LLM_PROVIDER=gemini` and add `GOOGLE_API_KEY` |
| `No compatible Gemini model found` | API key invalid | Check key at [aistudio.google.com](https://aistudio.google.com) |
| `pip is not recognized` | Python not on PATH | Use `python -m pip install -r requirements.txt` |
| `Rate limit exceeded` | Too many VT requests | Wait 1 minute — VT free tier: 4 req/min |
| `OpenAI error 429` | Quota exceeded | Add credits or switch to `LLM_PROVIDER=gemini` |
| `python-whois not installed` | Missing package | Run `pip install python-whois` |
| `streamlit: command not found` | Not installed | Run `pip install streamlit` |
| `ModuleNotFoundError` | Dependencies missing | Run `pip install -r requirements.txt` |

---

## 🔐 Security Notes

- The scanner **never visits** the target URL in a browser or makes HTTP requests to it.
- All analysis is done on the URL string and external reputation APIs only.
- URLs are sent to VirusTotal and your chosen LLM. Do not scan private or internal URLs.
- Always add `.env` to `.gitignore` before pushing to GitHub.
- WHOIS lookups are done locally through the `python-whois` library — no third-party service.

---

## 🤝 Contributing

Contributions are welcome.

1. Fork the repository.
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Make your changes and test them.
4. Commit: `git commit -m "Add: your feature description"`
5. Push: `git push origin feature/your-feature`
6. Open a Pull Request.

**Ideas for contributions:**
- Add URL screenshot capture with Playwright
- Add Slack or email alert output
- Add threat intel feed integration (URLhaus, PhishTank, OpenPhish)
- Add Flask API wrapper
- Add SIEM integration (Splunk HEC / Sentinel Log Analytics)

---

## 📄 License

This project is licensed under the **MIT License** — free to use, modify, and distribute with attribution.

---

## 🙏 Acknowledgements

- [VirusTotal](https://www.virustotal.com) — URL and file reputation API
- [AbuseIPDB](https://www.abuseipdb.com) — IP reputation and abuse tracking
- [Google Gemini](https://aistudio.google.com) — AI semantic analysis
- [OpenAI](https://openai.com) — GPT-4o AI analysis
- [MITRE ATT&CK](https://attack.mitre.org) — Threat technique framework
- [python-whois](https://pypi.org/project/python-whois/) — WHOIS lookup library

---

Made with 🔍 by **Praharsh Kumar**

[![LinkedIn](https://img.shields.io/badge/LinkedIn-praharshkumar23-blue?logo=linkedin)](https://linkedin.com/in/praharshkumar23)
[![GitHub](https://img.shields.io/badge/GitHub-praharshkumar23-black?logo=github)](https://github.com/praharshkumar23)
