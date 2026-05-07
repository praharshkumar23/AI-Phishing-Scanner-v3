# 🛡️ AI Phishing Link Scanner v3.0

> Multi-layer phishing detection combining static analysis, WHOIS domain age check, VirusTotal + AbuseIPDB reputation, and AI semantic analysis (Gemini / GPT-4o). Now with a **Streamlit web UI**, **bulk CSV scanning**, **email header phishing analyzer**, **attacker simulation mode**, and **SOC incident report generator**.

Built by **Praharsh Kumar** — SOC Analyst | Detection Engineering | SC-200 Certified

[![Live Demo](https://img.shields.io/badge/Live%20Demo-Streamlit-red?logo=streamlit)](https://praharsh-phishing-scanner.streamlit.app)
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
- [Attacker Simulation Mode](#-attacker-simulation-mode)
- [SOC Playbook Generator](#-soc-playbook-generator)
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

This scanner runs every URL through **5 independent detection layers** and combines their signals into a single weighted risk score out of 100. Version 3.0 adds a full **Streamlit web UI**, **WHOIS domain age check**, **bulk CSV scanning**, a dedicated **email header phishing analyzer**, an **attacker simulation mode** for brand protection research, and an automated **SOC incident report generator**.

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
| **Attacker Simulation Mode** | ❌ | ✅ |
| **SOC Playbook & Incident Report (PDF)** | ❌ | ✅ |
| **MITRE ATT&CK response checklist** | ❌ | ✅ |
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
           → Auto-generates SOC Incident Report (PDF + JSON)
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
├── attacker_simulation.py    # Attacker simulation & brand protection
├── soc_playbook.py           # SOC incident report + playbook generator
├── requirements.txt          # All Python dependencies
├── .env.example              # API key template — rename to .env
├── .gitignore                # Excludes .env, venv, reports, cache
├── sample_urls.csv           # Sample CSV for bulk scan testing
├── README.md                 # This file
│
└── (auto-generated on use)
    ├── scan_history.json                     # Logs every scan
    ├── scan_report_TIMESTAMP.json            # Per-scan JSON export
    ├── bulk_scan_TIMESTAMP.csv               # Bulk scan CSV output
    ├── email_scan_TIMESTAMP.json             # Email scan JSON export
    ├── SOC_Report_INC-YYYY-XXXX.pdf          # SOC incident report PDF
    ├── SOC_Report_INC-YYYY-XXXX.json         # SOC incident report JSON
    └── simulation_domain_TIMESTAMP.json      # Attacker simulation report
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
| `reportlab` | 4.0.0+ | PDF SOC incident report generation |

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
- **Email Scanner** — analyze raw email content for embedded phishing URLs
- **Attacker Simulation** — generate and check phishing domain variants for any brand

**Deploy free on Streamlit Cloud:**

1. Push project to GitHub.
2. Go to [share.streamlit.io](https://share.streamlit.io).
3. Connect your GitHub repo.
4. Add API keys in the Streamlit Secrets section.
5. Deploy — you get a live public URL to share on your resume.

---

## 🚨 Real Scan — Live Demo Result

> This is an actual scan run against a real malicious URL using this tool.

**URL scanned:** `https://ybrjaouww.com/`

| Detection Layer | Result |
|---|---|
| Static Analysis | `0/100` — no obvious static indicators |
| VirusTotal | `11 / 93` engines flagged as **MALICIOUS** |
| AI Analysis (Gemini) | **PHISHING — 95% confidence** |
| MITRE ATT&CK | `T1566.002 — Spearphishing Link` |
| **Final Verdict** | ✅ **CAUGHT — MALICIOUS** |

**Why this matters:** Static analysis scored it 0/100 — the URL looked clean structurally. But VirusTotal flagged it across 11 engines and Gemini identified it as phishing with 95% confidence. This is exactly why single-layer detection fails. Multi-layer detection is not optional in a real SOC.

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

## 🎯 Attacker Simulation Mode

> For defensive research and brand protection only.

Generates phishing domain variants for a target brand and checks which ones are already registered by real attackers.

```bash
python attacker_simulation.py paypal.com
```

Or interactive:

```bash
python attacker_simulation.py
```

**What it generates:**

| Variant Type | Example |
|---|---|
| Homoglyph / Typosquatting | `paypa1.com`, `p4ypal.com` |
| Typo Variants | `paypall.com`, `paypl.com` |
| Combo Squatting | `secure-paypal.com`, `paypal-login.com` |
| Subdomain Abuse | `secure.paypal.com.evil.tk` |
| TLD Swap | `paypal.tk`, `paypal.ml`, `paypal.xyz` |

**Example output:**

```
[LIVE]  paypa1-login.tk    (Combo Squatting)
[LIVE]  paypal-verify.ml   (TLD Swap)
[LIVE]  p4ypal.com         (Homoglyph)

Generated : 52 variants
Live DNS  : 3 registered domains found
Scanned   : 3 through full scanner

[MALICIOUS]  Risk: 89/100  paypa1-login.tk
[SUSPICIOUS] Risk: 55/100  paypal-verify.ml
[MALICIOUS]  Risk: 91/100  p4ypal.com
```

**Use cases:**
- Brand protection monitoring — check if your company domain has phishing variants
- Red team research — understand attacker techniques
- Defensive threat hunting — proactive IOC discovery

---

## 📋 SOC Playbook Generator

After every scan, auto-generates a formatted SOC incident report as PDF and JSON.

```bash
python soc_playbook.py scan_report.json
```

Or call it directly from code:

```python
from soc_playbook import generate_from_scan
pdf_path = generate_from_scan(scan_result)
```

**What the report includes:**

- **Incident ID** — auto-incremented (INC-2026-0001)
- **Severity** — HIGH / MEDIUM / LOW with color coding
- **Risk score** — out of 100
- **IOC table** — URL, domain, VT detection count
- **MITRE ATT&CK mapping** — technique + tactic
- **Response playbook** — step-by-step analyst action checklist
- **Escalation recommendation** — Tier 2 escalation guidance
- **AI reasoning** — full Gemini analysis text
- **Detection breakdown** — all 5 layers summarized

**Sample report header:**

```
SOC INCIDENT REPORT
═══════════════════════════════════════

Incident ID  : INC-2026-0001
Analyst      : Praharsh Kumar
Date/Time    : 2026-05-06 12:45:00
Severity     : HIGH
Risk Score   : 91/100
MITRE        : T1566.002 - Spearphishing Link
Escalate     : YES — Escalate to Tier 2 immediately

RESPONSE CHECKLIST
  ☐  1. Block URL at web proxy and DNS filter
  ☐  2. Search mail gateway logs for distribution
  ☐  3. Identify all users who received the link
  ☐  4. Check endpoint logs for click events
  ☐  5. Force password reset for any user who clicked
  ...
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
<img width="1432" height="836" alt="Screenshot 2026-05-07 105829" src="https://github.com/user-attachments/assets/98a5c876-7229-409e-bda8-6f70f6afae54" />

```
======================================================================
  SCANNING: http://amaz0n-security-update.com/verify-account
======================================================================

[1/5] Static analysis...        Risk score: 75/100
[2/5] WHOIS domain age...       4 days — HIGH — domain < 30 days old
[3/5] VirusTotal check...       12 malicious / 89 engines
[4/5] AbuseIPDB check...        No IP in URL — skipped
[5/5] AI semantic analysis...   95% confidence — PHISHING

======================================================================
  FINAL VERDICT: MALICIOUS — HIGH RISK
  Overall Risk : 91/100
  MITRE        : T1566.002 - Phishing: Spearphishing Link
  Action       : DO NOT VISIT. Strong phishing indicators detected.
  SOC Report   : SOC_Report_INC-2026-0001.pdf generated
======================================================================
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
| `reportlab not installed` | Missing package | Run `pip install reportlab` |
| `streamlit: command not found` | Not installed | Run `pip install streamlit` |
| `ModuleNotFoundError` | Dependencies missing | Run `pip install -r requirements.txt` |

---

## 🔐 Security Notes

- The scanner **never visits** the target URL in a browser or makes HTTP requests to it.
- All analysis is done on the URL string and external reputation APIs only.
- URLs are sent to VirusTotal and your chosen LLM. Do not scan private or internal URLs.
- Always add `.env` to `.gitignore` before pushing to GitHub.
- WHOIS lookups are done locally through the `python-whois` library — no third-party service.
- Attacker Simulation Mode is for **defensive research only**. Do not use for malicious purposes.

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
- Add Slack or Teams alert integration
- Add threat intel feed integration (URLhaus, PhishTank, OpenPhish)
- Add Flask REST API wrapper
- Add SIEM integration (Splunk HEC / Sentinel Log Analytics)
- Add real-time threat feed dashboard

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
- [ReportLab](https://www.reportlab.com) — PDF generation

---

Made with 🔍 by **Praharsh Kumar**

[![LinkedIn](https://img.shields.io/badge/LinkedIn-praharshkumar23-blue?logo=linkedin)](https://linkedin.com/in/praharshkumar23)
[![GitHub](https://img.shields.io/badge/GitHub-praharshkumar23-black?logo=github)](https://github.com/praharshkumar23)
