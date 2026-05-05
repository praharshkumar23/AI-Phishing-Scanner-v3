#!/usr/bin/env python3
"""
AI Phishing Link Scanner v3.0
Built by Praharsh Kumar

Layers:
  1. Static Analysis
  2. WHOIS Domain Age Check
  3. VirusTotal Reputation
  4. AbuseIPDB IP Reputation
  5. AI Semantic Analysis (Gemini / OpenAI)

Modes:
  - Single URL scan
  - Batch URL scan
  - CSV bulk scan
  - Scan history
  - JSON export
"""

import re
import time
import sys
import json
import os
from datetime import datetime, timezone
from typing import Dict, List, Tuple
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    print("colorama not installed. Run: pip install colorama")
    sys.exit(1)

load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSEIPDB_API_KEY  = os.getenv("ABUSEIPDB_API_KEY")
OPENAI_API_KEY     = os.getenv("OPENAI_API_KEY")
GOOGLE_API_KEY     = os.getenv("GOOGLE_API_KEY")
LLM_PROVIDER       = os.getenv("LLM_PROVIDER", "gemini").lower()

VT_API_BASE    = "https://www.virustotal.com/api/v3"
ABUSEIPDB_BASE = "https://api.abuseipdb.com/api/v2"
SCAN_LOG_FILE  = "scan_history.json"

BANNER = """
  ██████╗ ██╗  ██╗██╗███████╗██╗  ██╗██╗███╗   ██╗ ██████╗
  ██╔══██╗██║  ██║██║██╔════╝██║  ██║██║████╗  ██║██╔════╝
  ██████╔╝███████║██║███████╗███████║██║██╔██╗ ██║██║  ███╗
  ██╔═══╝ ██╔══██║██║╚════██║██╔══██║██║██║╚██╗██║██║   ██║
  ██║     ██║  ██║██║███████║██║  ██║██║██║ ╚████║╚██████╔╝
  ╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝

  AI Phishing Link Scanner v3.0  |  Built by Praharsh Kumar
  SC-200 | Detection Engineering | Threat Intelligence
"""

def divider(char="=", length=70):
    print(char * length)

def ok(msg):   print(f"  [+] {msg}")
def warn(msg): print(f"  [!] {msg}")
def err(msg):  print(f"  [-] {msg}")
def info(msg): print(f"  [>] {msg}")


class PhishingScanner:

    def __init__(self):
        self._validate_config()
        self._init_llm()

    def _validate_config(self):
        if not VIRUSTOTAL_API_KEY:
            raise ValueError("VIRUSTOTAL_API_KEY missing from .env")
        if LLM_PROVIDER == "openai" and not OPENAI_API_KEY:
            raise ValueError("OPENAI_API_KEY missing from .env")
        if LLM_PROVIDER == "gemini" and not GOOGLE_API_KEY:
            raise ValueError("GOOGLE_API_KEY missing from .env")

    def _init_llm(self):
        try:
            if LLM_PROVIDER == "openai":
                from openai import OpenAI
                self.llm_client = OpenAI(api_key=OPENAI_API_KEY)
                self.llm_model  = "gpt-4o-mini"
                ok(f"OpenAI ready ({self.llm_model})")
            elif LLM_PROVIDER == "gemini":
                import google.generativeai as genai
                genai.configure(api_key=GOOGLE_API_KEY)
                model_priority = ["gemini-2.5-flash","gemini-2.5-pro","gemini-1.5-flash","gemini-1.5-pro","gemini-pro"]
                self.llm_client = None
                self.llm_model  = None
                for name in model_priority:
                    try:
                        client = genai.GenerativeModel(name)
                        client.generate_content("ping")
                        self.llm_client = client
                        self.llm_model  = name
                        ok(f"Gemini ready ({name})")
                        break
                    except Exception as e:
                        if "404" in str(e) or "not found" in str(e).lower():
                            continue
                        raise
                if not self.llm_client:
                    raise ValueError("No compatible Gemini model found.")
            else:
                raise ValueError(f"Unknown LLM_PROVIDER: {LLM_PROVIDER}")
        except ImportError:
            raise ImportError("Install missing library: pip install -r requirements.txt")

    # ── URL VALIDATION ────────────────────────────────────────────────────────
    def validate_url(self, url: str) -> Tuple[bool, str]:
        pattern = re.compile(
            r'^https?://'
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'
            r'localhost|\d{1,3}(?:\.\d{1,3}){3})'
            r'(?::\d+)?(?:/?|[/?]\S+)$', re.IGNORECASE)
        if not pattern.match(url):
            return False, "Invalid URL format"
        return True, ""

    # ── STATIC ANALYSIS ───────────────────────────────────────────────────────
    def static_analysis(self, url: str) -> Dict:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        phishing_keywords = [
            'login','signin','account','verify','secure','update','confirm',
            'banking','paypal','amazon','apple','microsoft','password',
            'suspend','locked','unusual','click','urgent','alert',
            'validate','authorize','authenticate','recover'
        ]
        typosquat_patterns = [
            r'amaz[o0]n',r'g[o0]{2}gle',r'faceb[o0]{2}k',r'micr[o0]s[o0]ft',
            r'paypa[l1]',r'app[l1]e',r'netf[l1]ix',r'tw[i1]tter',
            r'ins[t7]agram',r'[l1]inked[i1]n',r'dropb[o0]x',r'[o0]ff[i1]ce365'
        ]
        found_keywords  = [kw for kw in phishing_keywords if kw in url.lower()]
        found_typosquat = [p for p in typosquat_patterns if re.search(p, domain)]
        flags = {
            "has_ip_address"       : bool(re.match(r'\d{1,3}(?:\.\d{1,3}){3}', domain)),
            "excessive_length"     : len(url) > 75,
            "excessive_subdomains" : domain.count('.') > 3,
            "has_suspicious_tld"   : any(domain.endswith(t) for t in ['.tk','.ml','.ga','.cf','.gq','.pw','.top','.xyz']),
            "uses_http"            : parsed.scheme == 'http',
            "has_at_symbol"        : '@' in url,
            "has_double_slash"     : '//' in parsed.path,
            "has_hex_encoding"     : bool(re.search(r'%[0-9a-fA-F]{2}', url)),
            "suspicious_keywords"  : found_keywords,
            "typosquatting"        : found_typosquat,
        }
        score = sum([
            flags["has_ip_address"]*30, flags["excessive_length"]*15,
            flags["excessive_subdomains"]*20, flags["has_suspicious_tld"]*25,
            flags["uses_http"]*10, flags["has_at_symbol"]*20,
            flags["has_double_slash"]*15, flags["has_hex_encoding"]*10,
            len(flags["suspicious_keywords"])*5, len(flags["typosquatting"])*30,
        ])
        flags["risk_score"] = min(score, 100)
        return flags

    # ── WHOIS DOMAIN AGE ─────────────────────────────────────────────────────
    def check_domain_age(self, url: str) -> Dict:
        """Check domain registration age — newly registered = high risk."""
        try:
            import whois as pythonwhois
        except ImportError:
            return {"available": False, "error": "python-whois not installed. Run: pip install python-whois"}

        domain = urlparse(url).netloc.lower().split(":")[0]
        if domain.startswith("www."):
            domain = domain[4:]

        # Skip IP addresses
        if re.match(r'\d{1,3}(?:\.\d{1,3}){3}', domain):
            return {"available": False, "error": "IP address — WHOIS skipped"}

        info(f"WHOIS lookup: {domain}")
        try:
            w = pythonwhois.whois(domain)
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            if not creation_date:
                return {"available": False, "error": "Creation date not found in WHOIS"}

            if hasattr(creation_date, "tzinfo") and creation_date.tzinfo is None:
                creation_date = creation_date.replace(tzinfo=timezone.utc)

            now      = datetime.now(timezone.utc)
            age_days = (now - creation_date).days
            is_new   = age_days < 30
            is_recent= age_days < 90

            return {
                "available"    : True,
                "domain"       : domain,
                "created"      : creation_date.strftime("%Y-%m-%d"),
                "age_days"     : age_days,
                "is_new_domain": is_new,
                "is_recent"    : is_recent,
                "registrar"    : str(w.registrar or "Unknown"),
                "country"      : str(w.country or "Unknown"),
                "risk_flag"    : "HIGH — domain < 30 days old" if is_new else
                                 ("MEDIUM — domain < 90 days old" if is_recent else
                                  "LOW — domain age is normal"),
            }
        except Exception as e:
            return {"available": False, "error": f"WHOIS failed: {str(e)}"}

    # ── VIRUSTOTAL ────────────────────────────────────────────────────────────
    def check_virustotal(self, url: str) -> Dict:
        info("Submitting to VirusTotal...")
        headers = {"accept": "application/json", "x-apikey": VIRUSTOTAL_API_KEY}
        try:
            r = requests.post(f"{VT_API_BASE}/urls", headers=headers, data={"url": url}, timeout=15)
            if r.status_code == 401: return {"available": False, "error": "Invalid VT API key"}
            if r.status_code == 429: return {"available": False, "error": "VT rate limit — wait 1 min"}
            if r.status_code != 200: return {"available": False, "error": f"VT error {r.status_code}"}
            analysis_id = r.json()["data"]["id"]
            info("Waiting 15s for VT analysis...")
            time.sleep(15)
            r2 = requests.get(f"{VT_API_BASE}/analyses/{analysis_id}", headers=headers, timeout=15)
            if r2.status_code != 200: return {"available": False, "error": f"VT retrieval error {r2.status_code}"}
            attrs = r2.json()["data"]["attributes"]
            stats = attrs.get("stats", {})
            total = sum(stats.values()) if stats else 0
            return {"available":True,"malicious":stats.get("malicious",0),"suspicious":stats.get("suspicious",0),
                    "harmless":stats.get("harmless",0),"undetected":stats.get("undetected",0),
                    "total":total,"status":attrs.get("status","unknown")}
        except requests.exceptions.Timeout:
            return {"available": False, "error": "VT request timed out"}
        except Exception as e:
            return {"available": False, "error": str(e)}

    # ── ABUSEIPDB ─────────────────────────────────────────────────────────────
    def check_abuseipdb(self, url: str) -> Dict:
        if not ABUSEIPDB_API_KEY:
            return {"available": False, "error": "ABUSEIPDB_API_KEY not set"}
        domain   = urlparse(url).netloc
        ip_match = re.match(r'(\d{1,3}(?:\.\d{1,3}){3})', domain)
        if not ip_match:
            return {"available": False, "error": "No IP in URL — AbuseIPDB skipped"}
        ip = ip_match.group(1)
        info(f"AbuseIPDB check: {ip}")
        try:
            r = requests.get(f"{ABUSEIPDB_BASE}/check",
                headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90}, timeout=10)
            if r.status_code != 200: return {"available": False, "error": f"AbuseIPDB error {r.status_code}"}
            data = r.json().get("data", {})
            return {"available":True,"ip":ip,"abuse_score":data.get("abuseConfidenceScore",0),
                    "total_reports":data.get("totalReports",0),"country":data.get("countryCode","Unknown"),
                    "isp":data.get("isp","Unknown"),"is_tor":data.get("isTor",False)}
        except Exception as e:
            return {"available": False, "error": str(e)}

    # ── LLM ANALYSIS ─────────────────────────────────────────────────────────
    def llm_analysis(self, url: str, static: Dict, whois: Dict) -> Dict:
        info(f"AI analysis ({self.llm_model})...")
        domain_age_info = f"Domain age: {whois.get('age_days','?')} days ({whois.get('risk_flag','unknown')})" if whois.get("available") else "Domain age: unknown"
        prompt = f"""You are a senior cybersecurity analyst specialising in phishing detection.

URL: {url}

Static Analysis:
- Risk Score     : {static['risk_score']}/100
- IP in URL      : {static['has_ip_address']}
- HTTP (not HTTPS): {static['uses_http']}
- Typosquatting  : {', '.join(static['typosquatting']) or 'None'}
- Suspicious KWs : {', '.join(static['suspicious_keywords']) or 'None'}
- Hex Encoding   : {static['has_hex_encoding']}
- Suspicious TLD : {static['has_suspicious_tld']}

WHOIS:
- {domain_age_info}

Respond in EXACTLY this format:
VERDICT: YES or NO
CONFIDENCE: 0-100
RED_FLAGS: comma-separated list or None
MITRE_TECHNIQUE: most relevant MITRE ATT&CK technique ID and name
REASONING: 2-3 sentences max
"""
        try:
            if LLM_PROVIDER == "openai":
                resp = self.llm_client.chat.completions.create(
                    model=self.llm_model,
                    messages=[{"role":"system","content":"You are a cybersecurity expert."},{"role":"user","content":prompt}],
                    temperature=0.2, max_tokens=300)
                text = resp.choices[0].message.content
            else:
                text = self.llm_client.generate_content(prompt).text

            def extract(pattern, default=""):
                m = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
                return m.group(1).strip() if m else default

            verdict    = extract(r'VERDICT:\s*(YES|NO)')
            confidence = int(extract(r'CONFIDENCE:\s*(\d+)', '0'))
            red_flags  = extract(r'RED_FLAGS:\s*(.+?)(?=MITRE|REASONING|$)')
            mitre      = extract(r'MITRE_TECHNIQUE:\s*(.+?)(?=REASONING|$)')
            reasoning  = extract(r'REASONING:\s*(.+)')

            return {"available":True,"is_phishing":verdict.upper()=="YES","confidence":confidence,
                    "red_flags":red_flags or "None","mitre_technique":mitre or "Not identified",
                    "reasoning":reasoning,"raw":text}
        except Exception as e:
            return {"available": False, "error": str(e)}

    # ── FINAL VERDICT ─────────────────────────────────────────────────────────
    def _final_verdict(self, static, whois, vt, abuse, llm) -> Dict:
        factors = [static["risk_score"] * 0.20]

        # WHOIS domain age adds risk
        if whois.get("available"):
            if whois.get("is_new_domain"):
                factors.append(80 * 0.15)
            elif whois.get("is_recent"):
                factors.append(40 * 0.15)
            else:
                factors.append(0)
        else:
            factors.append(static["risk_score"] * 0.05)

        if vt.get("available") and vt["total"] > 0:
            vt_risk = ((vt["malicious"] + vt["suspicious"] * 0.5) / vt["total"]) * 100
            factors.append(vt_risk * 0.35)

        if abuse.get("available"):
            factors.append(abuse["abuse_score"] * 0.10)

        if llm.get("available") and llm.get("is_phishing") is not None:
            llm_risk = llm["confidence"] if llm["is_phishing"] else (100 - llm["confidence"])
            factors.append(llm_risk * 0.20)

        risk = min(int(sum(factors)), 100)

        if risk >= 70:
            return {"risk":risk,"status":"MALICIOUS","label":"MALICIOUS — HIGH RISK",
                    "action":"DO NOT VISIT. Strong phishing indicators detected."}
        elif risk >= 40:
            return {"risk":risk,"status":"SUSPICIOUS","label":"SUSPICIOUS — MEDIUM RISK",
                    "action":"Exercise caution. Verify sender before clicking."}
        else:
            return {"risk":risk,"status":"SAFE","label":"APPEARS SAFE — LOW RISK",
                    "action":"URL looks legitimate. Always verify sender context."}

    # ── PRINT REPORT ─────────────────────────────────────────────────────────
    def print_report(self, report: Dict):
        if "error" in report:
            err(f"Scan failed: {report['error']}")
            return
        divider()
        print("  SCAN REPORT")
        divider()
        print(f"\n  URL      : {report['url']}")
        print(f"  Scanned  : {report['timestamp']}\n")

        s = report["static"]
        print("  STATIC ANALYSIS")
        print(f"  Risk Score      : {s['risk_score']}/100")
        print(f"  IP in URL       : {'YES' if s['has_ip_address'] else 'No'}")
        print(f"  HTTP (no HTTPS) : {'YES' if s['uses_http'] else 'No'}")
        print(f"  Suspicious TLD  : {'YES' if s['has_suspicious_tld'] else 'No'}")
        print(f"  Hex Encoding    : {'YES' if s['has_hex_encoding'] else 'No'}")
        if s["suspicious_keywords"]: print(f"  Keywords        : {', '.join(s['suspicious_keywords'])}")
        if s["typosquatting"]:       print(f"  Typosquatting   : {', '.join(s['typosquatting'])}")

        w = report["whois"]
        print("\n  WHOIS DOMAIN AGE")
        if w.get("available"):
            print(f"  Domain Age      : {w['age_days']} days (created {w['created']})")
            print(f"  Registrar       : {w['registrar']}")
            print(f"  Risk Flag       : {w['risk_flag']}")
        else:
            print(f"  {w.get('error', 'Not available')}")

        vt = report["virustotal"]
        print("\n  VIRUSTOTAL REPUTATION")
        if vt.get("available"):
            print(f"  Malicious  : {vt['malicious']}/{vt['total']}")
            print(f"  Suspicious : {vt['suspicious']}/{vt['total']}")
            print(f"  Harmless   : {vt['harmless']}/{vt['total']}")
        else:
            print(f"  {vt.get('error')}")

        abuse = report["abuseipdb"]
        print("\n  ABUSEIPDB CHECK")
        if abuse.get("available"):
            print(f"  Abuse Score : {abuse['abuse_score']}%  ({abuse['total_reports']} reports)")
            print(f"  Country/ISP : {abuse['country']} / {abuse['isp']}")
            print(f"  Tor Node    : {'YES' if abuse['is_tor'] else 'No'}")
        else:
            print(f"  {abuse.get('error')}")

        llm = report["llm"]
        print(f"\n  AI ANALYSIS ({self.llm_model})")
        if llm.get("available"):
            print(f"  Verdict         : {'PHISHING' if llm['is_phishing'] else 'LEGITIMATE'}")
            print(f"  Confidence      : {llm['confidence']}%")
            print(f"  Red Flags       : {llm['red_flags']}")
            print(f"  MITRE Technique : {llm['mitre_technique']}")
            print(f"  Reasoning       : {llm['reasoning'][:200]}")
        else:
            print(f"  {llm.get('error')}")

        v = report["verdict"]
        print(f"\n  {'='*60}")
        print(f"  FINAL VERDICT: {v['label']}")
        print(f"  Overall Risk : {v['risk']}/100")
        print(f"  Action       : {v['action']}")
        print(f"  {'='*60}\n")

    # ── SCAN ─────────────────────────────────────────────────────────────────
    def scan(self, url: str) -> Dict:
        divider()
        print(f"  SCANNING: {url}")
        divider()
        valid, msg = self.validate_url(url)
        if not valid:
            return {"error": msg, "url": url}
        ok("URL structure valid")

        print("\n[1/5] Static analysis...")
        static = self.static_analysis(url)
        ok(f"Risk score: {static['risk_score']}/100")

        print("\n[2/5] WHOIS domain age check...")
        whois = self.check_domain_age(url)
        ok(f"Domain age: {whois.get('age_days','?')} days — {whois.get('risk_flag','N/A')}") if whois.get("available") else warn(whois.get("error","Skipped"))

        print("\n[3/5] VirusTotal check...")
        vt = self.check_virustotal(url)
        ok("Done") if vt.get("available") else warn(vt.get("error","Failed"))

        print("\n[4/5] AbuseIPDB check...")
        abuse = self.check_abuseipdb(url)
        ok("Done") if abuse.get("available") else warn(abuse.get("error","Skipped"))

        print("\n[5/5] AI semantic analysis...")
        llm = self.llm_analysis(url, static, whois)
        ok(f"Done — {llm.get('confidence','?')}% confidence") if llm.get("available") else warn(llm.get("error","Failed"))

        verdict = self._final_verdict(static, whois, vt, abuse, llm)
        report  = {
            "url"       : url,
            "timestamp" : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "static"    : static,
            "whois"     : whois,
            "virustotal": vt,
            "abuseipdb" : abuse,
            "llm"       : llm,
            "verdict"   : verdict,
        }
        self._log_scan(report)
        return report

    # ── BATCH SCAN ────────────────────────────────────────────────────────────
    def batch_scan(self, urls: List[str]) -> List[Dict]:
        results = []
        print(f"\nBatch scanning {len(urls)} URLs...\n")
        for i, url in enumerate(urls, 1):
            print(f"[{i}/{len(urls)}]")
            r = self.scan(url)
            self.print_report(r)
            results.append(r)
        return results

    # ── CSV SCAN ──────────────────────────────────────────────────────────────
    def scan_csv(self, input_file: str, output_file: str = None) -> str:
        try:
            import csv
        except ImportError:
            err("csv module not available")
            return ""

        if not os.path.exists(input_file):
            err(f"File not found: {input_file}")
            return ""

        with open(input_file, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            if "url" not in (reader.fieldnames or []):
                err("CSV must have a column named 'url'")
                return ""
            rows = list(reader)

        print(f"\nFound {len(rows)} URLs in {input_file}")
        results = []
        for i, row in enumerate(rows, 1):
            url = row.get("url", "").strip()
            if not url:
                continue
            print(f"\n[{i}/{len(rows)}] {url}")
            r = self.scan(url)
            results.append({
                "url"         : url,
                "risk"        : r.get("verdict",{}).get("risk", "Error"),
                "status"      : r.get("verdict",{}).get("status", "Error"),
                "action"      : r.get("verdict",{}).get("action", ""),
                "vt_malicious": r.get("virustotal",{}).get("malicious", "N/A"),
                "domain_age"  : r.get("whois",{}).get("age_days", "N/A"),
                "ai_verdict"  : "PHISHING" if r.get("llm",{}).get("is_phishing") else "LEGITIMATE",
                "mitre"       : r.get("llm",{}).get("mitre_technique","N/A"),
            })

        if not output_file:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"bulk_scan_{ts}.csv"

        with open(output_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(results[0].keys()))
            writer.writeheader()
            writer.writerows(results)

        ok(f"CSV report saved: {output_file}")
        return output_file

    # ── EXPORT JSON ──────────────────────────────────────────────────────────
    def export_json(self, data, filename: str = None):
        if not filename:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"scan_report_{ts}.json"
        with open(filename, "w") as f:
            json.dump(data, f, indent=2, default=str)
        ok(f"Report saved: {filename}")
        return filename

    # ── SCAN HISTORY LOG ─────────────────────────────────────────────────────
    def _log_scan(self, report: Dict):
        history = []
        if os.path.exists(SCAN_LOG_FILE):
            try:
                with open(SCAN_LOG_FILE) as f:
                    history = json.load(f)
            except Exception:
                history = []
        history.append({
            "timestamp" : report["timestamp"],
            "url"       : report["url"],
            "risk"      : report["verdict"]["risk"],
            "status"    : report["verdict"]["status"],
        })
        with open(SCAN_LOG_FILE, "w") as f:
            json.dump(history, f, indent=2)

    def show_history(self):
        if not os.path.exists(SCAN_LOG_FILE):
            warn("No scan history found.")
            return
        with open(SCAN_LOG_FILE) as f:
            history = json.load(f)
        divider()
        print(f"  SCAN HISTORY ({len(history)} scans)")
        divider()
        for h in history[-20:]:
            print(f"  {h['timestamp']}  {h['status']:12}  Risk: {h['risk']:3}/100  {h['url']}")
        print()


# ── MAIN ──────────────────────────────────────────────────────────────────────
def main():
    print(BANNER)
    scanner = PhishingScanner()

    if len(sys.argv) > 1:
        arg = sys.argv[1]
        if arg.endswith(".csv"):
            out = scanner.scan_csv(arg)
            print(f"Done. Report: {out}")
        else:
            report = scanner.scan(arg)
            scanner.print_report(report)
            scanner.export_json(report)
        return

    while True:
        print("\n  OPTIONS")
        print("  1  Scan a single URL")
        print("  2  Batch scan (multiple URLs)")
        print("  3  Scan from CSV file")
        print("  4  View scan history")
        print("  q  Quit\n")
        choice = input("  > ").strip().lower()

        if choice == "q":
            print("Goodbye.")
            break
        elif choice == "1":
            url = input("  URL > ").strip()
            if url:
                report = scanner.scan(url)
                scanner.print_report(report)
                if input("  Save to JSON? (y/n) > ").strip().lower() == "y":
                    scanner.export_json(report)
        elif choice == "2":
            print("  Enter URLs one per line. Empty line to start.")
            urls = []
            while True:
                u = input(f"  URL {len(urls)+1} > ").strip()
                if not u: break
                urls.append(u)
            if urls:
                reports = scanner.batch_scan(urls)
                if input("  Save all to JSON? (y/n) > ").strip().lower() == "y":
                    scanner.export_json(reports)
        elif choice == "3":
            f = input("  CSV file path > ").strip()
            scanner.scan_csv(f)
        elif choice == "4":
            scanner.show_history()
        else:
            warn("Invalid choice.")


if __name__ == "__main__":
    try:
        main()
    except ValueError as e:
        print(f"Config error: {e}")
    except ImportError as e:
        print(f"Import error: {e}\nRun: pip install -r requirements.txt")
    except KeyboardInterrupt:
        print("\nInterrupted.")
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
