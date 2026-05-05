#!/usr/bin/env python3
"""
Email Header Phishing Scanner
Part of AI Phishing Scanner v3.0
Built by Praharsh Kumar

Paste a raw email header and this tool will:
- Extract all URLs from the email body/headers
- Scan each URL through the phishing scanner
- Check SPF / DKIM / DMARC authentication
- Flag display-name vs actual sender mismatches
- Return a full phishing verdict for the email
"""

import re
import email
import json
import os
import sys
from typing import Dict, List
from urllib.parse import urlparse
from datetime import datetime

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    print("colorama not installed. Run: pip install colorama")
    sys.exit(1)

# Import main scanner
sys.path.insert(0, os.path.dirname(__file__))
from phishing_scanner import PhishingScanner


def ok(msg):   print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} {msg}")
def warn(msg): print(f"  {Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")
def err(msg):  print(f"  {Fore.RED}[-]{Style.RESET_ALL} {msg}")
def info(msg): print(f"  {Fore.BLUE}[>]{Style.RESET_ALL} {msg}")
def divider(): print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")


class EmailPhishingScanner:
    """
    Analyzes raw email headers and body for phishing indicators.
    Extracts URLs and scans each one using the main PhishingScanner.
    """

    def __init__(self):
        self.url_scanner = PhishingScanner()

    # ── EXTRACT URLS FROM EMAIL ───────────────────────────────────────────────
    def extract_urls(self, text: str) -> List[str]:
        """Extract all URLs from email text."""
        url_pattern = re.compile(
            r'https?://[^\s<>"'\)\]]+',
            re.IGNORECASE
        )
        urls = list(set(url_pattern.findall(text)))
        # Clean trailing punctuation
        cleaned = []
        for u in urls:
            u = u.rstrip(".,;:)\'\">")
            cleaned.append(u)
        return list(set(cleaned))

    # ── PARSE EMAIL HEADERS ───────────────────────────────────────────────────
    def parse_headers(self, raw_email: str) -> Dict:
        """Parse email headers and extract key security fields."""
        try:
            msg = email.message_from_string(raw_email)
        except Exception as e:
            return {"error": f"Failed to parse email: {str(e)}"}

        from_header    = msg.get("From", "")
        reply_to       = msg.get("Reply-To", "")
        return_path    = msg.get("Return-Path", "")
        subject        = msg.get("Subject", "")
        date           = msg.get("Date", "")
        received       = msg.get_all("Received", [])
        auth_results   = msg.get("Authentication-Results", "")
        dkim           = msg.get("DKIM-Signature", "")
        spf_header     = msg.get("Received-SPF", "")
        message_id     = msg.get("Message-ID", "")

        # Extract display name vs actual email
        display_name_match = re.search(r'^"?([^<"]+)"?\s*<', from_header)
        email_match        = re.search(r'<([^>]+)>', from_header)

        display_name   = display_name_match.group(1).strip() if display_name_match else ""
        actual_email   = email_match.group(1).strip() if email_match else from_header.strip()
        actual_domain  = actual_email.split("@")[-1] if "@" in actual_email else ""

        reply_to_match  = re.search(r'<([^>]+)>', reply_to)
        reply_to_email  = reply_to_match.group(1).strip() if reply_to_match else reply_to.strip()
        reply_to_domain = reply_to_email.split("@")[-1] if "@" in reply_to_email else ""

        # Check SPF pass/fail
        spf_pass  = "pass"  in spf_header.lower()  if spf_header else None
        spf_fail  = "fail"  in spf_header.lower()  if spf_header else None
        dkim_pass = "pass"  in auth_results.lower() and "dkim" in auth_results.lower()
        dmarc_pass= "pass"  in auth_results.lower() and "dmarc" in auth_results.lower()

        # Reply-to domain mismatch
        reply_mismatch = (
            reply_to_email and
            actual_domain and
            reply_to_domain != actual_domain
        )

        # Check brand spoofing in display name
        brands = ["amazon", "paypal", "apple", "microsoft", "google",
                  "facebook", "netflix", "dropbox", "linkedin", "bank"]
        display_name_lower = display_name.lower()
        spoofed_brand = next(
            (b for b in brands if b in display_name_lower and b not in actual_domain.lower()),
            None
        )

        # Urgency keywords in subject
        urgency_keywords = [
            "urgent", "immediate", "action required", "verify", "suspend",
            "locked", "unusual", "confirm", "update", "security alert",
            "password", "account", "limited time", "expires", "click now"
        ]
        found_urgency = [k for k in urgency_keywords if k in subject.lower()]

        # Extract body text for URL extraction
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type in ["text/plain", "text/html"]:
                    try:
                        body += part.get_payload(decode=True).decode("utf-8", errors="ignore")
                    except Exception:
                        pass
        else:
            try:
                body = msg.get_payload(decode=True).decode("utf-8", errors="ignore")
            except Exception:
                body = str(msg.get_payload())

        return {
            "from_header"      : from_header,
            "display_name"     : display_name,
            "actual_email"     : actual_email,
            "actual_domain"    : actual_domain,
            "reply_to"         : reply_to_email,
            "reply_to_domain"  : reply_to_domain,
            "return_path"      : return_path,
            "subject"          : subject,
            "date"             : date,
            "message_id"       : message_id,
            "spf_pass"         : spf_pass,
            "spf_fail"         : spf_fail,
            "dkim_signed"      : bool(dkim),
            "dkim_pass"        : dkim_pass,
            "dmarc_pass"       : dmarc_pass,
            "auth_results"     : auth_results,
            "reply_mismatch"   : reply_mismatch,
            "spoofed_brand"    : spoofed_brand,
            "urgency_keywords" : found_urgency,
            "received_hops"    : len(received),
            "body"             : body,
            "raw_headers"      : dict(msg.items()),
        }

    # ── SCAN EMAIL ────────────────────────────────────────────────────────────
    def scan_email(self, raw_email: str) -> Dict:
        """Full email phishing scan."""
        divider()
        print(f"{Fore.CYAN}  EMAIL PHISHING SCANNER{Style.RESET_ALL}")
        divider()

        # Step 1: Parse headers
        info("Parsing email headers...")
        headers = self.parse_headers(raw_email)
        if "error" in headers:
            err(headers["error"])
            return {"error": headers["error"]}
        ok(f"From: {headers['actual_email']}")
        ok(f"Subject: {headers['subject'][:60]}")

        # Step 2: Extract URLs
        info("Extracting URLs from email body...")
        urls = self.extract_urls(headers["body"] + raw_email)
        ok(f"Found {len(urls)} URL(s)")

        # Step 3: Scan each URL
        url_reports = []
        if urls:
            print(f"\n{Fore.YELLOW}Scanning {len(urls)} extracted URL(s)...{Style.RESET_ALL}\n")
            for i, url in enumerate(urls, 1):
                print(f"{Fore.YELLOW}  [{i}/{len(urls)}] {url}{Style.RESET_ALL}")
                report = self.url_scanner.scan(url)
                url_reports.append(report)
        else:
            warn("No URLs found in email.")

        # Step 4: Calculate email risk score
        risk_factors = []

        # Header-based risk signals
        if headers["spf_fail"]:           risk_factors.append(("SPF failed",         30))
        if not headers["dkim_signed"]:    risk_factors.append(("No DKIM signature",  20))
        if not headers["dkim_pass"]:      risk_factors.append(("DKIM not verified",  15))
        if not headers["dmarc_pass"]:     risk_factors.append(("DMARC not verified", 15))
        if headers["reply_mismatch"]:     risk_factors.append(("Reply-To mismatch",  25))
        if headers["spoofed_brand"]:      risk_factors.append((f"Brand spoofing: {headers['spoofed_brand']}", 35))
        if headers["urgency_keywords"]:   risk_factors.append((f"Urgency keywords: {', '.join(headers['urgency_keywords'][:3])}", 20))

        # URL-based risk
        malicious_urls  = [r for r in url_reports if r.get("verdict", {}).get("status") == "MALICIOUS"]
        suspicious_urls = [r for r in url_reports if r.get("verdict", {}).get("status") == "SUSPICIOUS"]

        if malicious_urls:
            risk_factors.append((f"{len(malicious_urls)} malicious URL(s) found", 50))
        if suspicious_urls:
            risk_factors.append((f"{len(suspicious_urls)} suspicious URL(s) found", 25))

        total_risk = min(sum(v for _, v in risk_factors), 100)

        if total_risk >= 70:
            verdict = "PHISHING"
            label   = "🚨 HIGH RISK — This email is likely a phishing attack"
            action  = "DO NOT click any links. Report to security team immediately."
        elif total_risk >= 40:
            verdict = "SUSPICIOUS"
            label   = "⚠️  SUSPICIOUS — This email shows phishing indicators"
            action  = "Verify sender identity before clicking any links."
        else:
            verdict = "LIKELY SAFE"
            label   = "✅ LOW RISK — No significant phishing indicators found"
            action  = "Email appears legitimate but always verify sender context."

        return {
            "timestamp"      : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "verdict"        : verdict,
            "label"          : label,
            "action"         : action,
            "risk_score"     : total_risk,
            "risk_factors"   : risk_factors,
            "headers"        : headers,
            "urls_found"     : urls,
            "url_reports"    : url_reports,
            "malicious_urls" : [r["url"] for r in malicious_urls],
            "suspicious_urls": [r["url"] for r in suspicious_urls],
        }

    # ── PRINT REPORT ─────────────────────────────────────────────────────────
    def print_report(self, result: Dict):
        if "error" in result:
            err(result["error"])
            return

        divider()
        print(f"{Fore.CYAN}  EMAIL SCAN REPORT{Style.RESET_ALL}")
        divider()

        v_color = Fore.RED if result["verdict"] == "PHISHING" else (Fore.YELLOW if result["verdict"] == "SUSPICIOUS" else Fore.GREEN)
        print(f"\n  {v_color}{result['label']}{Style.RESET_ALL}")
        print(f"  Risk Score : {result['risk_score']}/100")
        print(f"  Action     : {result['action']}\n")

        h = result["headers"]
        print(f"{Fore.YELLOW}  SENDER ANALYSIS{Style.RESET_ALL}")
        print(f"  From         : {h['actual_email']}")
        print(f"  Display Name : {h['display_name'] or '(none)'}")
        print(f"  Reply-To     : {h['reply_to'] or '(same as From)'}")
        print(f"  Subject      : {h['subject'][:80]}")

        print(f"\n{Fore.YELLOW}  AUTHENTICATION{Style.RESET_ALL}")
        print(f"  SPF          : {Fore.GREEN+'PASS'+Style.RESET_ALL if h['spf_pass'] else Fore.RED+'FAIL/UNKNOWN'+Style.RESET_ALL}")
        print(f"  DKIM Signed  : {Fore.GREEN+'YES'+Style.RESET_ALL if h['dkim_signed'] else Fore.RED+'NO'+Style.RESET_ALL}")
        print(f"  DKIM Valid   : {Fore.GREEN+'YES'+Style.RESET_ALL if h['dkim_pass'] else Fore.RED+'NO/UNKNOWN'+Style.RESET_ALL}")
        print(f"  DMARC        : {Fore.GREEN+'PASS'+Style.RESET_ALL if h['dmarc_pass'] else Fore.RED+'FAIL/UNKNOWN'+Style.RESET_ALL}")

        if h["reply_mismatch"]:
            print(f"\n  {Fore.RED}⚠ Reply-To mismatch: From {h['actual_domain']} → Reply-To {h['reply_to_domain']}{Style.RESET_ALL}")

        if h["spoofed_brand"]:
            print(f"  {Fore.RED}⚠ Brand spoofing detected: {h['spoofed_brand']} in display name{Style.RESET_ALL}")

        if h["urgency_keywords"]:
            print(f"  {Fore.YELLOW}⚠ Urgency keywords: {', '.join(h['urgency_keywords'])}{Style.RESET_ALL}")

        print(f"\n{Fore.YELLOW}  RISK FACTORS{Style.RESET_ALL}")
        for factor, score in result["risk_factors"]:
            color = Fore.RED if score >= 30 else Fore.YELLOW
            print(f"  {color}[+{score:2d}]{Style.RESET_ALL} {factor}")

        print(f"\n{Fore.YELLOW}  URLs FOUND ({len(result['urls_found'])}){Style.RESET_ALL}")
        for url in result["urls_found"]:
            verdict_map = {r["url"]: r.get("verdict",{}).get("status","?") for r in result["url_reports"]}
            status = verdict_map.get(url, "?")
            color = Fore.RED if status == "MALICIOUS" else (Fore.YELLOW if status == "SUSPICIOUS" else Fore.GREEN)
            print(f"  {color}[{status}]{Style.RESET_ALL} {url}")

        divider()


# ── MAIN ──────────────────────────────────────────────────────────────────────
def main():
    print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  📧 EMAIL PHISHING SCANNER{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  Paste raw email headers/body below.{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  Type END on a new line when done.{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")

    lines = []
    try:
        while True:
            line = input()
            if line.strip().upper() == "END":
                break
            lines.append(line)
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return

    raw_email = "\n".join(lines)
    if not raw_email.strip():
        err("No email content provided.")
        return

    scanner = EmailPhishingScanner()
    result  = scanner.scan_email(raw_email)
    scanner.print_report(result)

    save = input(f"\n{Fore.GREEN}Save report to JSON? (y/n) > {Style.RESET_ALL}").strip().lower()
    if save == "y":
        ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"email_scan_{ts}.json"
        with open(filename, "w") as f:
            json.dump(result, f, indent=2, default=str)
        print(f"{Fore.GREEN}  [+] Saved to {filename}{Style.RESET_ALL}")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
