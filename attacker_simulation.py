#!/usr/bin/env python3
"""
Attacker Simulation Mode — AI Phishing Scanner v3.0
Built by Praharsh Kumar

Takes a real domain and generates phishing variants:
- Typosquatting
- Homoglyph substitution
- Subdomain abuse
- TLD swapping
- Hyphen insertion
- Combo squatting

Then scans ALL variants through the full scanner to check which
are already registered, active, or flagged as malicious.

This is used for:
- Brand protection monitoring
- Red team phishing simulation
- Defensive research
"""

import re
import sys
import os
import json
import socket
import itertools
from datetime import datetime
from typing import List, Dict, Tuple
from urllib.parse import urlparse

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    print("Run: pip install colorama")
    sys.exit(1)

sys.path.insert(0, os.path.dirname(__file__))


def divider(): print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
def ok(m):    print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} {m}")
def warn(m):  print(f"  {Fore.YELLOW}[!]{Style.RESET_ALL} {m}")
def err(m):   print(f"  {Fore.RED}[-]{Style.RESET_ALL} {m}")
def info(m):  print(f"  {Fore.BLUE}[>]{Style.RESET_ALL} {m}")


# ── VARIANT GENERATORS ────────────────────────────────────────────────────────

HOMOGLYPHS = {
    'a': ['4', '@', 'а'],  # Cyrillic а
    'e': ['3', 'е'],       # Cyrillic е
    'i': ['1', 'l', '!'],
    'l': ['1', 'i'],
    'o': ['0', 'о'],       # Cyrillic о
    's': ['5', '$'],
    't': ['7'],
    'b': ['6'],
    'g': ['9'],
}

SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.top', '.xyz', '.click', '.link', '.online']

PHISHING_PREFIXES = ['secure-', 'login-', 'verify-', 'account-', 'update-', 'support-', 'help-', 'signin-']
PHISHING_SUFFIXES = ['-login', '-verify', '-secure', '-account', '-update', '-signin', '-support']
PHISHING_PATHS    = ['/login', '/verify', '/account', '/signin', '/update-password', '/confirm-identity', '/suspended']


def extract_domain(target: str) -> Tuple[str, str]:
    """Extract domain name and TLD from input."""
    target = target.lower().strip()
    if not target.startswith('http'):
        target = 'https://' + target
    parsed = urlparse(target)
    host   = parsed.netloc or parsed.path
    host   = host.replace('www.', '')
    parts  = host.rsplit('.', 1)
    if len(parts) == 2:
        return parts[0], '.' + parts[1]
    return host, '.com'


def generate_homoglyphs(name: str) -> List[str]:
    """Generate typosquatting variants using character substitution."""
    variants = set()
    for i, char in enumerate(name):
        if char in HOMOGLYPHS:
            for replacement in HOMOGLYPHS[char]:
                variant = name[:i] + replacement + name[i+1:]
                variants.add(variant)
    # Double substitution
    for i, c1 in enumerate(name):
        if c1 in HOMOGLYPHS:
            for r1 in HOMOGLYPHS[c1]:
                for j, c2 in enumerate(name):
                    if j != i and c2 in HOMOGLYPHS:
                        for r2 in HOMOGLYPHS[c2]:
                            v = list(name)
                            v[i] = r1
                            v[j] = r2
                            variants.add(''.join(v))
    return list(variants)[:15]  # Cap at 15


def generate_typos(name: str) -> List[str]:
    """Generate common typo variants."""
    variants = set()
    # Missing letter
    for i in range(len(name)):
        variants.add(name[:i] + name[i+1:])
    # Doubled letter
    for i, c in enumerate(name):
        variants.add(name[:i] + c + c + name[i+1:])
    # Transposed adjacent letters
    for i in range(len(name) - 1):
        v = list(name)
        v[i], v[i+1] = v[i+1], v[i]
        variants.add(''.join(v))
    # Added hyphen
    for i in range(1, len(name)):
        variants.add(name[:i] + '-' + name[i:])
    return [v for v in variants if len(v) > 2 and v != name][:10]


def generate_combo_squats(name: str) -> List[str]:
    """Add phishing prefixes/suffixes to domain name."""
    variants = []
    for prefix in PHISHING_PREFIXES:
        variants.append(prefix + name)
    for suffix in PHISHING_SUFFIXES:
        variants.append(name + suffix)
    return variants


def generate_subdomain_abuse(name: str, tld: str) -> List[str]:
    """Generate subdomain abuse variants."""
    return [
        f"secure.{name}{tld}",
        f"login.{name}{tld}",
        f"account.{name}{tld}",
        f"verify.{name}{tld}",
        f"{name}.secure-login{tld}",
        f"{name}.account-verify{tld}",
    ]


def generate_tld_swap(name: str) -> List[str]:
    """Swap TLD to suspicious alternatives."""
    return [name + tld for tld in SUSPICIOUS_TLDS]


def check_domain_resolves(domain: str) -> bool:
    """Check if domain resolves via DNS — means it's registered."""
    try:
        socket.setdefaulttimeout(3)
        socket.gethostbyname(domain)
        return True
    except (socket.gaierror, socket.timeout):
        return False


# ── MAIN SIMULATION CLASS ─────────────────────────────────────────────────────

class AttackerSimulator:

    def __init__(self, scan: bool = True):
        self.scan = scan
        if scan:
            try:
                from phishing_scanner import PhishingScanner
                self.scanner = PhishingScanner()
            except Exception as e:
                warn(f"Scanner not available: {e}")
                warn("Running in DNS-only mode.")
                self.scan  = False
                self.scanner = None

    def simulate(self, target: str, max_scan: int = 10) -> Dict:
        """Generate all phishing variants and scan them."""
        divider()
        print(f"{Fore.RED}  ⚠  ATTACKER SIMULATION MODE{Style.RESET_ALL}")
        print(f"  For defensive research and brand protection only.")
        divider()

        name, tld = extract_domain(target)
        ok(f"Target domain: {name}{tld}")
        info(f"Generating phishing variants...")

        # Generate all variants
        homoglyph_variants = generate_homoglyphs(name)
        typo_variants      = generate_typos(name)
        combo_variants     = generate_combo_squats(name)
        subdomain_variants = generate_subdomain_abuse(name, tld)
        tld_variants       = generate_tld_swap(name)

        # Build full URLs
        all_variants = []

        for v in homoglyph_variants:
            all_variants.append({
                "domain"  : f"{v}{tld}",
                "url"     : f"http://{v}{tld}/login",
                "type"    : "Homoglyph/Typosquatting",
                "original": f"{name}{tld}",
            })

        for v in typo_variants:
            all_variants.append({
                "domain"  : f"{v}{tld}",
                "url"     : f"http://{v}{tld}",
                "type"    : "Typo Variant",
                "original": f"{name}{tld}",
            })

        for v in combo_variants:
            all_variants.append({
                "domain"  : f"{v}{tld}",
                "url"     : f"http://{v}{tld}/verify-account",
                "type"    : "Combo Squatting",
                "original": f"{name}{tld}",
            })

        for v in subdomain_variants:
            all_variants.append({
                "domain"  : v,
                "url"     : f"http://{v}/login",
                "type"    : "Subdomain Abuse",
                "original": f"{name}{tld}",
            })

        for v in tld_variants:
            all_variants.append({
                "domain"  : v,
                "url"     : f"http://{v}/signin",
                "type"    : "TLD Swap",
                "original": f"{name}{tld}",
            })

        ok(f"Generated {len(all_variants)} phishing variant(s)")

        # DNS check — which ones are actually registered
        info("Checking which domains are already registered (DNS)...")
        registered = []
        for v in all_variants:
            resolves = check_domain_resolves(v["domain"])
            v["dns_registered"] = resolves
            if resolves:
                registered.append(v)
                print(f"  {Fore.RED}[LIVE]{Style.RESET_ALL} {v['domain']} ({v['type']})")

        ok(f"Found {len(registered)} LIVE registered variant(s) out of {len(all_variants)}")

        # Scan top variants through full scanner
        scan_results = []
        if self.scan and registered:
            to_scan = registered[:max_scan]
            print(f"\n{Fore.YELLOW}Scanning {len(to_scan)} live variant(s) through full scanner...{Style.RESET_ALL}\n")
            for v in to_scan:
                info(f"Scanning: {v['url']}")
                result = self.scanner.scan(v["url"])
                v["scan_result"] = result.get("verdict", {})
                v["risk_score"]  = result.get("verdict", {}).get("risk", 0)
                v["status"]      = result.get("verdict", {}).get("status", "UNKNOWN")
                scan_results.append(v)
        elif self.scan and not registered:
            warn("No live variants found — skipping scanner.")

        return {
            "timestamp"      : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "target"         : f"{name}{tld}",
            "total_generated": len(all_variants),
            "total_live"     : len(registered),
            "all_variants"   : all_variants,
            "live_variants"  : registered,
            "scanned"        : scan_results,
        }

    def print_report(self, result: Dict):
        divider()
        print(f"{Fore.RED}  ATTACKER SIMULATION REPORT{Style.RESET_ALL}")
        divider()
        print(f"\n  Target      : {result['target']}")
        print(f"  Generated   : {result['total_generated']} variants")
        print(f"  Live (DNS)  : {result['total_live']} registered domains found")
        print(f"  Scanned     : {len(result['scanned'])} through full scanner\n")

        if result["live_variants"]:
            print(f"{Fore.RED}  LIVE PHISHING VARIANTS (Already Registered):{Style.RESET_ALL}")
            for v in result["live_variants"]:
                status = v.get("status", "DNS LIVE")
                risk   = v.get("risk_score", "?")
                color  = Fore.RED if status == "MALICIOUS" else (Fore.YELLOW if status == "SUSPICIOUS" else Fore.GREEN)
                print(f"  {color}[{status}]{Style.RESET_ALL}  Risk: {risk}/100  {v['domain']}  ({v['type']})")
        else:
            ok("No live phishing variants found. Target brand appears clean.")

        print(f"\n{Fore.YELLOW}  VARIANT BREAKDOWN:{Style.RESET_ALL}")
        from collections import Counter
        type_counts = Counter(v["type"] for v in result["all_variants"])
        for t, c in type_counts.items():
            print(f"  {c:3d}  {t}")

        divider()

    def save_report(self, result: Dict) -> str:
        ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"simulation_{result['target'].replace('.','_')}_{ts}.json"
        with open(filename, "w") as f:
            json.dump(result, f, indent=2, default=str)
        ok(f"Report saved: {filename}")
        return filename


# ── MAIN ──────────────────────────────────────────────────────────────────────
def main():
    print(f"\n{Fore.RED}{'='*70}{Style.RESET_ALL}")
    print(f"{Fore.RED}  ⚠  ATTACKER SIMULATION MODE{Style.RESET_ALL}")
    print(f"  For defensive research and brand protection only.")
    print(f"  Do NOT use this for malicious purposes.")
    print(f"{Fore.RED}{'='*70}{Style.RESET_ALL}\n")

    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = input("  Enter target domain (e.g. paypal.com) > ").strip()

    if not target:
        err("No domain provided.")
        return

    sim    = AttackerSimulator(scan=True)
    result = sim.simulate(target)
    sim.print_report(result)

    if input("\n  Save report to JSON? (y/n) > ").strip().lower() == "y":
        sim.save_report(result)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted.")
    except Exception as e:
        import traceback
        traceback.print_exc()
