#!/usr/bin/env python3
"""
SOC Playbook & Incident Report Generator — AI Phishing Scanner v3.0
Built by Praharsh Kumar

After every phishing scan, auto-generates:
- Formatted SOC incident report (PDF + JSON)
- MITRE ATT&CK mapped response playbook
- Analyst action checklist
- IOC (Indicator of Compromise) summary
- Escalation recommendation

This is exactly what L1 SOC analysts do every day.
"""

import os
import sys
import json
import re
from datetime import datetime
from typing import Dict, List

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, KeepTogether
    )
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False
    print("[!] reportlab not installed. PDF export disabled.")
    print("    Run: pip install reportlab")


# ── INCIDENT ID COUNTER ───────────────────────────────────────────────────────
COUNTER_FILE = "incident_counter.json"

def get_next_incident_id() -> str:
    counter = 1
    if os.path.exists(COUNTER_FILE):
        try:
            with open(COUNTER_FILE) as f:
                data = json.load(f)
                counter = data.get("counter", 1)
        except Exception:
            counter = 1
    with open(COUNTER_FILE, "w") as f:
        json.dump({"counter": counter + 1}, f)
    year = datetime.now().year
    return f"INC-{year}-{counter:04d}"


# ── PLAYBOOK MAPPINGS ─────────────────────────────────────────────────────────
MITRE_PLAYBOOKS = {
    "T1566"    : {
        "name"   : "Phishing",
        "tactics": "Initial Access",
        "steps"  : [
            "Block the identified URL/domain at the web proxy and DNS filter.",
            "Search mail gateway logs for the URL sent to other users.",
            "Identify all recipients who received the phishing link.",
            "Check endpoint logs for any users who clicked the link.",
            "Reset credentials for any accounts that may have been compromised.",
            "Preserve all email headers and URL evidence for forensics.",
            "Notify affected users and advise them not to enter credentials.",
            "Submit URL to VirusTotal, URLhaus, and PhishTank for community reporting.",
            "Escalate to Tier 2 if credential compromise is confirmed.",
        ]
    },
    "T1566.001": {
        "name"   : "Spearphishing Attachment",
        "tactics": "Initial Access",
        "steps"  : [
            "Quarantine the email attachment immediately.",
            "Submit attachment hash to VirusTotal for analysis.",
            "Check if attachment was opened by any user.",
            "Isolate endpoint if attachment was executed.",
            "Run full AV scan on affected systems.",
            "Check for persistence mechanisms (scheduled tasks, registry keys).",
            "Collect and preserve memory dump if malware executed.",
            "Escalate to Tier 2 for malware analysis.",
        ]
    },
    "T1566.002": {
        "name"   : "Spearphishing Link",
        "tactics": "Initial Access",
        "steps"  : [
            "Block the malicious URL at web proxy and DNS filter.",
            "Search SIEM for any users who visited the URL.",
            "Check for credential harvesting page indicators.",
            "Review authentication logs for suspicious logins after link access.",
            "Force password reset for any user who accessed the URL.",
            "Check for OAuth token theft or session hijacking.",
            "Add URL to blocklist across all security controls.",
            "Notify users who received the link via email.",
            "Document timeline: when URL was created, sent, clicked.",
        ]
    },
    "T1078"    : {
        "name"   : "Valid Accounts",
        "tactics": "Defense Evasion, Persistence, Privilege Escalation, Initial Access",
        "steps"  : [
            "Identify all accounts that may have been compromised.",
            "Disable affected accounts immediately pending investigation.",
            "Review login logs for the accounts — source IPs, times, locations.",
            "Check for lateral movement from compromised accounts.",
            "Review privilege escalation attempts.",
            "Enable MFA on all affected accounts.",
            "Audit all actions taken by the compromised account.",
            "Notify account owners and management.",
            "Escalate to Tier 2 if insider threat is suspected.",
        ]
    },
    "default"  : {
        "name"   : "Phishing / Malicious URL",
        "tactics": "Initial Access",
        "steps"  : [
            "Block the identified URL at web proxy and DNS filter.",
            "Search logs for any internal users who accessed the URL.",
            "Check endpoint security logs for related activity.",
            "Review email logs for distribution of this URL.",
            "Document all findings in the incident ticket.",
            "Escalate to Tier 2 if active compromise is detected.",
        ]
    }
}

SEVERITY_MAP = {
    "MALICIOUS" : ("HIGH",    colors.HexColor("#dc2626")),
    "SUSPICIOUS": ("MEDIUM",  colors.HexColor("#d97706")),
    "SAFE"      : ("LOW",     colors.HexColor("#16a34a")),
}

ESCALATION_MAP = {
    "MALICIOUS" : "Escalate to Tier 2 immediately. High-confidence malicious URL.",
    "SUSPICIOUS": "Monitor and investigate. Escalate if additional IOCs found.",
    "SAFE"      : "No escalation required. Document and close.",
}


# ── PDF GENERATOR ─────────────────────────────────────────────────────────────
class SOCPlaybookGenerator:

    def __init__(self):
        self.styles = getSampleStyleSheet() if REPORTLAB_AVAILABLE else None
        self._setup_styles()

    def _setup_styles(self):
        if not REPORTLAB_AVAILABLE:
            return
        self.style_title = ParagraphStyle(
            "title", fontSize=18, fontName="Helvetica-Bold",
            textColor=colors.HexColor("#1e3a8a"), spaceAfter=6, alignment=TA_LEFT
        )
        self.style_h1 = ParagraphStyle(
            "h1", fontSize=13, fontName="Helvetica-Bold",
            textColor=colors.HexColor("#1e40af"), spaceBefore=14, spaceAfter=6
        )
        self.style_h2 = ParagraphStyle(
            "h2", fontSize=11, fontName="Helvetica-Bold",
            textColor=colors.HexColor("#374151"), spaceBefore=10, spaceAfter=4
        )
        self.style_body = ParagraphStyle(
            "body", fontSize=9, fontName="Helvetica",
            textColor=colors.HexColor("#1f2937"), spaceAfter=4, leading=14
        )
        self.style_mono = ParagraphStyle(
            "mono", fontSize=8, fontName="Courier",
            textColor=colors.HexColor("#374151"),
            backColor=colors.HexColor("#f3f4f6"),
            spaceAfter=4, leading=12, leftIndent=8, rightIndent=8
        )
        self.style_small = ParagraphStyle(
            "small", fontSize=8, fontName="Helvetica",
            textColor=colors.HexColor("#6b7280"), spaceAfter=2
        )
        self.style_red = ParagraphStyle(
            "red", fontSize=10, fontName="Helvetica-Bold",
            textColor=colors.HexColor("#dc2626"), spaceAfter=4
        )
        self.style_step = ParagraphStyle(
            "step", fontSize=9, fontName="Helvetica",
            textColor=colors.HexColor("#1f2937"), spaceAfter=3,
            leftIndent=12, leading=14
        )

    def _get_playbook(self, mitre_technique: str) -> Dict:
        if not mitre_technique:
            return MITRE_PLAYBOOKS["default"]
        for key in MITRE_PLAYBOOKS:
            if key.lower() in mitre_technique.lower():
                return MITRE_PLAYBOOKS[key]
        return MITRE_PLAYBOOKS["default"]

    def generate(self, scan_result: Dict, analyst_name: str = "Praharsh Kumar") -> Dict:
        """Generate full SOC incident report from scan result."""
        incident_id = get_next_incident_id()
        timestamp   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        verdict     = scan_result.get("verdict", {})
        status      = verdict.get("status", "UNKNOWN")
        risk        = verdict.get("risk", 0)
        url         = scan_result.get("url", "Unknown")
        llm         = scan_result.get("llm", {})
        vt          = scan_result.get("virustotal", {})
        static      = scan_result.get("static", {})
        whois       = scan_result.get("whois", {})

        severity, _   = SEVERITY_MAP.get(status, ("UNKNOWN", colors.grey))
        escalation    = ESCALATION_MAP.get(status, "Review required.")
        mitre         = llm.get("mitre_technique", "Not identified")
        playbook      = self._get_playbook(mitre)

        # Build IOCs
        iocs = [{"type": "URL", "value": url, "confidence": f"{risk}/100"}]
        parsed_domain = re.sub(r'^https?://', '', url).split('/')[0]
        if parsed_domain:
            iocs.append({"type": "Domain", "value": parsed_domain, "confidence": f"{risk}/100"})
        if vt.get("available") and vt.get("malicious", 0) > 0:
            iocs.append({"type": "VT Detection", "value": f"{vt['malicious']}/{vt['total']} engines", "confidence": "High"})

        report = {
            "incident_id"   : incident_id,
            "timestamp"     : timestamp,
            "analyst"       : analyst_name,
            "url"           : url,
            "domain"        : parsed_domain,
            "severity"      : severity,
            "status"        : status,
            "risk_score"    : risk,
            "mitre"         : mitre,
            "playbook"      : playbook,
            "escalation"    : escalation,
            "iocs"          : iocs,
            "scan_result"   : scan_result,
            "action_checklist": [
                {"action": step, "done": False}
                for step in playbook["steps"]
            ]
        }

        return report

    def export_pdf(self, report: Dict, filename: str = None) -> str:
        if not REPORTLAB_AVAILABLE:
            print("[!] reportlab not installed — PDF not generated.")
            return ""

        if not filename:
            ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"SOC_Report_{report['incident_id']}_{ts}.pdf"

        doc   = SimpleDocTemplate(filename, pagesize=A4,
                                  rightMargin=2*cm, leftMargin=2*cm,
                                  topMargin=2*cm, bottomMargin=2*cm)
        story = []

        severity_color = SEVERITY_MAP.get(report["status"], ("UNKNOWN", colors.grey))[1]

        # ── HEADER ────────────────────────────────────────────────────────────
        story.append(Paragraph("🛡️  SOC INCIDENT REPORT", self.style_title))
        story.append(Paragraph("AI Phishing Link Scanner v3.0  |  Built by Praharsh Kumar", self.style_small))
        story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#1e3a8a")))
        story.append(Spacer(1, 8))

        # ── INCIDENT SUMMARY TABLE ────────────────────────────────────────────
        summary_data = [
            ["Incident ID",  report["incident_id"],  "Date/Time",   report["timestamp"]],
            ["Analyst",      report["analyst"],       "Severity",    report["severity"]],
            ["Risk Score",   f"{report['risk_score']}/100",  "Verdict", report["status"]],
            ["MITRE",        report["mitre"][:50] if report["mitre"] else "N/A", "Escalation", "YES" if report["severity"] == "HIGH" else "NO"],
        ]
        summary_table = Table(summary_data, colWidths=[3.5*cm, 6*cm, 3.5*cm, 4.5*cm])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor("#e0e7ff")),
            ('BACKGROUND', (2, 0), (2, -1), colors.HexColor("#e0e7ff")),
            ('BACKGROUND', (1, 2), (1, 2), colors.HexColor("#fef9c3")),
            ('BACKGROUND', (3, 1), (3, 1), severity_color),
            ('TEXTCOLOR',  (3, 1), (3, 1), colors.white),
            ('FONTNAME',   (0, 0), (-1, -1), 'Helvetica'),
            ('FONTNAME',   (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME',   (2, 0), (2, -1), 'Helvetica-Bold'),
            ('FONTSIZE',   (0, 0), (-1, -1), 8),
            ('GRID',       (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")),
            ('PADDING',    (0, 0), (-1, -1), 6),
            ('VALIGN',     (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 10))

        # ── URL ───────────────────────────────────────────────────────────────
        story.append(Paragraph("URL Under Investigation", self.style_h1))
        story.append(Paragraph(report["url"], self.style_mono))
        story.append(Spacer(1, 6))

        # ── VERDICT BOX ───────────────────────────────────────────────────────
        story.append(Paragraph("Final Verdict", self.style_h1))
        verdict_style = ParagraphStyle(
            "verdict", fontSize=12, fontName="Helvetica-Bold",
            textColor=severity_color, spaceAfter=4
        )
        story.append(Paragraph(
            f"{report['status']} — Risk Score: {report['risk_score']}/100",
            verdict_style
        ))
        story.append(Paragraph(f"Escalation: {report['escalation']}", self.style_body))
        story.append(Spacer(1, 8))

        # ── DETECTION DETAILS ─────────────────────────────────────────────────
        story.append(Paragraph("Detection Details", self.style_h1))
        scan = report["scan_result"]
        s    = scan.get("static", {})
        llm  = scan.get("llm", {})
        vt   = scan.get("virustotal", {})
        whois= scan.get("whois", {})

        det_data = [
            ["Detection Layer", "Result", "Score"],
            ["Static Analysis",
             f"Keywords: {', '.join(s.get('suspicious_keywords', [])[:3]) or 'None'} | Typosquat: {', '.join(s.get('typosquatting', [])) or 'None'}",
             f"{s.get('risk_score', 0)}/100"],
            ["WHOIS Domain Age",
             f"{whois.get('age_days', '?')} days — {whois.get('risk_flag', 'N/A')}" if whois.get('available') else "N/A",
             whois.get('risk_flag', 'N/A').split('—')[0].strip() if whois.get('available') else "N/A"],
            ["VirusTotal",
             f"{vt.get('malicious', 0)} malicious / {vt.get('suspicious', 0)} suspicious out of {vt.get('total', 0)} engines" if vt.get('available') else "N/A",
             f"{vt.get('malicious', 0)}/{vt.get('total', 0)}"],
            ["AI Semantic (Gemini)",
             f"{'PHISHING' if llm.get('is_phishing') else 'LEGITIMATE'} — {llm.get('red_flags', 'None')[:60]}" if llm.get('available') else "N/A",
             f"{llm.get('confidence', 0)}%"],
        ]
        det_table = Table(det_data, colWidths=[4*cm, 10*cm, 3.5*cm])
        det_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1e3a8a")),
            ('TEXTCOLOR',  (0, 0), (-1, 0), colors.white),
            ('FONTNAME',   (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTNAME',   (0, 1), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE',   (0, 0), (-1, -1), 8),
            ('GRID',       (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")),
            ('PADDING',    (0, 0), (-1, -1), 6),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor("#f9fafb")]),
            ('VALIGN',     (0, 0), (-1, -1), 'TOP'),
        ]))
        story.append(det_table)
        story.append(Spacer(1, 10))

        # ── IOCs ──────────────────────────────────────────────────────────────
        story.append(Paragraph("Indicators of Compromise (IOCs)", self.style_h1))
        ioc_data = [["Type", "Value", "Confidence"]]
        for ioc in report["iocs"]:
            ioc_data.append([ioc["type"], ioc["value"], ioc["confidence"]])
        ioc_table = Table(ioc_data, colWidths=[3.5*cm, 10*cm, 4*cm])
        ioc_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#7f1d1d")),
            ('TEXTCOLOR',  (0, 0), (-1, 0), colors.white),
            ('FONTNAME',   (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE',   (0, 0), (-1, -1), 8),
            ('GRID',       (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")),
            ('PADDING',    (0, 0), (-1, -1), 6),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor("#fff1f2"), colors.white]),
        ]))
        story.append(ioc_table)
        story.append(Spacer(1, 10))

        # ── MITRE ATT&CK ──────────────────────────────────────────────────────
        story.append(Paragraph("MITRE ATT&CK Mapping", self.style_h1))
        playbook = report["playbook"]
        story.append(Paragraph(
            f"<b>Technique:</b> {report['mitre']}",
            self.style_body
        ))
        story.append(Paragraph(
            f"<b>Tactic:</b> {playbook['tactics']}",
            self.style_body
        ))
        story.append(Spacer(1, 6))

        # ── RESPONSE PLAYBOOK ─────────────────────────────────────────────────
        story.append(Paragraph("Response Playbook — Analyst Action Checklist", self.style_h1))
        story.append(Paragraph(
            "Complete these steps in order. Check off each action as completed.",
            self.style_small
        ))
        story.append(Spacer(1, 6))

        checklist_data = [["#", "Action", "Status"]]
        for i, item in enumerate(report["action_checklist"], 1):
            checklist_data.append([
                str(i),
                item["action"],
                "☐ Pending"
            ])

        cl_table = Table(checklist_data, colWidths=[0.8*cm, 13.7*cm, 2.5*cm])
        cl_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1e3a8a")),
            ('TEXTCOLOR',  (0, 0), (-1, 0), colors.white),
            ('FONTNAME',   (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTNAME',   (0, 1), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE',   (0, 0), (-1, -1), 8),
            ('GRID',       (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")),
            ('PADDING',    (0, 0), (-1, -1), 6),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor("#f0f9ff")]),
            ('VALIGN',     (0, 0), (-1, -1), 'TOP'),
        ]))
        story.append(cl_table)
        story.append(Spacer(1, 10))

        # ── AI REASONING ──────────────────────────────────────────────────────
        if llm.get("available") and llm.get("reasoning"):
            story.append(Paragraph("AI Analyst Reasoning", self.style_h1))
            story.append(Paragraph(llm["reasoning"], self.style_body))
            story.append(Spacer(1, 6))

        # ── FOOTER ────────────────────────────────────────────────────────────
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#d1d5db")))
        story.append(Spacer(1, 4))
        story.append(Paragraph(
            f"Report generated by AI Phishing Scanner v3.0  |  Analyst: {report['analyst']}  |  {report['timestamp']}",
            self.style_small
        ))
        story.append(Paragraph(
            "GitHub: github.com/praharshkumar23/AI-Phishing-Scanner-v3  |  linkedin.com/in/praharshkumar23",
            self.style_small
        ))

        doc.build(story)
        print(f"  [+] PDF report saved: {filename}")
        return filename

    def export_json(self, report: Dict, filename: str = None) -> str:
        if not filename:
            ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"SOC_Report_{report['incident_id']}_{ts}.json"
        with open(filename, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"  [+] JSON report saved: {filename}")
        return filename

    def print_checklist(self, report: Dict):
        print(f"\n{'='*70}")
        print(f"  SOC INCIDENT REPORT — {report['incident_id']}")
        print(f"{'='*70}")
        print(f"  Analyst   : {report['analyst']}")
        print(f"  Timestamp : {report['timestamp']}")
        print(f"  URL       : {report['url']}")
        print(f"  Severity  : {report['severity']}")
        print(f"  Risk      : {report['risk_score']}/100")
        print(f"  MITRE     : {report['mitre']}")
        print(f"  Escalate  : {report['escalation']}")
        print(f"\n  RESPONSE CHECKLIST ({report['playbook']['name']})")
        print(f"  {'-'*60}")
        for i, item in enumerate(report["action_checklist"], 1):
            print(f"  ☐  {i:2d}. {item['action']}")
        print(f"{'='*70}\n")


# ── STANDALONE USAGE ──────────────────────────────────────────────────────────
def generate_from_scan(scan_result: Dict, analyst: str = "Praharsh Kumar") -> str:
    """
    Call this after any scan to auto-generate the SOC report.
    Returns path to saved PDF.

    Usage:
        from soc_playbook import generate_from_scan
        pdf_path = generate_from_scan(scan_result)
    """
    gen    = SOCPlaybookGenerator()
    report = gen.generate(scan_result, analyst)
    gen.print_checklist(report)
    pdf    = gen.export_pdf(report)
    gen.export_json(report)
    return pdf


def main():
    print("\n  SOC Playbook Generator")
    print("  Generates incident report from a saved scan JSON file.")
    print("  Usage: python soc_playbook.py scan_report.json\n")

    if len(sys.argv) > 1:
        filepath = sys.argv[1]
    else:
        filepath = input("  Enter scan JSON file path > ").strip()

    if not os.path.exists(filepath):
        print(f"  [-] File not found: {filepath}")
        return

    with open(filepath) as f:
        scan_result = json.load(f)

    analyst = input("  Analyst name (press Enter for default) > ").strip()
    if not analyst:
        analyst = "Praharsh Kumar"

    gen    = SOCPlaybookGenerator()
    report = gen.generate(scan_result, analyst)
    gen.print_checklist(report)

    if REPORTLAB_AVAILABLE:
        gen.export_pdf(report)
    gen.export_json(report)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted.")
    except Exception as e:
        import traceback
        traceback.print_exc()
