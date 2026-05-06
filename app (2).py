#!/usr/bin/env python3
"""
AI Phishing Scanner v3.0 — Streamlit Web App
Built by Praharsh Kumar
"""

import os
import sys
import json
import streamlit as st
from datetime import datetime

# ── PAGE CONFIG ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="AI Phishing Scanner v3.0",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ── LOAD ENV ──────────────────────────────────────────────────────────────────
from dotenv import load_dotenv
load_dotenv()

# ── IMPORTS ───────────────────────────────────────────────────────────────────
try:
    from phishing_scanner import PhishingScanner
    SCANNER_OK = True
except Exception as e:
    SCANNER_OK = False
    SCANNER_ERR = str(e)

try:
    from soc_playbook import SOCPlaybookGenerator
    PLAYBOOK_OK = True
except Exception as e:
    PLAYBOOK_OK = False
    PLAYBOOK_ERR = str(e)

try:
    from attacker_simulation import AttackerSimulator
    SIM_OK = True
except Exception as e:
    SIM_OK = False
    SIM_ERR = str(e)

# ── SIDEBAR ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🛡️ AI Phishing Scanner")
    st.markdown("**v3.0** — Built by Praharsh Kumar")
    st.markdown("---")

    st.markdown("### API Status")
    vt_key  = os.getenv("VIRUSTOTAL_API_KEY", "")
    gem_key = os.getenv("GOOGLE_API_KEY", "")
    oai_key = os.getenv("OPENAI_API_KEY", "")

    st.markdown(f"{'✅' if vt_key  else '❌'} VirusTotal API")
    st.markdown(f"{'✅' if gem_key else '❌'} Google Gemini API")
    st.markdown(f"{'✅' if oai_key else '❌'} OpenAI API (optional)")
    st.markdown(f"{'✅' if SCANNER_OK  else '❌'} phishing_scanner.py")
    st.markdown(f"{'✅' if PLAYBOOK_OK else '❌'} soc_playbook.py")
    st.markdown(f"{'✅' if SIM_OK      else '❌'} attacker_simulation.py")

    st.markdown("---")
    st.markdown("### About")
    st.markdown(
        "Combines **static analysis**, **VirusTotal**, and **Gemini AI** "
        "to detect phishing URLs with SOC-grade incident reporting."
    )
    st.markdown("[GitHub](https://github.com/praharshkumar23) | [LinkedIn](https://linkedin.com/in/praharshkumar23)")

# ── HEADER ────────────────────────────────────────────────────────────────────
st.markdown("# 🛡️ AI Phishing Link Scanner v3.0")
st.markdown("*Real-time phishing detection with MITRE ATT&CK mapped SOC incident reports*")
st.markdown("---")

# ── TABS ──────────────────────────────────────────────────────────────────────
tab1, tab2, tab3 = st.tabs(["🔍 Single URL Scan", "📧 Email Scanner", "⚠️ Attacker Simulation"])

# ══════════════════════════════════════════════════════════════════════════════
# TAB 1 — SINGLE URL SCAN
# ══════════════════════════════════════════════════════════════════════════════
with tab1:
    st.markdown("### Scan a URL")
    url_input = st.text_input(
        "Enter URL to scan",
        placeholder="https://example.com/login",
        help="Paste the full URL including https://"
    )

    col_scan, col_clear = st.columns([1, 5])
    with col_scan:
        scan_btn = st.button("🔍 Scan URL", type="primary", use_container_width=True)
    with col_clear:
        clear_btn = st.button("🗑️ Clear", use_container_width=False)

    if clear_btn:
        st.rerun()

    if scan_btn and url_input:
        if not SCANNER_OK:
            st.error(f"Scanner not loaded: {SCANNER_ERR}")
        else:
            with st.spinner("Scanning URL — this takes ~20 seconds for VirusTotal..."):
                try:
                    scanner = PhishingScanner()
                    raw     = scanner.scan(url_input)

                    # Normalize result keys so both old and new scanner versions work
                    result = {
                        "url"        : raw.get("url", url_input),
                        "static"     : raw.get("static_analysis", raw.get("static", {})),
                        "virustotal" : raw.get("virustotal", {}),
                        "llm"        : raw.get("llm_analysis",  raw.get("llm", {})),
                        "whois"      : raw.get("whois", {}),
                    }

                    # Build verdict from final_verdict or recalculate
                    fv = raw.get("verdict") or scanner._calculate_final_verdict(raw)
                    result["verdict"] = {
                        "status": (
                            "MALICIOUS"  if fv.get("is_malicious") and fv.get("risk_level", 0) >= 70 else
                            "SUSPICIOUS" if fv.get("is_malicious") else
                            "SAFE"
                        ),
                        "risk"  : fv.get("risk_level", 0),
                    }

                    st.session_state["last_result"] = result

                except Exception as e:
                    st.error(f"Scan failed: {e}")
                    st.stop()

    # ── DISPLAY RESULTS ───────────────────────────────────────────────────────
    result = st.session_state.get("last_result")
    if result and result.get("verdict"):
        verdict = result["verdict"]
        status  = verdict.get("status", "UNKNOWN")
        risk    = verdict.get("risk",   0)

        # Verdict banner
        if status == "MALICIOUS":
            st.error(f"🚨 **{status}** — Risk Score: {risk}/100")
        elif status == "SUSPICIOUS":
            st.warning(f"⚠️ **{status}** — Risk Score: {risk}/100")
        else:
            st.success(f"✅ **{status}** — Risk Score: {risk}/100")

        # Detection breakdown
        st.markdown("#### Detection Breakdown")
        c1, c2, c3 = st.columns(3)

        static = result.get("static", {})
        vt     = result.get("virustotal", {})
        llm    = result.get("llm", {})

        with c1:
            st.metric("Static Risk Score", f"{static.get('risk_score', 0)}/100")
            if static.get("suspicious_keywords"):
                st.caption(f"Keywords: {', '.join(static['suspicious_keywords'][:3])}")

        with c2:
            if vt.get("available"):
                st.metric("VirusTotal Detections", f"{vt.get('malicious',0)}/{vt.get('total_engines', vt.get('total', 0))}")
            else:
                st.metric("VirusTotal", "N/A")
                st.caption(vt.get("error", "Not available"))

        with c3:
            if llm.get("available"):
                verdict_str = "PHISHING" if llm.get("is_phishing") else "LEGITIMATE"
                st.metric("AI Analysis", f"{verdict_str} ({llm.get('confidence', 0)}%)")
                if llm.get("mitre_technique"):
                    st.caption(f"MITRE: {llm['mitre_technique']}")
            else:
                st.metric("AI Analysis", "N/A")

        # ── SOC REPORT SECTION ────────────────────────────────────────────────
        st.markdown("---")
        st.markdown("### 📋 SOC Incident Report")

        col1, col2, col3 = st.columns(3)

        with col1:
            if st.button("🗒️ Generate SOC Report (PDF)", use_container_width=True):
                if not PLAYBOOK_OK:
                    st.error(f"soc_playbook.py not loaded: {PLAYBOOK_ERR}")
                else:
                    with st.spinner("Generating SOC incident report..."):
                        try:
                            gen      = SOCPlaybookGenerator()
                            report   = gen.generate(result)
                            pdf_path = f"/tmp/SOC_{report['incident_id']}.pdf"
                            gen.export_pdf(report, pdf_path)
                            gen.export_json(report, f"/tmp/SOC_{report['incident_id']}.json")

                            if os.path.exists(pdf_path):
                                with open(pdf_path, "rb") as f:
                                    st.download_button(
                                        label="⬇️ Download PDF Report",
                                        data=f.read(),
                                        file_name=f"SOC_Report_{report['incident_id']}.pdf",
                                        mime="application/pdf",
                                        use_container_width=True
                                    )
                            else:
                                st.warning("PDF not generated (reportlab not installed). JSON report saved.")

                            st.success(f"✅ Report generated: {report['incident_id']}")

                            st.markdown("**Response Playbook Checklist:**")
                            for i, item in enumerate(report["action_checklist"], 1):
                                st.checkbox(f"{i}. {item['action']}", key=f"check_{i}")

                        except Exception as e:
                            st.error(f"Report generation failed: {e}")

        with col2:
            if st.button("🎯 Run Attacker Simulation", use_container_width=True):
                if not SIM_OK:
                    st.error(f"attacker_simulation.py not loaded: {SIM_ERR}")
                else:
                    with st.spinner("Generating phishing variants..."):
                        try:
                            sim        = AttackerSimulator(scan=False)
                            sim_result = sim.simulate(result.get("url", ""))
                            st.markdown(f"**Generated:** {sim_result['total_generated']} variants")
                            st.markdown(f"**Live (DNS):** {sim_result['total_live']} registered domains found")
                            if sim_result.get("live_variants"):
                                st.error("⚠️ Live phishing variants found!")
                                for v in sim_result["live_variants"][:5]:
                                    st.code(f"{v['domain']}  ({v['type']})")
                            else:
                                st.success("✅ No live phishing variants found")
                        except Exception as e:
                            st.error(f"Simulation failed: {e}")

        with col3:
            mitre = result.get("llm", {}).get("mitre_technique", "Not identified")
            st.info(f"**MITRE ATT&CK:**\n{mitre}")

    elif scan_btn and not url_input:
        st.warning("Please enter a URL first.")

# ══════════════════════════════════════════════════════════════════════════════
# TAB 2 — EMAIL SCANNER
# ══════════════════════════════════════════════════════════════════════════════
with tab2:
    st.markdown("### Scan Email for Phishing Links")
    st.markdown("Paste the raw email body or headers below.")

    email_input = st.text_area(
        "Email Content",
        height=250,
        placeholder="Paste email body here..."
    )

    if st.button("📧 Scan Email", type="primary"):
        if not email_input.strip():
            st.warning("Paste some email content first.")
        else:
            try:
                from email_scanner import EmailScanner
                with st.spinner("Extracting and scanning URLs from email..."):
                    es      = EmailScanner()
                    e_result = es.scan(email_input)
                    urls_found = e_result.get("urls_found", [])
                    st.markdown(f"**URLs found:** {len(urls_found)}")
                    for u in urls_found:
                        risk = u.get("risk", 0)
                        col_a, col_b = st.columns([3, 1])
                        with col_a:
                            st.code(u.get("url", ""))
                        with col_b:
                            if risk >= 70:
                                st.error(f"Risk: {risk}/100")
                            elif risk >= 40:
                                st.warning(f"Risk: {risk}/100")
                            else:
                                st.success(f"Risk: {risk}/100")
            except ImportError:
                st.error("email_scanner.py not found in the repo.")
            except Exception as e:
                st.error(f"Email scan failed: {e}")

# ══════════════════════════════════════════════════════════════════════════════
# TAB 3 — ATTACKER SIMULATION
# ══════════════════════════════════════════════════════════════════════════════
with tab3:
    st.markdown("### Attacker Perspective — Phishing Domain Simulation")
    st.markdown(
        "Simulates what an attacker would generate as phishing variants for a target domain. "
        "Checks DNS to see which variants are already registered."
    )

    sim_domain = st.text_input(
        "Target Domain",
        placeholder="google.com",
        help="Enter just the domain, no https://"
    )

    if st.button("🎯 Simulate Attack Variants", type="primary"):
        if not sim_domain.strip():
            st.warning("Enter a domain first.")
        elif not SIM_OK:
            st.error(f"attacker_simulation.py not loaded: {SIM_ERR}")
        else:
            with st.spinner("Generating phishing variants and checking DNS..."):
                try:
                    sim        = AttackerSimulator(scan=False)
                    sim_result = sim.simulate(f"https://{sim_domain}")

                    st.markdown(f"**Target:** `{sim_domain}`")
                    st.markdown(f"**Variants generated:** {sim_result['total_generated']}")
                    st.markdown(f"**Live DNS hits:** {sim_result['total_live']}")

                    if sim_result.get("live_variants"):
                        st.error("⚠️ Live phishing domains detected!")
                        for v in sim_result["live_variants"]:
                            st.code(f"{v['domain']}  —  {v['type']}")
                    else:
                        st.success("✅ No live phishing variants found for this domain.")

                    if sim_result.get("all_variants"):
                        with st.expander(f"View all {sim_result['total_generated']} generated variants"):
                            for v in sim_result["all_variants"][:50]:
                                st.text(f"{v['domain']}  ({v['type']})")

                except Exception as e:
                    st.error(f"Simulation failed: {e}")

# ── FOOTER ────────────────────────────────────────────────────────────────────
st.markdown("---")
st.markdown(
    "<center><small>AI Phishing Scanner v3.0 — Built by "
    "<a href='https://linkedin.com/in/praharshkumar23'>Praharsh Kumar</a> · "
    "<a href='https://github.com/praharshkumar23/ai-phishing-scanner-v3'>GitHub</a></small></center>",
    unsafe_allow_html=True
)
