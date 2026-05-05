import streamlit as st
import json
import os
import sys
sys.path.insert(0, os.path.dirname(__file__))
from phishing_scanner import PhishingScanner

st.set_page_config(
    page_title="AI Phishing Scanner",
    page_icon="🛡️",
    layout="wide"
)

st.markdown("""
<style>
.main-title { font-size: 2.2rem; font-weight: 800; color: #1e3a8a; }
.sub-title  { color: #64748b; font-size: 1rem; margin-top: -10px; }
.safe-box       { background: #dcfce7; border-left: 5px solid #16a34a; padding: 16px; border-radius: 8px; }
.suspicious-box { background: #fef9c3; border-left: 5px solid #ca8a04; padding: 16px; border-radius: 8px; }
.malicious-box  { background: #fee2e2; border-left: 5px solid #dc2626; padding: 16px; border-radius: 8px; }
.metric-card    { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 12px; text-align: center; }
</style>
""", unsafe_allow_html=True)

st.markdown('<p class="main-title">🛡️ AI Phishing Link Scanner v3.0</p>', unsafe_allow_html=True)
st.markdown('<p class="sub-title">Static Analysis · VirusTotal · AbuseIPDB · AI Semantic Analysis (Gemini / GPT-4o)</p>', unsafe_allow_html=True)
st.markdown("---")

@st.cache_resource
def get_scanner():
    return PhishingScanner()

scanner = get_scanner()

tab1, tab2, tab3 = st.tabs(["🔍 Single URL Scan", "📋 Bulk CSV Scan", "📜 Scan History"])

# ── TAB 1: SINGLE SCAN ────────────────────────────────────────────────────────
with tab1:
    url_input = st.text_input("Enter URL to scan", placeholder="https://example.com")
    scan_btn  = st.button("Scan URL", type="primary", use_container_width=True)

    if scan_btn and url_input:
        with st.spinner("Scanning..."):
            report = scanner.scan(url_input.strip())

        if "error" in report:
            st.error(f"Scan failed: {report['error']}")
        else:
            verdict = report["verdict"]
            risk    = verdict["risk"]

            if verdict["status"] == "SAFE":
                box_class = "safe-box"
                icon = "✅"
            elif verdict["status"] == "SUSPICIOUS":
                box_class = "suspicious-box"
                icon = "⚠️"
            else:
                box_class = "malicious-box"
                icon = "🚨"

            st.markdown(f"""
            <div class="{box_class}">
                <h2>{icon} {verdict["label"]}</h2>
                <p><strong>Overall Risk Score:</strong> {risk}/100</p>
                <p><strong>Action:</strong> {verdict["action"]}</p>
            </div>
            """, unsafe_allow_html=True)

            st.markdown("---")

            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Static Risk", f"{report['static']['risk_score']}/100")
            with col2:
                vt = report["virustotal"]
                vt_val = f"{vt.get('malicious',0)} malicious" if vt.get("available") else "N/A"
                st.metric("VirusTotal", vt_val)
            with col3:
                ab = report["abuseipdb"]
                ab_val = f"{ab.get('abuse_score',0)}%" if ab.get("available") else "Skipped"
                st.metric("AbuseIPDB", ab_val)
            with col4:
                llm = report["llm"]
                llm_val = f"{llm.get('confidence',0)}%" if llm.get("available") else "N/A"
                st.metric("AI Confidence", llm_val)

            st.markdown("---")

            with st.expander("🔍 Static Analysis Details"):
                s = report["static"]
                st.write(f"**Risk Score:** {s['risk_score']}/100")
                st.write(f"**IP in URL:** {'Yes ❌' if s['has_ip_address'] else 'No ✓'}")
                st.write(f"**HTTP (no HTTPS):** {'Yes ⚠️' if s['uses_http'] else 'No ✓'}")
                st.write(f"**Suspicious TLD:** {'Yes ⚠️' if s['has_suspicious_tld'] else 'No ✓'}")
                st.write(f"**Hex Encoding:** {'Yes ⚠️' if s['has_hex_encoding'] else 'No ✓'}")
                if s["suspicious_keywords"]:
                    st.write(f"**Suspicious Keywords:** {', '.join(s['suspicious_keywords'])}")
                if s["typosquatting"]:
                    st.write(f"**Typosquatting Detected:** {', '.join(s['typosquatting'])}")

            with st.expander("🌐 VirusTotal Results"):
                if vt.get("available"):
                    st.write(f"**Malicious:** {vt['malicious']}/{vt['total']}")
                    st.write(f"**Suspicious:** {vt['suspicious']}/{vt['total']}")
                    st.write(f"**Harmless:** {vt['harmless']}/{vt['total']}")
                    st.write(f"**Status:** {vt['status']}")
                else:
                    st.warning(vt.get("error", "Not available"))

            with st.expander("🛑 AbuseIPDB Results"):
                if ab.get("available"):
                    st.write(f"**IP:** {ab['ip']}")
                    st.write(f"**Abuse Score:** {ab['abuse_score']}%")
                    st.write(f"**Total Reports:** {ab['total_reports']}")
                    st.write(f"**Country / ISP:** {ab['country']} / {ab['isp']}")
                    st.write(f"**Tor Node:** {'Yes ❌' if ab['is_tor'] else 'No ✓'}")
                else:
                    st.info(ab.get("error", "Not available"))

            with st.expander("🤖 AI Semantic Analysis"):
                if llm.get("available"):
                    st.write(f"**Verdict:** {'PHISHING 🚨' if llm['is_phishing'] else 'LEGITIMATE ✅'}")
                    st.write(f"**Confidence:** {llm['confidence']}%")
                    st.write(f"**Red Flags:** {llm['red_flags']}")
                    st.write(f"**MITRE Technique:** {llm['mitre_technique']}")
                    st.write(f"**Reasoning:** {llm['reasoning']}")
                else:
                    st.warning(llm.get("error", "Not available"))

            st.download_button(
                label="💾 Download JSON Report",
                data=json.dumps(report, indent=2, default=str),
                file_name=f"scan_report_{report['timestamp'].replace(' ','_').replace(':','')}.json",
                mime="application/json"
            )

# ── TAB 2: BULK CSV SCAN ─────────────────────────────────────────────────────
with tab2:
    st.markdown("### Upload a CSV file with URLs")
    st.markdown("CSV must have a column named `url`.")

    sample_csv = "url\nhttps://www.google.com\nhttps://www.github.com\nhttp://amaz0n-verify.tk/login"
    st.download_button("Download sample CSV", sample_csv, "sample_urls.csv", "text/csv")

    uploaded = st.file_uploader("Upload CSV", type=["csv"])

    if uploaded:
        import pandas as pd
        import io
        df = pd.read_csv(io.StringIO(uploaded.read().decode("utf-8")))
        if "url" not in df.columns:
            st.error("CSV must have a column named 'url'")
        else:
            st.write(f"Found **{len(df)}** URLs")
            if st.button("Start Bulk Scan", type="primary"):
                results = []
                progress = st.progress(0)
                status_text = st.empty()
                for i, url in enumerate(df["url"].dropna().tolist()):
                    status_text.text(f"Scanning {i+1}/{len(df)}: {url}")
                    r = scanner.scan(url.strip())
                    results.append({
                        "url"    : url,
                        "risk"   : r.get("verdict", {}).get("risk", "Error"),
                        "status" : r.get("verdict", {}).get("status", "Error"),
                        "action" : r.get("verdict", {}).get("action", "Scan failed"),
                        "vt_malicious": r.get("virustotal", {}).get("malicious", "N/A"),
                        "ai_verdict"  : "PHISHING" if r.get("llm", {}).get("is_phishing") else "LEGITIMATE",
                        "mitre"       : r.get("llm", {}).get("mitre_technique", "N/A"),
                    })
                    progress.progress((i+1) / len(df))
                status_text.text("Scan complete!")

                result_df = pd.DataFrame(results)
                st.dataframe(result_df, use_container_width=True)

                csv_out = result_df.to_csv(index=False)
                st.download_button("💾 Download CSV Report", csv_out, "bulk_scan_report.csv", "text/csv")
                st.download_button("💾 Download JSON Report", json.dumps(results, indent=2), "bulk_scan_report.json", "application/json")

# ── TAB 3: SCAN HISTORY ───────────────────────────────────────────────────────
with tab3:
    st.markdown("### Scan History")
    if os.path.exists("scan_history.json"):
        with open("scan_history.json") as f:
            history = json.load(f)
        import pandas as pd
        df_h = pd.DataFrame(history)
        st.dataframe(df_h, use_container_width=True)
        st.download_button("💾 Export History", df_h.to_csv(index=False), "scan_history.csv", "text/csv")
    else:
        st.info("No scan history yet. Run a scan first.")

st.markdown("---")
st.markdown("Made with 🔍 by **Praharsh Kumar** · [LinkedIn](https://linkedin.com/in/praharshkumar23) · [GitHub](https://github.com/praharshkumar23)")
