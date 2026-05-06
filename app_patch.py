
# ── ADD THIS TO app.py — after scan result is displayed ──────────────────────
# Place inside the "Single URL Scan" tab, after verdict is shown

from soc_playbook import SOCPlaybookGenerator, generate_from_scan

# After your existing scan display code, add:
if result and result.get("verdict"):
    st.markdown("---")
    st.markdown("### 📋 SOC Incident Report")

    col1, col2, col3 = st.columns(3)

    with col1:
        if st.button("🗒️ Generate SOC Report (PDF)", use_container_width=True):
            with st.spinner("Generating SOC incident report..."):
                gen     = SOCPlaybookGenerator()
                report  = gen.generate(result)
                pdf_path = f"/tmp/SOC_{report['incident_id']}.pdf"
                gen.export_pdf(report, pdf_path)
                gen.export_json(report, f"/tmp/SOC_{report['incident_id']}.json")

                with open(pdf_path, "rb") as f:
                    st.download_button(
                        label="⬇️ Download PDF Report",
                        data=f.read(),
                        file_name=f"SOC_Report_{report['incident_id']}.pdf",
                        mime="application/pdf",
                        use_container_width=True
                    )
                st.success(f"Report generated: {report['incident_id']}")

                # Show checklist in UI
                st.markdown("**Response Playbook Checklist:**")
                for i, item in enumerate(report["action_checklist"], 1):
                    st.checkbox(f"{i}. {item['action']}", key=f"check_{i}")

    with col2:
        if st.button("🎯 Run Attacker Simulation", use_container_width=True):
            with st.spinner("Generating phishing variants..."):
                from attacker_simulation import AttackerSimulator, extract_domain
                domain = result.get("url", "")
                sim    = AttackerSimulator(scan=False)  # DNS-only in web UI
                sim_result = sim.simulate(domain)
                st.markdown(f"**Generated:** {sim_result['total_generated']} variants")
                st.markdown(f"**Live (DNS):** {sim_result['total_live']} registered domains found")
                if sim_result["live_variants"]:
                    st.error("⚠️ Live phishing variants found!")
                    for v in sim_result["live_variants"][:5]:
                        st.code(f"{v['domain']}  ({v['type']})")
                else:
                    st.success("✅ No live phishing variants found")

    with col3:
        st.info("**MITRE ATT&CK:**\n" + result.get("llm", {}).get("mitre_technique", "Not identified"))
