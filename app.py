"""Threat Analyzer — professional Streamlit frontend.

Pages: Analyze Report | Dashboard | History
Run:  streamlit run app.py
"""

import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
from collections import Counter
from pathlib import Path

from src.analyze import analyze_text, render_markdown
from src.pdf_report import generate_pdf
from src.similarity import find_similar_incidents
from src import database, extractor

st.set_page_config(page_title="Threat Analyzer", page_icon="🛡️",
                   layout="wide", initial_sidebar_state="expanded")

# ------------------------------------------------------------ theme / CSS

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
.stApp { font-family: 'Inter', sans-serif; }
.block-container { padding-top: 1.2rem; max-width: 1200px; }
.kpi-card {
    background: linear-gradient(135deg, #161c30 0%, #1d2440 100%);
    border: 1px solid #2b3557; border-radius: 14px;
    padding: 18px 20px; text-align: center;
    box-shadow: 0 4px 14px rgba(0,0,0,.35);
}
.kpi-label { color: #8b94b3; font-size: .78rem; letter-spacing: .08em;
             text-transform: uppercase; margin-bottom: 6px; }
.kpi-value { color: #f2f5ff; font-size: 1.35rem; font-weight: 700; }
.report-card {
    background: #141a2e; border: 1px solid #2b3557; border-radius: 14px;
    padding: 22px 26px; margin-bottom: 18px;
    box-shadow: 0 4px 14px rgba(0,0,0,.35);
}
.sev { display:inline-block; padding:4px 16px; border-radius:20px;
       font-weight:700; font-size:.95rem; color:#fff; }
.sev-Critical { background: linear-gradient(90deg,#e63946,#ff5964); }
.sev-High     { background: linear-gradient(90deg,#e07b00,#ffa02e); }
.sev-Medium   { background: linear-gradient(90deg,#1d6fd1,#3f9dff); }
.sev-Low      { background: linear-gradient(90deg,#1f9d55,#37c871); }
.cvss { display:inline-block; min-width:52px; text-align:center; padding:2px 10px;
        border-radius:8px; font-weight:700; color:#fff; font-size:.85rem; }
.timeline-dot { color:#00d4ff; font-weight:700; }
.stTabs [data-baseweb="tab-list"] { gap: 6px; }
.stTabs [data-baseweb="tab"] { border-radius: 8px 8px 0 0; }
h1, h2, h3 { letter-spacing: -0.01em; }
</style>
""", unsafe_allow_html=True)

SAMPLES = {
    "Ransomware incident (IR-2026-0417)": "data/samples/sample_ransomware.txt",
    "Phishing campaign (TA-2026-0091)": "data/samples/sample_phishing.txt",
}

IOC_LABELS = {"ipv4": "IP addresses", "domains": "Domains", "urls": "URLs",
              "emails": "Emails", "md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256"}


def cvss_badge(score):
    if score is None:
        return "<span class='cvss' style='background:#555'>n/a</span>"
    color = "#e63946" if score >= 9 else "#ff8c00" if score >= 7 \
        else "#d1a100" if score >= 4 else "#1f9d55"
    return f"<span class='cvss' style='background:{color}'>{score}</span>"


def kpi_row(result: dict):
    n_ioc = sum(len(v) for v in result["iocs"].values())
    cards = [
        ("Threat Type", result["threat_type"]),
        ("Severity", f"<span class='sev sev-{result['severity']}'>"
                     f"{result['severity']}</span>"),
        ("Indicators", str(n_ioc)),
        ("Techniques", str(len(result["techniques"]))),
    ]
    cols = st.columns(4)
    for col, (label, value) in zip(cols, cards):
        with col:
            st.markdown(f"<div class='kpi-card'><div class='kpi-label'>{label}</div>"
                        f"<div class='kpi-value'>{value}</div></div>",
                        unsafe_allow_html=True)


def show_threat_report(result: dict, report_id: int | None = None):
    st.markdown(f"<div class='report-card'><h2 style='margin:0'>🛡️ {result['filename']}</h2>"
                f"<span style='color:#8b94b3'>{result['word_count']} words analyzed</span></div>",
                unsafe_allow_html=True)
    kpi_row(result)

    tab_over, tab_ioc, tab_tech, tab_time, tab_sim = st.tabs(
        ["📋 Overview", "🎯 Indicators", "⚔️ Techniques", "🕒 Timeline", "🔗 Similar"])

    with tab_over:
        st.subheader("Executive Summary")
        st.write(result["summary"])
        st.subheader("Vulnerabilities")
        cves = result.get("cves_enriched") or [{"id": c} for c in result["iocs"]["cves"]]
        if cves:
            for c in cves:
                badge = cvss_badge(c.get("score"))
                sev_txt = f" · {c.get('severity')}" if c.get("severity") else ""
                st.markdown(f"`{c['id']}` {badge}{sev_txt}", unsafe_allow_html=True)
        else:
            st.write("None found")
        c1, c2 = st.columns(2)
        with c1:
            st.subheader("Malware / Actors")
            mal = result["entities"]["malware"]
            st.write("\n".join(f"- {m}" for m in mal) if mal else "None identified")
        with c2:
            st.subheader("Affected Products")
            prods = result["entities"]["products"]
            st.write("\n".join(f"- {p}" for p in prods) if prods else "None identified")

    with tab_ioc:
        tabs = st.tabs([f"{IOC_LABELS[k]} ({len(result['iocs'][k])})" for k in IOC_LABELS])
        for tab, key in zip(tabs, IOC_LABELS):
            with tab:
                vals = result["iocs"][key]
                st.code("\n".join(vals) if vals else "— none —")

    with tab_tech:
        if result["techniques"]:
            for t in result["techniques"]:
                st.markdown(
                    f"<div class='report-card' style='padding:12px 18px'>"
                    f"<b style='color:#00d4ff'>{t['id']}</b> — <b>{t['name']}</b>"
                    f"<br><span style='color:#8b94b3'>{t['tactic']} · "
                    f"matched: {', '.join(t['matched_keywords'][:4])}</span></div>",
                    unsafe_allow_html=True)
        else:
            st.write("None mapped")

    with tab_time:
        if result["timeline"]:
            for ev in result["timeline"]:
                st.markdown(f"<span class='timeline-dot'>●</span> **{ev['date']}** — {ev['event']}",
                            unsafe_allow_html=True)
        else:
            st.write("No dated events extracted.")

    with tab_sim:
        if st.button("🔍 Find similar past incidents", key=f"sim{report_id or 'new'}"):
            with st.spinner("Comparing with report history…"):
                sims = find_similar_incidents(result["text_excerpt"], exclude_id=report_id)
            if sims:
                for s in sims:
                    st.markdown(
                        f"<div class='report-card' style='padding:12px 18px'>"
                        f"<b>#{s['id']}</b> {s['filename']} "
                        f"<span class='sev sev-{s['severity']}' style='font-size:.75rem'>"
                        f"{s['severity']}</span><br>"
                        f"<span style='color:#8b94b3'>{s['threat_type']} · "
                        f"similarity {s['score']:.0%}</span></div>",
                        unsafe_allow_html=True)
            else:
                st.info("No similar incidents in history yet.")

    st.subheader("✅ Recommended Actions")
    for i, a in enumerate(result["recommended_actions"], 1):
        st.write(f"{i}. {a}")

    with st.expander("Classification details (transparency)"):
        st.write("**Threat-type scores:**", result["threat_type_scores"])
        st.write("**Severity reasons:**")
        for r in result["severity_reasons"]:
            st.write(f"- {r}")


# ------------------------------------------------------------------ pages

def page_analyze():
    st.markdown("# 🔍 Analyze Threat Report")
    st.caption("Upload a **PDF** or **TXT** threat report, paste text, or try a sample.")

    with st.container():
        c1, c2 = st.columns([2, 1])
        with c1:
            uploaded = st.file_uploader("Upload report", type=["pdf", "txt"])
        with c2:
            sample = st.selectbox("…or load a sample", ["—"] + list(SAMPLES))
    pasted = st.text_area("…or paste report text", height=120)
    cvss_on = st.checkbox("Enrich CVEs with CVSS scores (needs internet)", value=True)

    if st.button("🚀 Analyze", type="primary"):
        text, filename = None, None
        try:
            if uploaded:
                text = extractor.extract_text(uploaded.name, uploaded.read())
                filename = uploaded.name
            elif sample != "—":
                p = Path(SAMPLES[sample])
                text, filename = p.read_text(encoding="utf-8"), p.name
            elif pasted.strip():
                text, filename = pasted, "pasted-text.txt"
            else:
                st.warning("Upload a file, pick a sample, or paste text first.")
                return
        except ValueError as e:
            st.error(str(e))
            return
        if len(text.strip()) < 50:
            st.error("Not enough text to analyze (need at least ~50 characters).")
            return

        with st.spinner("🛡️ Running NLP pipeline…"):
            result = analyze_text(text, filename, cvss_lookup=cvss_on)
        st.session_state["last_result"] = result
        st.session_state["last_text"] = text

    result = st.session_state.get("last_result")
    if result:
        st.divider()
        show_threat_report(result)
        st.divider()
        c1, c2, c3 = st.columns(3)
        with c1:
            st.download_button("⬇️ Markdown report", render_markdown(result),
                               file_name=result["filename"].rsplit(".", 1)[0] + "_report.md")
        with c2:
            st.download_button("⬇️ PDF report", generate_pdf(result),
                               file_name=result["filename"].rsplit(".", 1)[0] + "_report.pdf",
                               mime="application/pdf")
        with c3:
            if st.button("💾 Save to database"):
                rid = database.save_report(result["filename"], result["threat_type"],
                                           result["severity"], result["summary"], result)
                st.success(f"Saved as report #{rid}")


def page_dashboard():
    st.markdown("# 📊 Threat Intelligence Dashboard")
    reports = database.get_reports(limit=200)
    if not reports:
        st.info("No reports analyzed yet — run an analysis first.")
        return

    severities = Counter(r["severity"] for r in reports)
    types = Counter(r["threat_type"] for r in reports)
    total_iocs = 0
    tech_counter: Counter = Counter()
    for r in reports:
        full = database.get_report(r["id"])
        res = full["result"]
        total_iocs += sum(len(v) for v in res["iocs"].values())
        for t in res["techniques"]:
            tech_counter[f"{t['id']} {t['name']}"] += 1

    k1, k2, k3, k4 = st.columns(4)
    for col, (label, val) in zip((k1, k2, k3, k4),
                                 [("Reports", len(reports)),
                                  ("Critical", severities.get("Critical", 0)),
                                  ("IOCs extracted", total_iocs),
                                  ("Techniques seen", len(tech_counter))]):
        with col:
            st.markdown(f"<div class='kpi-card'><div class='kpi-label'>{label}</div>"
                        f"<div class='kpi-value'>{val}</div></div>", unsafe_allow_html=True)
    st.write("")

    dark = dict(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)")
    c1, c2 = st.columns(2)
    with c1:
        st.plotly_chart(px.pie(names=list(severities), values=list(severities.values()),
                               title="Severity distribution",
                               color=list(severities),
                               color_discrete_map={"Critical": "#e63946", "High": "#ff8c00",
                                                   "Medium": "#3f9dff", "Low": "#37c871"})
                        .update_layout(**dark), use_container_width=True)
    with c2:
        st.plotly_chart(px.bar(x=list(types), y=list(types.values()), title="Threat types",
                               labels={"x": "Threat type", "y": "Reports"},
                               color=list(types.values()), color_continuous_scale="Teal")
                        .update_layout(**dark, coloraxis_showscale=False),
                        use_container_width=True)
    if tech_counter:
        top = tech_counter.most_common(10)
        st.plotly_chart(px.bar(x=[v for _, v in top], y=[k for k, _ in top],
                               orientation="h", title="Top MITRE ATT&CK techniques",
                               labels={"x": "Reports", "y": "Technique"},
                               color=[v for _, v in top], color_continuous_scale="Teal")
                        .update_layout(**dark, coloraxis_showscale=False, yaxis_autorange="reversed"),
                        use_container_width=True)


def page_history():
    st.markdown("# 🗂️ Report History")
    reports = database.get_reports()
    if not reports:
        st.info("Nothing saved yet.")
        return
    for r in reports:
        with st.expander(f"#{r['id']} — {r['filename']}  ·  "
                         f"{r['threat_type']}  ·  {r['severity']}  ·  {r['created_at']}"):
            b1, b2 = st.columns([1, 1])
            with b1:
                if st.button("👁 View", key=f"view{r['id']}"):
                    full = database.get_report(r["id"])
                    show_threat_report(full["result"], report_id=r["id"])
            with b2:
                if st.button("🗑 Delete", key=f"del{r['id']}"):
                    database.delete_report(r["id"])
                    st.rerun()


# ------------------------------------------------------------------ sidebar + main

with st.sidebar:
    st.markdown("## 🛡️ Threat Analyzer")
    st.caption("NLP-based Cybersecurity\nThreat Report Analyzer")
    st.divider()
    page = st.radio("Navigate", ["🔍 Analyze Report", "📊 Dashboard", "🗂️ History"],
                    label_visibility="collapsed")
    st.divider()
    st.caption("**Pipeline**  \nspaCy NER + regex IOCs → classification → "
               "MITRE ATT&CK → CVSS → timeline → SQLite")

{"🔍 Analyze Report": page_analyze,
 "📊 Dashboard": page_dashboard,
 "🗂️ History": page_history}[page]()
