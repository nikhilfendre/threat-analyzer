"""Single entry point: run the full analysis pipeline on raw text."""

from . import entities, preprocessor
from .classifier import (classify_severity, classify_threat_type,
                         recommend_actions)
from .cvss import enrich_cves
from .mitre import map_techniques
from .summarizer import summarize
from .timeline import extract_timeline


def analyze_text(text: str, filename: str = "pasted-text",
                 cvss_lookup: bool = True) -> dict:
    """Run the whole pipeline; return a JSON-serializable result dict."""
    nlp = entities.get_nlp()
    cleaned = preprocessor.clean_text(text)
    cleaned = preprocessor.refang(cleaned)  # normalize defanged IOCs

    iocs = entities.extract_iocs(cleaned)
    ml_entities = entities.extract_ml_entities(cleaned, nlp)
    threat_type, type_scores = classify_threat_type(cleaned)
    severity, sev_reasons = classify_severity(cleaned, iocs)
    techniques = map_techniques(cleaned)
    summary = summarize(cleaned, nlp)
    actions = recommend_actions(threat_type, severity)
    timeline = extract_timeline(cleaned, nlp)

    cves_enriched = enrich_cves(iocs["cves"]) if cvss_lookup and iocs["cves"] else []

    return {
        "filename": filename,
        "word_count": preprocessor.word_count(cleaned),
        "threat_type": threat_type,
        "threat_type_scores": type_scores,
        "severity": severity,
        "severity_reasons": sev_reasons,
        "summary": summary,
        "iocs": iocs,
        "cves_enriched": cves_enriched,
        "entities": ml_entities,
        "techniques": techniques,
        "timeline": timeline,
        "recommended_actions": actions,
        # stored for similar-incident search (never shown raw)
        "text_excerpt": cleaned[:6000],
    }


def render_markdown(result: dict) -> str:
    """Structured threat report as Markdown (for download)."""
    L = [f"# THREAT REPORT — {result['filename']}", "",
         f"**Threat Type:** {result['threat_type']}",
         f"**Severity:** {result['severity']}", "",
         "## Summary", result["summary"], "",
         "## Vulnerabilities"]
    cves = result.get("cves_enriched") or [{"id": c} for c in result["iocs"]["cves"]]
    for c in cves:
        extra = (f" — CVSS {c['score']} ({c.get('severity')})"
                 if c.get("score") is not None else "")
        L.append(f"- {c['id']}{extra}")
    if not cves:
        L.append("- None found")
    L += ["", "## Affected Products"]
    prods = result["entities"].get("products", [])
    L += [f"- {p}" for p in prods] or ["- None identified"]
    L += ["", "## Attack Techniques (MITRE ATT&CK)"]
    for t in result["techniques"]:
        L.append(f"- {t['id']} — {t['name']} ({t['tactic']})")
    if not result["techniques"]:
        L.append("- None mapped")
    L += ["", "## Indicators of Compromise"]
    for label, vals in result["iocs"].items():
        if vals:
            L.append(f"### {label}")
            L += [f"- `{v}`" for v in vals]
    L += ["", "## Recommended Actions"]
    L += [f"{i+1}. {a}" for i, a in enumerate(result["recommended_actions"])]
    return "\n".join(L)
