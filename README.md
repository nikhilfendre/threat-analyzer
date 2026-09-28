# 🛡️ Threat Analyzer — NLP-Based Cybersecurity Threat Report Analyzer

Upload a cybersecurity threat / vulnerability / incident report (PDF or TXT) and
get a **structured threat report**: threat type, severity, MITRE ATT&CK
techniques, indicators of compromise (CVEs, IPs, domains, hashes), an
extractive summary, and recommended actions — plus a dashboard over all
analyzed reports.

## Quick start (copy-paste)

```bash
cd threat-analyzer
python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate     # Linux/Mac

pip install -r requirements.txt
python -m spacy download en_core_web_sm

streamlit run app.py
```

Then open the URL Streamlit prints (usually http://localhost:8501) and try
`data/samples/sample_ransomware.txt` from the sidebar dropdown.

## How it works

```
Upload (PDF/TXT) → PyMuPDF text extraction → cleaning / sentence split / refang
  → regex IOC extraction (CVE, IPv4, domain, URL, email, MD5/SHA1/SHA256)
  → spaCy NER + EntityRuler (malware families, products, orgs)
  → threat-type classification (keyword scoring, 8 classes)
  → severity scoring (Critical/High/Medium/Low + reasons)
  → MITRE ATT&CK technique mapping (15 techniques, keyword triggers)
  → CVSS enrichment of CVEs via NVD API (cached, offline-safe)
  → attack-timeline extraction (dates + event sentences)
  → extractive summarization + recommended actions
  → structured report (Markdown + PDF) + Plotly dashboard (dark theme)
  → SQLite storage (report history + TF-IDF similar-incident search)
```

## Project structure

```
threat-analyzer/
├── app.py                 # Streamlit UI (Analyze / Dashboard / History)
├── requirements.txt
├── src/
│   ├── analyze.py         # pipeline orchestration + Markdown report renderer
│   ├── extractor.py       # PDF (PyMuPDF) / TXT text extraction
│   ├── preprocessor.py    # cleaning, refang, sentence segmentation
│   ├── entities.py        # regex IOCs + spaCy NER/EntityRuler
│   ├── classifier.py      # threat-type + severity + recommendations
│   ├── mitre.py           # MITRE ATT&CK keyword → technique map
│   ├── cvss.py            # NVD API CVSS lookup with local cache
│   ├── timeline.py        # attack-timeline extraction
│   ├── similarity.py      # TF-IDF similar-incident search
│   ├── pdf_report.py      # professional PDF report export
│   ├── summarizer.py      # extractive summarizer
│   └── database.py        # SQLite report storage
└── data/samples/          # 2 sample reports for instant testing
```

## Honest limitations (good viva material)

- **No labeled training data** → classification is transparent rule-based
  scoring, not a trained ML model. Every decision lists its triggering
  keywords in the "Classification details" expander.
- **Generic spaCy model** (`en_core_web_sm`) is trained on news/web text, not
  security reports — so well-formed indicators use deterministic regex
  (more reliable), and domain knowledge comes from the curated EntityRuler
  + MITRE keyword lists.
- **Severity is heuristic**, not a CVSS calculation.

## Natural extensions

1. Train sklearn classifiers on a labeled report corpus (replaces keyword scoring)
2. Fine-tune a transformer NER (e.g. CyNER-style) on security text
3. VirusTotal / AbuseIPDB reputation checks for extracted IPs and domains
4. STIX 2.1 export (industry threat-intel sharing format)
