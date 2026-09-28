"""
Threat Analyzer — NLP-based Cybersecurity Threat Report Analyzer.

Pipeline:
    upload (PDF/TXT) -> extract text -> preprocess -> entity/IOC extraction
    -> threat classification -> severity scoring -> MITRE ATT&CK mapping
    -> summarization -> structured report + dashboard
"""

__version__ = "1.0.0"
