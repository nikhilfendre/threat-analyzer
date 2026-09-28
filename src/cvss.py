"""CVSS lookup for extracted CVEs via the NVD API (with local cache).

No API key needed at low request rates. Every failure (offline, rate
limit, unknown CVE) degrades gracefully to None — the report still works.
"""

import json
import time
from pathlib import Path

import requests

CACHE_PATH = Path(__file__).resolve().parent.parent / "data" / "cache" / "cvss.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _load_cache() -> dict:
    if CACHE_PATH.exists():
        try:
            return json.loads(CACHE_PATH.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def _save_cache(cache: dict) -> None:
    try:
        CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        CACHE_PATH.write_text(json.dumps(cache, indent=1))
    except OSError:
        pass


def _parse_metrics(cve_item: dict) -> dict | None:
    metrics = cve_item.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            data = entries[0].get("cvssData", {})
            return {
                "score": data.get("baseScore"),
                "severity": data.get("baseSeverity", "").upper() or None,
                "vector": data.get("vectorString"),
                "version": key.replace("cvssMetricV", "v"),
            }
    return None


def lookup_cve(cve_id: str, timeout: int = 8) -> dict | None:
    """Return {score, severity, vector, version} or None on any failure."""
    cache = _load_cache()
    key = cve_id.upper()
    if key in cache:
        return cache[key]

    result = None
    try:
        resp = requests.get(NVD_URL, params={"cveId": key}, timeout=timeout)
        if resp.status_code == 200:
            vulns = resp.json().get("vulnerabilities", [])
            if vulns:
                result = _parse_metrics(vulns[0].get("cve", {}))
        elif resp.status_code == 429:
            time.sleep(2)  # polite single backoff; give up after that
    except Exception:
        result = None

    cache[key] = result
    _save_cache(cache)
    return result


def enrich_cves(cve_ids: list[str]) -> list[dict]:
    """[{id, score, severity, vector, version}] — score may be None offline."""
    enriched = []
    for cve in cve_ids:
        info = lookup_cve(cve) or {}
        enriched.append({
            "id": cve,
            "score": info.get("score"),
            "severity": info.get("severity"),
            "vector": info.get("vector"),
            "version": info.get("version"),
        })
        time.sleep(0.4)  # stay polite to the public NVD API
    return enriched
