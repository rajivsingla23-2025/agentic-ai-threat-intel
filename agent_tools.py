"""
Agent toolbelt for the Threat Intel Dashboard.
- Pure-requests (no vendor SDKs) to keep it portable on Streamlit Cloud.
- Safe defaults (rate limits, caching, allowlists, timeouts).
"""

from __future__ import annotations
import os, re, json, time, hashlib
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List, Optional, Tuple
import requests
import pandas as pd

# ---------- Tunables ----------
HTTP_TIMEOUT = 15
USER_AGENT = "TI-Dashboard-Agent/1.0"
ALLOWED_HOSTS = {
    "cve.circl.lu", "api.first.org", "www.cisa.gov",
    "bazaar.abuse.ch", "urlhaus.abuse.ch", "hooks.slack.com",
    "services.nvd.nist.gov"
}
CACHE_TTL_SECONDS = 60 * 30  # 30 min
DRY_RUN = os.getenv("AGENT_DRY_RUN", "false").lower() == "true"
SLACK_WEBHOOK = os.getenv("SLACK_WEBHOOK_URL", "")
JIRA_BASE = os.getenv("JIRA_BASE_URL", "")        # e.g. https://yourco.atlassian.net
JIRA_USER = os.getenv("JIRA_USER_EMAIL", "")
JIRA_TOKEN = os.getenv("JIRA_API_TOKEN", "")
JIRA_PROJECT_KEY = os.getenv("JIRA_PROJECT_KEY", "SEC")

# Simple in-memory cache (sufficient for Streamlit single-process)
_cache: Dict[str, Tuple[float, Any]] = {}

def _cache_get(key: str):
    v = _cache.get(key)
    if not v: return None
    ts, data = v
    if time.time() - ts > CACHE_TTL_SECONDS:
        _cache.pop(key, None)
        return None
    return data

def _cache_set(key: str, data: Any):
    _cache[key] = (time.time(), data)

def _allowlisted(url: str) -> bool:
    try:
        host = requests.utils.urlparse(url).hostname or ""
        return host in ALLOWED_HOSTS
    except Exception:
        return False

def _get_json(url: str, params=None, headers=None):
    if not _allowlisted(url):
        raise ValueError(f"Host not allow-listed: {url}")
    key = "GET:" + url + "|" + json.dumps(params or {}, sort_keys=True)
    hit = _cache_get(key)
    if hit is not None:
        return hit
    hdrs = {"User-Agent": USER_AGENT}
    if headers: hdrs.update(headers)
    r = requests.get(url, params=params, headers=hdrs, timeout=HTTP_TIMEOUT)
    r.raise_for_status()
    data = r.json()
    _cache_set(key, data)
    return data

def _post_json(url: str, data=None, headers=None):
    if not _allowlisted(url):
        raise ValueError(f"Host not allow-listed: {url}")
    hdrs = {"User-Agent": USER_AGENT}
    if headers: hdrs.update(headers)
    r = requests.post(url, data=data, headers=hdrs, timeout=HTTP_TIMEOUT)
    r.raise_for_status()
    return r.json()


# ------------------- Feed helpers (from your app cache) -------------------
def fetch_feed_from_df(
    df: pd.DataFrame,
    query: str | None = None,
    hours: int = 24,
    cves: list[str] | None = None,
    keywords: list[str] | None = None,
    any_match: bool = False,
    source_filter: list[str] | None = None,
):
    """
    Filter dashboard DF by time window + (CVE OR keywords), with optional source scoping.
    - Prioritizes CVE matches.
    - When no match: auto-expands to 30 days (for CVEs or keywords).
    - any_match=True makes keyword matching OR instead of AND.
    - source_filter=["CISA KEV"] limits to KEV rows for KEV-focused queries.
    """
    from datetime import datetime, timezone, timedelta
    import pandas as pd, re

    def _apply_filters(d: pd.DataFrame, cutoff, cves, keywords, any_match, source_filter):
        if d.empty:
            return d

        d = d.copy()
        d["Published"] = pd.to_datetime(d["Published"], utc=True, errors="coerce")
        d = d[d["Published"] >= cutoff]

        if d.empty:
            return d

        # Optional source scoping (e.g., only CISA KEV)
        if source_filter:
            d = d[d["Source"].isin(source_filter)]
            if d.empty:
                return d

        # Build searchable text
        text = d["Title"].astype(str).str.lower()
        if "Source" in d.columns:
            text = (d["Title"].astype(str) + " " + d["Source"].astype(str)).str.lower()

        # CVE filter (highest priority)
        if cves:
            mask = pd.Series(False, index=d.index)
            for c in cves:
                if c:
                    mask = mask | text.str.contains(c.lower(), regex=False)
            d = d[mask]
            return d

        # Keyword filter
        if keywords:
            if any_match:
                # OR across tokens
                mask = pd.Series(False, index=d.index)
                for k in keywords:
                    if k and len(k) > 2:
                        mask = mask | text.str.contains(re.escape(k.lower()), regex=True)
            else:
                # AND across tokens
                mask = pd.Series(True, index=d.index)
                for k in keywords:
                    if k and len(k) > 2:
                        mask = mask & text.str.contains(re.escape(k.lower()), regex=True)
            d = d[mask]

        return d

    # --- Initial window ---
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=hours)
    d = _apply_filters(df, cutoff, cves, keywords, any_match, source_filter)

    # --- Auto-expand (to 30 days) if nothing found ---
    if (d is None or d.empty) and (cves or keywords):
        cutoff_30d = now - timedelta(days=30)
        d = _apply_filters(df, cutoff_30d, cves, keywords, any_match, source_filter)
        if d is not None and not d.empty:
            # mark widened results for audit trail
            d = d.copy()
            d["__auto_widened"] = True

    if d is None or d.empty:
        return []

    return d.sort_values("Published", ascending=False).to_dict("records")


# ------------------- CVE enrichment -------------------
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

def extract_cves(text: str) -> List[str]:
    return list(dict.fromkeys(_CVE_RE.findall(text or "")))  # unique, keep order

def get_cve_details(cve_id: str) -> Dict[str, Any]:
    # 1) KEV + EPSS first (so we always have these)
    kev_info = {}
    try:
        kev_info = is_in_cisa_kev(cve_id)  # returns dict with keys: in_kev, date_added, due_date, short_description (add this in your is_in_cisa_kev)
    except Exception:
        kev_info = {"cve": cve_id, "in_kev": None, "short_description": None}

    epss_info = {}
    try:
        epss_info = get_epss(cve_id)
    except Exception:
        epss_info = {"cve": cve_id, "epss": None, "percentile": None}

    # 2) CIRCL enrichment
    url = f"https://cve.circl.lu/api/cve/{cve_id}"
    try:
        data = _get_json(url)
        desc = data.get("summary")
        cvss = data.get("cvss3") or data.get("cvss")
        vector = data.get("cvss-vector") or data.get("cvss3-vector") or data.get("vectorString")
        pub = data.get("Published") or data.get("published")
        refs = (data.get("references") or [])[:10]

        # --- Fallback: if CIRCL lacks description, use KEV shortDescription
        if not desc:
            desc = kev_info.get("short_description")

        return {
            "cve": cve_id,
            "cvss": cvss,
            "vector": vector,
            "description": desc,
            "published": pub,
            "references": refs,
            "note": "source: CIRCL",
            "kev": kev_info,
            "epss": epss_info,
        }
    except Exception as e:
        return {
            "cve": cve_id,
            "cvss": None,
            "vector": None,
            "description": kev_info.get("short_description"),  # <- KEV fallback
            "published": None,
            "references": [],
            "note": f"CIRCL unavailable: {type(e).__name__}",
            "kev": kev_info,
            "epss": epss_info,
        }

        
def get_epss(cve_id: str) -> Dict[str, Any]:
    """FIRST EPSS score."""
    url = "https://api.first.org/data/v1/epss"
    data = _get_json(url, params={"cve": cve_id})
    rows = data.get("data", [])
    if not rows: return {"cve": cve_id, "epss": None}
    row = rows[0]
    return {"cve": cve_id, "epss": float(row.get("epss", 0.0)), "percentile": float(row.get("percentile", 0.0))}
    
def get_epss_bulk(cves: list[str]) -> dict[str, dict]:
    """
    Bulk EPSS lookup for a list of CVEs.
    Uses your existing get_epss(cve) helper in a loop.
    Returns {CVE: {"cve": CVE, "epss": float|None, "percentile": float|None}}
    """
    out = {}
    for c in set(cves or []):
        try:
            s = get_epss(c)  # <-- assumes you already have a single-CVE EPSS fetch
            if s:
                out[c] = {
                    "cve": c,
                    "epss": s.get("epss"),
                    "percentile": s.get("percentile"),
                }
            else:
                out[c] = {"cve": c, "epss": None, "percentile": None}
        except Exception:
            out[c] = {"cve": c, "epss": None, "percentile": None}
    return out


def is_in_cisa_kev(cve_id: str) -> Dict[str, Any]:
    """Check CISA Known Exploited Vulnerabilities list (JSON)."""
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    data = _get_json(url)
    for v in data.get("vulnerabilities", []):
        if v.get("cveID") == cve_id:
            return {
                "cve": cve_id,
                "in_kev": True,
                "date_added": v.get("dateAdded"),
                "due_date": v.get("dueDate") or v.get("requiredActionDueDate"),
                "short_description": v.get("shortDescription"),
                "vendor_project": v.get("vendorProject"),
                "product": v.get("product"),
            }
    return {"cve": cve_id, "in_kev": False, "short_description": None}

# ------------------- MalwareBazaar enrichment -------------------
def mb_enrich_sha256(sha256: str) -> Dict[str, Any]:
    url = "https://bazaar.abuse.ch/api/v1/"
    res = _post_json(url, data={"query": "get_info", "hash": sha256})
    if res.get("query_status") != "ok": return {"sha256": sha256, "found": False}
    d = res["data"][0]
    return {
        "sha256": sha256,
        "found": True,
        "file_type": d.get("file_type"),
        "signature": d.get("signature"),
        "first_seen": d.get("first_seen"),
        "vendor_intel": d.get("vendor_intel", {})
    }

def redact_poc(text: str, max_len: int = 5000) -> str:
    """
    Redact potentially sensitive PoC/code content from descriptions.
    - Removes fenced code blocks (``` ... ```)
    - Redacts common command patterns
    - Redacts long hex/hash-like blobs
    - Truncates very long text to max_len
    """
    if not text:
        return ""
    # Remove fenced code blocks
    text = re.sub(r"```.+?```", "[redacted code block]", text, flags=re.DOTALL | re.IGNORECASE)
    # Redact common command patterns (heuristic)
    text = re.sub(r"(?:^|\s)(curl|wget|nc|ncat|powershell|bash|sh|python3?|perl|ruby|php)\s+[^\n]{20,}",
                  " [redacted command] ", text, flags=re.IGNORECASE)
    # Redact long hex blobs / possible payloads
    text = re.sub(r"\b[a-fA-F0-9]{40,}\b", "[redacted hash/payload]", text)
    # Truncate as safety belt
    if len(text) > max_len:
        text = text[:max_len] + "\n\n[description truncated]"
    return text

# --- KEV index (JSON) ---------------------------------------------------------
import time
import requests

_KEV_JSON_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_kev_index: dict[str, dict] = {}
_kev_fetched_at: float = 0.0
_kev_ttl_seconds = 6 * 60 * 60  # refresh every 6 hours

def _ensure_kev_index(force: bool = False):
    global _kev_index, _kev_fetched_at
    now = time.time()
    if not force and _kev_index and (now - _kev_fetched_at) < _kev_ttl_seconds:
        return
    try:
        r = requests.get(_KEV_JSON_URL, timeout=15)
        r.raise_for_status()
        data = r.json() or {}
        idx = {}
        for v in data.get("vulnerabilities", []):
            cve = (v.get("cveID") or "").strip()
            if not cve:
                continue
            # Normalize field names (defensive)
            date_added = v.get("dateAdded") or v.get("date_added")
            due_date   = (
                v.get("dueDate") or
                v.get("requiredActionDueDate") or
                v.get("due_date")
            )
            idx[cve] = {
                "cve": cve,
                "in_kev": True,
                "date_added": date_added,
                "due_date": due_date,
                # keep a few useful extras if you like:
                "vendor": v.get("vendorProject"),
                "product": v.get("product"),
                "short_description": v.get("shortDescription"),
            }
        _kev_index = idx
        _kev_fetched_at = now
    except Exception:
        # On failure, keep existing cache if any
        if not _kev_index:
            _kev_index = {}
        # You could log/print here if desired

def lookup_kev(cve: str) -> dict:
    """Return normalized KEV record for a CVE, or {} if not in KEV."""
    _ensure_kev_index()
    return _kev_index.get(cve, {})

def get_kev_status(cve: str) -> dict:
    """Return {"in_kev": bool, "date_added": str|None, "due_date": str|None}."""
    try:
        rec = lookup_kev(cve)
        if not rec:
            return {"in_kev": False}
        return {
            "in_kev": True,
            "date_added": rec.get("date_added"),
            "due_date": rec.get("due_date"),
        }
    except Exception:
        return {"in_kev": False}


# ------------------- Notifications / Tickets -------------------
def notify_slack(text: str, channel_hint: str="#threat-intel") -> Dict[str, Any]:
    if not SLACK_WEBHOOK:
        return {"ok": False, "error": "No webhook configured"}
    if DRY_RUN:
        return {"ok": True, "dry_run": True, "text": text}
    headers = {"Content-Type": "application/json"}
    payload = {"text": text}
    r = requests.post(SLACK_WEBHOOK, headers=headers, data=json.dumps(payload), timeout=HTTP_TIMEOUT)
    try:
        r.raise_for_status()
        return {"ok": True}
    except Exception as e:
        return {"ok": False, "error": str(e), "status": r.status_code, "body": r.text[:300]}

def create_jira(summary: str, description: str, severity: str="Medium") -> Dict[str, Any]:
    if not (JIRA_BASE and JIRA_USER and JIRA_TOKEN):
        return {"ok": False, "error": "Jira creds missing"}
    if DRY_RUN:
        return {"ok": True, "dry_run": True, "summary": summary}
    url = f"{JIRA_BASE}/rest/api/3/issue"
    headers = {"Content-Type": "application/json"}
    auth = (JIRA_USER, JIRA_TOKEN)
    data = {
        "fields": {
            "project": {"key": JIRA_PROJECT_KEY},
            "summary": summary[:240],
            "description": description[:30000],
            "issuetype": {"name": "Task"},
            "priority": {"name": severity}
        }
    }
    r = requests.post(url, headers=headers, auth=auth, data=json.dumps(data), timeout=HTTP_TIMEOUT)
    try:
        r.raise_for_status()
        return {"ok": True, "key": r.json().get("key")}
    except Exception as e:
        return {"ok": False, "error": str(e), "status": r.status_code, "body": r.text[:300]}


