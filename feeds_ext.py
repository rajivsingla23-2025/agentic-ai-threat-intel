# ---- FEED EXPANSION: NVD + CISA KEV + (optional) Exploit-DB ----
import os, time, requests
import feedparser
import re
from datetime import datetime, timedelta, timezone
from dateutil import parser as dtparse
import streamlit as st

HTTP_TIMEOUT = 20
# NVD_API_KEY = os.getenv("NVD_API_KEY", "")  # empty string if not set
# tuning values (can be overridden by env if you prefer)
# NVD_CHUNK_DAYS = int(os.getenv("NVD_CHUNK_DAYS", "3"))      # chunk size when no key
# NVD_RESULTS_PER_PAGE = int(os.getenv("NVD_RESULTS_PER_PAGE", "100"))
# NVD_MAX_PAGES = int(os.getenv("NVD_MAX_PAGES", "3"))

def _utc_now():
    return datetime.now(timezone.utc)

def _iso_utc(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000 UTC")

def _do_nvd_request(params, headers):
    base = "https://services.nvd.nist.gov/rest/json/cves/1.0"
    r = requests.get(base, params=params, headers=headers, timeout=HTTP_TIMEOUT)
    return r

@st.cache_data(ttl=60*15, show_spinner=False)
def fetch_cisa_kev() -> list[dict]:
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    r = requests.get(url, timeout=HTTP_TIMEOUT)
    r.raise_for_status()
    kev = r.json()
    out = []
    for v in kev.get("vulnerabilities", []):
        cve = v.get("cveID")
        short = (v.get("shortDescription") or "").strip()
        dt = v.get("dateAdded") or v.get("requiredActionDueDate") or _utc_now().isoformat()
        try:
            published = dtparse.parse(dt).astimezone(timezone.utc)
        except Exception:
            published = _utc_now()
        out.append({
            "Published": published,
            "Source": "CISA KEV",
            "Title": f"{cve} (KEV) — {short[:140]}",
            "Link": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        })
    return out
