# data_pipeline.py
import os
import re
import pandas as pd
from datetime import datetime, timezone, timedelta
from typing import Dict, List

from vendor_feeds import fetch_rss, fetch_malwarebazaar
from feeds_ext import fetch_cisa_kev

# ---- CVE helpers ----
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

def _extract_cves_text(s: str) -> list[str]:
    if not s:
        return []
    return list(dict.fromkeys(_CVE_RE.findall(s)))

def _extract_cves_from_link_or_text(link: str, text: str = "") -> list[str]:
    s = f"{link or ''} {text or ''}"
    return _extract_cves_text(s)

# (Optional) very light page-scrape fallback
def _extract_cves_from_url(url: str, timeout: int = 8) -> list[str]:
    if not url:
        return []
    try:
        import requests
        from bs4 import BeautifulSoup
        r = requests.get(url, timeout=timeout, headers={"User-Agent": "TI-Dashboard/1.0"})
        r.raise_for_status()
        soup = BeautifulSoup(r.text, "html.parser")
        text = " ".join(t.get_text(" ", strip=True) for t in soup.find_all(["p","li","h1","h2","h3","code"]))
        return _extract_cves_text(text)
    except Exception:
        return []

def build_dashboard_df(
    feeds: Dict[str, str],
    top_n: int | None = 100,
    days_back: int | None = 30,            # <-- NEW: default 30 days
    enable_page_scrape: bool = False,      # <-- optional fallback
    scrape_limit: int = 10                 # <-- cap scrapes per run
) -> pd.DataFrame:
    rows: List[dict] = []

    # 1) Vendor blogs
    for name, url in feeds.items():
        rows.extend(fetch_rss(name, url))

    # 2) MalwareBazaar + KEV + Exploit-DB
    rows.extend(fetch_malwarebazaar())
    rows.extend(fetch_cisa_kev())
#    rows.extend(fetch_exploitdb_rss())

    df = pd.DataFrame(rows)
    if df.empty:
        return df

    # --- normalise string columns used for dedupe ---
#    for col in ("Link", "Title", "Source"):
#        if col in df.columns:
#            df[col] = df[col].fillna("").astype(str).str.strip()
#
#   # Prefer de-duplicating by Link if present, otherwise by (Title, Source)
#    if "Link" in df.columns and df["Link"].astype(bool).any():
#       df = df.drop_duplicates(subset=["Link"], keep="first")
#   else:
#        df = df.drop_duplicates(subset=["Title", "Source"], keep="first")

    # Normalize columns we rely on
    if "Summary" not in df.columns:
        df["Summary"] = ""  # fetch_rss should provide, but be safe
    df["Published"] = pd.to_datetime(df["Published"], utc=True, errors="coerce")
    df = df.dropna(subset=["Published"]).sort_values("Published", ascending=False)

    # 3) Time window (e.g., last 30 days)
    if days_back and days_back > 0:
        cutoff = datetime.now(timezone.utc) - timedelta(days=days_back)
        df = df[df["Published"] >= cutoff]

    # 4) CVE extraction: Title + Summary + Link
    # Make sure text columns are strings (no NaNs/floats)
    
    for col in ["Title", "Summary", "Link", "Source"]:
        if col in df.columns:
            df[col] = df[col].fillna("").astype(str)
    
    df = df.copy()
    df["CVEs"] = df.apply(
        lambda r: list(dict.fromkeys(
            _extract_cves_text((r.get("Title") or "") + " " + (r.get("Summary") or "")) +
            _extract_cves_from_link_or_text(r.get("Link"), r.get("Title"))
        )),
        axis=1
    )

    # 5) Optional: scrape a few articles missing CVEs
    if enable_page_scrape:
        to_scrape = df[df["CVEs"].apply(len).eq(0)].head(scrape_limit)
        for idx, row in to_scrape.iterrows():
            cves = _extract_cves_from_url(row.get("Link"))
            if cves:
                df.at[idx, "CVEs"] = cves

    # 6) Optional cap to keep UI snappy
    if top_n:
        df = df.head(top_n)

    return df.reset_index(drop=True)

