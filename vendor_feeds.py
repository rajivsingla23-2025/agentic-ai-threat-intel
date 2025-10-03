import feedparser
from dateutil import parser as dtparse
from datetime import datetime, timezone

HTTP_TIMEOUT = 20  # not used by feedparser but kept for consistency

def fetch_rss(name: str, url: str) -> list[dict]:
    d = feedparser.parse(url)
    rows = []
    for e in d.entries:
        title = getattr(e, "title", "").strip()
        link  = getattr(e, "link", "")
        # new: summary / description text
        summary = getattr(e, "summary", "") or getattr(e, "description", "")
        pub_raw = getattr(e, "published", "") or getattr(e, "updated", "")
        try:
            published = dtparse.parse(pub_raw).astimezone(timezone.utc)
        except Exception:
            published = datetime.now(timezone.utc)
        rows.append({
            "Published": published,
            "Source": name,
            "Title": title,
            "Summary": summary,
            "Link": link,
        })
    return rows


def fetch_malwarebazaar(limit: int = 50) -> list[dict]:
    rss = "https://bazaar.abuse.ch/feeds/rss/"
    d = feedparser.parse(rss)
    rows = []
    for e in d.entries[:limit]:
        title = getattr(e, "title", "").strip()
        link = getattr(e, "link", "")
        pub_raw = getattr(e, "published", "") or getattr(e, "updated", "")
        try:
            published = dtparse.parse(pub_raw).astimezone(timezone.utc)
        except Exception:
            published = datetime.now(timezone.utc)
        rows.append({"Published": published, "Source": "MalwareBazaar", "Title": title, "Link": link})
    return rows
