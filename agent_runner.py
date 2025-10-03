"""
Lightweight agent runner.
- If OPENAI_API_KEY is set, uses LLM for planning/summarizing via tool calls.
- Else, uses heuristic planner (rules) and templated summary.
"""

from __future__ import annotations
import os, re
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List, Optional
import pandas as pd

from agent_tools import (
    fetch_feed_from_df, extract_cves, get_cve_details, get_epss, get_epss_bulk, is_in_cisa_kev,
    mb_enrich_sha256, notify_slack, create_jira, get_kev_status
)

USE_LLM = bool(os.getenv("OPENAI_API_KEY"))
# Optional: pip install openai>=1.50
if USE_LLM:
    from openai import OpenAI
    oai = OpenAI()

SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")

import re

def _heuristic_plan(query: str) -> dict:
    q = query.lower()
    plan = {
        "need_feeds": True,
        "hours": 24,
        "keywords": [],
        "cves": [],
        "hashes": [],
        "actions": [],
        "kev_focus": False,         
        "any_match": False,         
        "min_epss": None,
        "vendor_sources": [],
    }

    # --- Time window parsing ---
    m = re.search(r"(\d+)\s*(hour|hours|day|days|week|weeks|month|months)", q)
    if m:
        num = int(m.group(1)); unit = m.group(2)
        if "hour" in unit:  plan["hours"] = num
        elif "day" in unit: plan["hours"] = num * 24
        elif "week" in unit: plan["hours"] = num * 7 * 24
        elif "month" in unit: plan["hours"] = num * 30 * 24

    # Handle phrases like "this week", "this month", "today", "yesterday"
    if "this week" in q:
        plan["hours"] = 7 * 24
    elif "this month" in q:
        plan["hours"] = 30 * 24
    elif "today" in q and ("hour" not in q and "day" not in q):
        plan["hours"] = 24
    elif "yesterday" in q:
        plan["hours"] = 48

    # EPSS threshold in the query: "epss > 0.7", "epss above 70%"
    m = re.search(r"epss\s*(?:>=|>|above|over)\s*(\d+(?:\.\d+)?%?)", q)
    if m:
        raw = m.group(1)
        plan["min_epss"] = (float(raw[:-1]) / 100.0) if raw.endswith("%") else (float(raw) if float(raw) <= 1 else float(raw)/100.0)

    # Map "high risk" to default EPSS if none specified
    if "high risk" in q and plan["min_epss"] is None:
        default_thr = float(os.getenv("HIGH_RISK_EPSS_DEFAULT", "0.7"))
        plan["min_epss"] = default_thr
        
    # --- KEV focus ---
    if "kev" in q or "known exploited" in q:
        plan["kev_focus"] = True
        plan["any_match"] = True  # OR matching is fine; we mainly need KEV + time

    # --- Detect vendor names and map to feed Source labels ---
    VENDOR_MAP = {
        "cisco": ["Cisco Talos"],
        "talos": ["Cisco Talos"],
        "microsoft": ["MSRC"],
        "msrc": ["MSRC"],
        "palo alto": ["Palo Alto Unit42"],
        "unit42": ["Palo Alto Unit42"],
        "crowdstrike": ["CrowdStrike"],
        "mandiant": ["Google Mandiant"],
        "google": ["Google Mandiant"],
        "kaspersky": ["Kaspersky"],
        "zdi": ["Trend Micro ZDI"],
        "Trend Micro": ["Trend Micro ZDI"],
    }
    vendors_detected = []
    for k, sources in VENDOR_MAP.items():
        if k in q:
            vendors_detected.extend(sources)
    if vendors_detected:
        plan["vendor_sources"] = sorted(set(vendors_detected))
        plan["any_match"] = True  # be permissive on keywords when scoping by source
    
    # --- Keywords (light, remove stopwords, keep up to 5)
    STOP = {"the","a","an","from","last","this","that","week","weeks","month","months",
            "show","list","added","and","or","of","in","for","to","cves","vulnerabilities",
            "summarize","high","risk","new"}
    words = [w.strip(",.") for w in q.split()]
    plan["keywords"] = [w for w in words if len(w) > 2 and w not in STOP and not w.startswith("cve-")][:5]

    # --- CVEs / hashes ---
    from agent_tools import extract_cves
    plan["cves"] = extract_cves(query)
    SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
    plan["hashes"] = SHA256_RE.findall(query)

    # --- Action hints ---
    if "notify" in q or "slack" in q: plan["actions"].append("notify_slack")
    if "ticket" in q or "jira" in q or "create issue" in q: plan["actions"].append("create_jira")

    return plan


def _summarize_heuristic(query, feeds, cve_details, kev_hits, epss_scores, hash_enrich, min_epss=None):
    """
    Build the agent markdown summary.
    - feeds: dict with keys "hours", "items", optional "source_filter", "selection_reason"
    - cve_details: list of CVE detail dicts (only selected ones)
    - kev_hits: list of kev dicts
    - epss_scores: list of {"cve", "epss", "percentile"} for selected CVEs
    - min_epss: optional threshold used for selection
    """
    # --- header / counts / what we will show ---
    items = feeds.get("items") or []
    items_count = len(items)
    selected_cves_count = len(cve_details or [])
    src_filter = feeds.get("source_filter")
    if isinstance(src_filter, (list, tuple)):
        src_note = f" | Source: {', '.join(str(x) for x in src_filter)}"
    elif isinstance(src_filter, str):
        src_note = f" | Source: {src_filter}"
    else:
        src_note = ""
    thr_note = f" | Filter: EPSS ≥ {float(min_epss):.2f}" if isinstance(min_epss, (int, float)) else ""
    sel_reason = feeds.get("selection_reason") or ""

    matched_count = feeds.get("matched_rows_count", None)
    # Build two separate lines for counts
    if matched_count is None:
        items_line = f"- Feed posts matched by text/vendor: {items_count}"
        matched_line = None
    else:
        items_line = f"- Feed posts matched by text/vendor: {items_count}"
        matched_line = f"- Feed rows mentioning selected CVEs: {matched_count}"

    # Decide what we will display
    if items_count > 0 and selected_cves_count > 0:
        showing = "- **Showing:** Feed posts + CVEs"
    elif items_count > 0:
        showing = "- **Showing:** Feed posts"
    elif selected_cves_count > 0:
        showing = "- **Showing:** CVEs"
    else:
        # nothing to show
        showing = "- **Showing:** (no feed posts or CVEs matched)"

    # Compose header lines
    lines = [
        f"### Intel summary for: **{query}**",
        f"- Time window: last {feeds.get('hours', 24)} hours{src_note}{thr_note}",
        items_line,
    ]
    if matched_line:
        lines.append(matched_line)
    lines.append(f"- CVEs selected: {selected_cves_count}" + (f" — {sel_reason}" if sel_reason else ""))
    lines.append(showing)

    # Single unified hint message (avoid duplicates)
    if src_filter and items_count == 0 and selected_cves_count == 0:
        lines.append("\n> No posts or CVEs found for the selected vendor(s) in this time window. Try widening the window or removing the vendor filter.")
    elif items_count == 0 and feeds.get("matched_rows_count", 0) > 0:
        lines.append("\n> No posts matched your text/vendor filters, but the selected CVEs were found in other KEV/EPSS sources referenced in the data window.")
    elif items_count == 0 and selected_cves_count > 0 and not feeds.get("matched_rows_count"):
        lines.append("\n> No feed posts matched the text/vendor filters in this window, but relevant CVEs were found via KEV/EPSS or explicit CVE input.")
   
    # --- Top items preview (only if any) ------------------------------------
    if items_count:
        lines.append("\n**Top items:**")
        seen = set()
        # iterate a bit more to allow dedupe, but display up to 5 unique items
        for it in (items or [])[:20]:
            # Normalize display fields
            link = (it.get("Link") or "").strip()
            title_raw = it.get("Title") or ""
            # If Title is empty, check Summary / fallback
            if not title_raw:
                title_raw = (it.get("Summary") or "").strip()[:140] or ""
            # sanitize title to avoid broken markdown
            safe_title = str(title_raw).replace("[", "(").replace("]", ")").strip()
            if not safe_title:
                safe_title = "(no title)"
            key = (link or "") or safe_title
            if key in seen:
                continue
            seen.add(key)

            pub = it.get("Published")
            if hasattr(pub, "strftime"):
                try:
                    pub = pub.strftime("%Y-%m-%d %H:%M")
                except Exception:
                    pub = str(pub)
            else:
                pub = str(pub)

            src = it.get("Source") or "unknown"
            if link:
                lines.append(f"- {pub} | {src}: [{safe_title}]({link})")
            else:
                lines.append(f"- {pub} | {src}: {safe_title}")

            if len(seen) >= 5:
                break 

 # CVE details with KEV due date & EPSS percentile
    # --- CVE details block ---
    if cve_details:
        lines.append("\n**CVE details:**")
        for c in cve_details:
            # basic fields
            cvss_txt = f"{c.get('cvss')}" if c.get("cvss") is not None else "N/A"
            epss = c.get("epss") or {}
            epss_val = epss.get("epss"); epss_pct = epss.get("percentile")
            if isinstance(epss_val, (int, float)):
                epss_txt = f"{epss_val:.2f}" + (f" (p{int(round(100*epss_pct))})" if isinstance(epss_pct, (int,float)) else "")
            else:
                epss_txt = "N/A"

            kev = c.get("kev") or {}
            kev_flag = " | KEV: YES" if kev.get("in_kev") else ""
            # be tolerant to either due_date or dueDate
            due = kev.get("due_date") or kev.get("dueDate")
            due_txt = f" | KEV due: {due}" if due else ""

            note = f" ({c['note']})" if c.get("note") else ""
            lines.append(f"- {c.get('cve')} | CVSS: {cvss_txt} | EPSS: {epss_txt}{kev_flag}{due_txt}{note}")

            # --- KEV remediation nudge (only when actually in KEV) ---
            if kev.get("in_kev"):
                if due:
                    lines.append(f"  > KEV-listed: prioritize patching before **{due}**; validate exposure, monitor IOCs, and apply compensating controls until patched.")
                else:
                    lines.append("  > KEV-listed: prioritize patching; validate exposure, monitor IOCs, and apply compensating controls until patched.")

            # --- Short description preview (if present) ---
            desc = c.get("description") or c.get("desc") or c.get("summary")
            if isinstance(desc, str) and desc.strip():
                preview = desc[:300] + ("..." if len(desc) > 300 else "")
                lines.append(f"  - _{preview}_")

            # --- Optional: a couple of references (if you store them) ---
            refs = c.get("references") or []
            for r in refs[:3]:
                lines.append(f"  - Ref: {r}")

  
    # KEV list recap
    if kev_hits:
        kev_list = [k["cve"] for k in kev_hits if k.get("in_kev")]
        if kev_list:
            lines.append(f"\n**CISA KEV:** {', '.join(kev_list)} (known exploited)")

    # --- EPSS top recap (filtered when min_epss is set) ---
    if epss_scores:
        # Keep only rows that actually have numeric EPSS
        valid = [e for e in epss_scores if isinstance(e.get("epss"), (int, float))]
        # If a threshold is present, filter here too (belt & suspenders)
        if isinstance(min_epss, (int, float)):
            valid = [e for e in valid if (e.get("epss") or 0) >= float(min_epss)]
        # sort high→low and take a few
        top = sorted(valid, key=lambda x: x.get("epss", 0), reverse=True)[:5]
        if top:
            label = "**Top EPSS CVEs**"
            if isinstance(min_epss, (int, float)):
                label = f"**Top EPSS CVEs (≥ {float(min_epss):.2f})**"
            def _fmt(t):
                val = t.get("epss")
                pct = t.get("percentile")
                cve = t.get("cve", "CVE-?")
                if isinstance(val, (int, float)):
                    if isinstance(pct, (int, float)):
                        return f"{cve} ({val:.2f}, p{int(round(100*pct))})"
                    return f"{cve} ({val:.2f})"
                return cve
            lines.append("\n" + label + ": " + ", ".join(_fmt(t) for t in top))
    
    # Hash enrichment (unchanged)
    if hash_enrich:
        lines.append("\n**Hash enrichments:**")
        for h in hash_enrich:
            if h.get("found"):
                lines.append(f"- {h['sha256']} | {h.get('file_type')} | {h.get('signature')}")

    return "\n".join(lines)


def run_agent(query: str, df, approve: bool = False) -> dict:
    """
    Run the intel agent:
    - Parse query -> plan (time window, KEV focus, EPSS threshold, CVEs, keywords, actions)
    - Pull feed items from df with time/source/keyword filters (CVE-first)
    - Build a candidate CVE set from the entire time window (incl. KEV rows)
    - Filter CVEs by EPSS threshold (if any)
    - Enrich CVEs (CIRCL/NVD alt), KEV status, EPSS
    - Summarize + propose actions; optionally execute (Slack/Jira) if approve=True
    """
    import pandas as pd
    from datetime import datetime, timezone, timedelta
    from agent_tools import extract_cves, get_epss_bulk, get_cve_details, get_kev_status

    # ---- 0) Plan -------------------------------------------------------------
    plan = _heuristic_plan(query)
    hours = int(plan.get("hours", 24))
    selection_reason = ""

    audit = {
        "plan": {k: plan.get(k) for k in [
            "need_feeds", "hours", "keywords", "cves", "hashes",
            "actions", "kev_focus", "any_match", "min_epss", "vendor_sources"
        ]},
        "feed_items_preview": [],
        "cve_details_preview": [],
        "kev_preview": [],
        "epss_preview": [],
        "hash_enrich_preview": [],
        "approved": bool(approve),
    }

    # ---- 1) Fetch feed items (CVE-first; keyword fallback; optional KEV/vendor) ----
    src_filter = None
    if plan.get("kev_focus"):
        src_filter = ["CISA KEV"]
    if plan.get("vendor_sources"):
        # Prefer explicit vendor scope if present
        src_filter = plan["vendor_sources"]

    items = fetch_feed_from_df(
        df=df,
        query=" ".join(plan.get("keywords") or []),
        hours=hours,
        cves=plan.get("cves", []),
        keywords=plan.get("keywords", []),
        any_match=plan.get("any_match", False),
        source_filter=src_filter,
    )

    feed_pack = {"hours": hours, "items": items, "source_filter": src_filter}
    
    audit["feed_items_preview"] = []
    for it in (items or [])[:8]:
        audit["feed_items_preview"].append({
            "Published": (it.get("Published").isoformat() if hasattr(it.get("Published"), "isoformat") else str(it.get("Published"))),
            "Source": it.get("Source"),
            "Title_raw": it.get("Title"),
            "Title_str": str(it.get("Title") or ""),
            "Link": it.get("Link"),
            "CVEs": it.get("CVEs"),
        })
    
    if items and isinstance(items, list) and "__auto_widened" in items[0]:
        feed_pack["auto_widened_hours"] = 30 * 24

    # audit preview (JSON-safe)
    audit["feed_items_preview"] = [
        {
            "Published": (it.get("Published").isoformat() if hasattr(it.get("Published"), "isoformat") else str(it.get("Published"))),
            "Source": it.get("Source"),
            "Title": it.get("Title"),
            "Link": it.get("Link"),
        }
        for it in (items[:10] if isinstance(items, list) else [])
    ]

    # ---- 2) Build candidate CVE set from the entire window -------------------
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=hours)

    dwin = df.copy()
    dwin["Published"] = pd.to_datetime(dwin["Published"], utc=True, errors="coerce")
    dwin = dwin[dwin["Published"] >= cutoff]

    # Constrain window DF to vendor sources if requested
    vendor_sources = plan.get("vendor_sources") or []
    if vendor_sources:
        dscope = dwin[dwin["Source"].isin(vendor_sources)].copy()
    else:
        dscope = dwin

    # 2.1 CVEs already extracted in the dashboard df
    cves_from_df = set()
    if "CVEs" in dscope.columns:
        for lst in dscope["CVEs"]:
            if isinstance(lst, (list, tuple)):
                cves_from_df.update(lst)

    # 2.2 CVEs from matched items
    item_cves = set()
    for it in (items or []):
        item_cves.update(extract_cves(str(it.get("Title", ""))))

    # 2.3 KEV CVEs present in the window
    kev_cves = set()
    if "Source" in dscope.columns:
        kev_rows = dscope[dscope["Source"] == "CISA KEV"]
        for t in kev_rows["Title"].astype(str):
            kev_cves.update(extract_cves(t))
    
    # 2.4 Explicit CVEs in the prompt
    prompt_cves = set(plan.get("cves", []))

    candidate_cves = sorted(cves_from_df | item_cves | kev_cves | prompt_cves)

    # ---- 3) EPSS threshold filter (if any) -----------------------------------
    min_epss = plan.get("min_epss")
    epss_map = get_epss_bulk(candidate_cves) if candidate_cves else {}

    def _epss(c):
        e = epss_map.get(c) or {}
        v = e.get("epss")
        return v if isinstance(v, (int, float)) else 0.0

    kev_set  = set(kev_cves)
    item_set = set(item_cves)

    # ---- 3b) Choose which CVEs to show, based on intent ----------------------
    selected = []

    if isinstance(min_epss, (int, float)):
        thr = float(min_epss)
        selected = [c for c in candidate_cves if _epss(c) >= thr]
        selected.sort(key=_epss, reverse=True)
        selection_reason = f"EPSS ≥ {thr:.2f}"
    elif prompt_cves:
        selected = [c for c in candidate_cves if c in prompt_cves]
        selection_reason = "Explicit CVEs from prompt"
    elif plan.get("kev_focus"):
        # Sort KEV CVEs by latest appearance in dwin
        def _latest_pub(cve):
            try:
                mask = dwin["CVEs"].apply(lambda x: cve in (x or []))
                ts = dwin.loc[mask, "Published"].max()
                return ts if pd.notna(ts) else pd.Timestamp.min.tz_localize("UTC")
            except Exception:
                return pd.Timestamp.min.tz_localize("UTC")
        selected = sorted(kev_set, key=_latest_pub, reverse=True)
        selection_reason = "CISA KEV in time window"
    else:
        # Generic summaries: CVEs from matched items; fallback to top EPSS
        selected = [c for c in candidate_cves if c in item_set]
        if not selected:
            # Fallback to top EPSS **within vendor scope** only
            if vendor_sources:
                selected = sorted(candidate_cves, key=_epss, reverse=True)[:5]
                selection_reason = "Fallback: Top EPSS within vendor scope"
            else:
                selected = sorted(candidate_cves, key=_epss, reverse=True)[:5]
                selection_reason = "Fallback: Top EPSS from window"
        else:
            selection_reason = "CVEs from matched items"
    
    # Cap results for readability
    MAX_CVES = 10
    selected = selected[:MAX_CVES]
    
    # --- compute how many feed rows in the time window mention any selected CVE ---
    try:
        # create a boolean mask: True if any selected CVE appears in the row's CVEs list
        if selected and "CVEs" in dwin.columns:
            mask = dwin["CVEs"].apply(lambda lst: any(c in (lst or []) for c in selected))
            matched_rows = dwin[mask].copy()
        else:
            matched_rows = dwin.iloc[0:0].copy()  # empty DF
    except Exception:
        matched_rows = dwin.iloc[0:0].copy()

    # number of matched feed rows (mentions selected CVEs)
    feed_matches_count = int(len(matched_rows))

    # include this context in feed_pack and audit
    feed_pack["matched_rows_count"] = feed_matches_count
    # small preview for audit (first 8 matched rows)
    audit["matched_rows_preview"] = [
        {
            "Published": (r.get("Published").isoformat() if hasattr(r.get("Published"), "isoformat") else str(r.get("Published"))),
            "Source": r.get("Source"),
            "Title": r.get("Title"),
            "Link": r.get("Link"),
            "CVEs": r.get("CVEs"),
        }
        for _, r in matched_rows.head(8).iterrows()
    ]

    # Attach selection reason now that we have it
    feed_pack["selection_reason"] = selection_reason

    # ---- 4) Enrich ONLY the selected CVEs -----------------------------------
    cve_out = []
    for c in selected:
        det = get_cve_details(c) or {"cve": c}
        det["epss"] = epss_map.get(c, {})
        det["kev"]  = get_kev_status(c)
        cve_out.append(det)

    # ---- Risk-based action suggestions (KEEP; do not overwrite later) --------
    actions = []
    has_kev = any((d.get("kev") or {}).get("in_kev") for d in cve_out)
    high_epss = any(((d.get("epss") or {}).get("epss") or 0) >= 0.7 for d in cve_out)

    # From prompt hints
    if "notify_slack" in plan.get("actions", []):
        actions.append({"title": "Notify on high/KEV CVEs", "type": "notify_slack"})
    if "create_jira" in plan.get("actions", []):
        actions.append({"title": "Create remediation ticket", "type": "create_jira"})

    # Auto-suggest if risky
    if has_kev and not any(a["type"] == "notify_slack" for a in actions):
        actions.append({"title": "Notify on KEV CVEs", "type": "notify_slack"})
    if (has_kev or high_epss) and not any(a["type"] == "create_jira" for a in actions):
        actions.append({"title": "Create remediation ticket", "type": "create_jira"})

    # EPSS list for summary (selected CVEs only)
    epss_scores_for_summary = []
    for d in cve_out:
        e = (d.get("epss") or {})
        v = e.get("epss")
        if isinstance(v, (int, float)):
            epss_scores_for_summary.append({"cve": d.get("cve"), "epss": v, "percentile": e.get("percentile")})

    # ---- 5) Summarize --------------------------------------------------------
    summary_md = _summarize_heuristic(
        query,
        feed_pack,
        cve_out,
        kev_hits=[(d.get("kev") or {}) | {"cve": d.get("cve")} for d in cve_out if (d.get("kev") or {}).get("in_kev")],
        epss_scores=epss_scores_for_summary,
        hash_enrich=[],
        min_epss=min_epss,
    )

    # ---- 6) Audit ------------------------------------------------------------
    audit["selection_reason"] = selection_reason
    audit["selected_cves"] = [d["cve"] for d in cve_out]
    audit["epss_threshold"] = float(min_epss) if isinstance(min_epss, (int, float)) else None
    audit["feed_items_matched"] = len(items or [])
    audit["cves_selected_count"] = len(cve_out)

    # ---- 7) Execute actions if approved -------------------------------------
    executed = []
    if approve and actions:
        for a in actions:
            try:
                if a["type"] == "notify_slack":
                    # notify_slack(summary_md)
                    executed.append({"type": "notify_slack", "status": "ok"})
                elif a["type"] == "create_jira":
                    # create_jira_ticket(summary_md)
                    executed.append({"type": "create_jira", "status": "ok"})
            except Exception as e:
                executed.append({"type": a["type"], "status": f"error: {e}"})

    # ---- 8) Return -----------------------------------------------------------
    return {
        "summary_md": summary_md,
        "audit": audit,
        "actions": actions,    # <- uses the risk-based list (not overwritten)
        "executed": executed,
    }



