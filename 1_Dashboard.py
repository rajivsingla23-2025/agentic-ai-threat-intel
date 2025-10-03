# threatdashboard3.py  — MAIN DASHBOARD ONLY
import os
import re
import pandas as pd
import streamlit as st
from datetime import datetime, timezone
from streamlit_autorefresh import st_autorefresh

# Shared pipeline & feeds (you created these earlier)
from data_pipeline import build_dashboard_df
from vendor_feeds_catalogue import feeds  # your central feeds dict

st.set_page_config(page_title="Threat Intel Dashboard", layout="wide")

st.markdown("""
<style>
/* 1) Hide the default header & toolbar (removes a big top band) */
header[data-testid="stHeader"] { display: none !important; }
div[data-testid="stToolbar"] { display: none !important; }

/* 2) Main content: remove top/bottom padding + compact headings */
main .block-container {
  padding-top: 0rem !important;
  padding-bottom: 0rem !important;
}
main h1, main h2, main h3, main h4 {
  margin-top: 0rem !important;
  margin-bottom: 0.25rem !important;
}

/* 3) Sidebar: remove container padding and all gaps between widgets */
section[data-testid="stSidebar"] .block-container {
  padding-top: 0rem !important;
  padding-bottom: 0rem !important;
}
section[data-testid="stSidebar"] hr {
  margin-top: 1px !important;
  margin-bottom: 1px !important;
}
section[data-testid="stSidebar"] .element-container {
  margin-bottom: 0rem !important;
  padding-bottom: 0rem !important;
}

/* Sidebar headers – compact by default */
section[data-testid="stSidebar"] h1,
section[data-testid="stSidebar"] h2,
section[data-testid="stSidebar"] h3 {
  font-size: 0.9rem !important;     /* compact font size */
  margin-top: 0rem !important;
  margin-bottom: 0rem !important;
  padding-top: 0rem !important;
  padding-bottom: 0rem !important;
}

/* Labels (like "Search Keyword") – smaller */
section[data-testid="stSidebar"] label {
  font-size: 0.85rem !important;
  margin-bottom: 0rem !important;
  padding-bottom: 0rem !important;
}

/* Inputs, text areas, select – smaller font & compact padding */
section[data-testid="stSidebar"] textarea,
section[data-testid="stSidebar"] input,
section[data-testid="stSidebar"] select {
  font-size: 0.85rem !important;
  margin-top: 0rem !important;
  margin-bottom: 0rem !important;
  padding-top: 0.2rem !important;   /* tiny inner padding so text isn't clipped */
  padding-bottom: 0.2rem !important;
  height: auto !important;
}

/* Multiselect tags – compact */
section[data-testid="stSidebar"] .stMultiSelect div[data-baseweb="tag"] {
  font-size: 0.8rem !important;
  padding: 0rem 0.3rem !important;
}

/* 4) Kill extra vertical rhythm added by emotion cache wrappers */
div[class*="st-emotion-cache"] {
  margin-top: 0rem !important;
  margin-bottom: 0rem !important;
  padding-top: 0rem !important;
  padding-bottom: 0rem !important;
}

/* 5) Tables / markdown spacing tightened subtly */
main .markdown-text-container p { margin: 0.25rem 0 !important; }
main .markdown-text-container ul { margin: 0.25rem 0 0.25rem 1rem !important; }
</style>
""", unsafe_allow_html=True)


# Hide Streamlit's default multipage nav ("Pages") from the sidebar
st.markdown("""
<style>
/* Works across recent Streamlit versions */
section[data-testid="stSidebar"] [data-testid="stSidebarNav"] { display: none; }
</style>
""", unsafe_allow_html=True)

# Auto-refresh every 15 minutes (900,000 ms)
st_autorefresh(interval=15 * 60 * 1000, key="refresh_dashboard")

st.title("🛡️ Cyber Threat Intelligence Dashboard 🛡️")

# --- Manual Refresh Button ---
if st.button("🔄 Refresh Now"):
    try:
        st.rerun()
    except AttributeError:
        st.experimental_rerun()

# -----------------------------
# HELPERS (local)
# -----------------------------

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)

def extract_cves_text(s: str) -> list[str]:
    return list(dict.fromkeys(CVE_RE.findall(s or "")))


# (Optional) threat actor tagging for quick glance
THREAT_ACTORS = [
    "APT28", "APT29", "Lazarus", "Conti", "FIN7", "REvil", "LockBit",
    "TA505", "Sandworm", "Turla", "Cobalt Group", "DarkSide", "Clop",
    "APT1", "APT3", "APT10", "APT33", "APT34", "APT35", "APT41",
    "Mustang Panda", "Hafnium", "Gamaredon", "Kimsuky", "Andariel", "BlueNoroff", "MuddyWater",
    "BlackCat", "ALPHV", "Vice Society", "Royal", "Black Basta", "Ragnar Locker", "Maze",
    "FIN4", "FIN6", "FIN8", "FIN11", "Evil Corp",
    "UNC2452", "Lapsus$", "Killnet",
]

def tag_threat_actor(text: str):
    t = (text or "").lower()
    for actor in THREAT_ACTORS:
        if actor.lower() in t:
            return actor
    return None

# -----------------------------
# Build DataFrame (shared pipeline)
# -----------------------------

@st.cache_data(ttl=15*60)
def get_df():
    # true 30-day coverage + cap at 100 for speed
    return build_dashboard_df(
        feeds,
        top_n=100,
        days_back=30,
        enable_page_scrape=False,   # set True if you want the fallback
        scrape_limit=8
    )

# @st.cache_data(ttl=15 * 60)
# def get_df():
#    # Top N for dashboard view; agent page builds its own (larger) df
#    return build_dashboard_df(feeds, top_n=100)

df = get_df()

# Basic enrichment used only for display (no external API here)
# df["CVEs"] = df["Title"].apply(extract_cves)
df["Threat Actor"] = df["Title"].apply(tag_threat_actor)


# -----------------------------
# Sidebar filters
# -----------------------------

# --- Sidebar: Intel Agent (inputs only; results shown on Agent page) ---
st.sidebar.markdown("### Navigation")
st.sidebar.page_link("1_Dashboard.py", label="🛡️ Dashboard")
st.sidebar.page_link("pages/2_Agentic_AI_Summary.py", label="🕵️ Agentic AI Summary")
st.sidebar.divider()


# --- Sidebar: Intel Agent (inputs only; results shown on Agent page) ---
st.sidebar.markdown("## 🕵️ Intel Agent")

# Agent query input with better default
agent_query = st.sidebar.text_area(
    "Query the agent:",
    value=st.session_state.get("agent_query", "Show CVEs with EPSS above 0.7 (High Risk) in last 14 days")
)

# Sample Query Examples (static text)
with st.sidebar.expander("Sample Query Examples", expanded=False):
    st.markdown("""
<style>
/* Shrink the expander title */
.streamlit-expanderHeader {
    font-size: 0.8rem !important;   /* smaller font size */
    font-weight: 500 !important;    /* optional: make it less bold */
}

/* Ultra compact list for Query Examples */
.query-examples ul {
    list-style-position: inside !important;
    margin: 0.1rem 0 !important;
    padding-left: 0rem !important;
}
.query-examples li {
    font-size: 0.7rem !important;
    line-height: 1rem !important;
    margin: 0.1rem 0 !important;
}
.query-examples code {
    font-size: 0.7rem !important;
    background: #f7f7f7 !important;
    padding: 0.05rem 0.25rem !important;
    border-radius: 2px !important;
}
</style>
<div class="query-examples">
<ul>
<li><code>Summarize all CVEs from last 72 hours or 3 days</code></li>
<li><code>Summarize CVEs with EPSS above 0.7 (High Risk) in last 1 month</code></li>
<li><code>Summarize specific CVE-XXXX-XXXXXX</code></li>
<li><code>List KEV vulnerabilities added this week</code></li>
<li><code>Summarize Cisco or Palo Alto vulnerabilities from last 5 days</code></li>
</ul>
</div>
""", unsafe_allow_html=True)

# Approve flag (sticky in session state)
approve = st.sidebar.checkbox(
    "Approve actions (Slack/Jira)",
    value=st.session_state.get("agent_approve", False),
    help="Leave unchecked to run in shadow mode"
)

# Run button → goes to agent page
if st.sidebar.button("Run Agent →"):
    st.session_state["agent_query"] = agent_query
    st.session_state["agent_approve"] = approve
    st.switch_page("pages/2_Agentic_AI_Summary.py")

st.sidebar.header("🔍 Search & Filters")

keyword_filter = st.sidebar.text_input("Search Keyword")
actors_available = sorted([a for a in df["Threat Actor"].dropna().unique().tolist()])
actor_filter = st.sidebar.multiselect("Threat Actor", actors_available)

# Apply filters
filtered_df = df.copy()
if keyword_filter:
    filtered_df = filtered_df[filtered_df["Title"].str.contains(keyword_filter, case=False, na=False)]
if actor_filter:
    filtered_df = filtered_df[filtered_df["Threat Actor"].isin(actor_filter)]

# -----------------------------
# Display
# -----------------------------
st.write("### Latest Top 100 Threat Intel Feeds (with CVE & Actor tags)")
st.write("Click on titles to open the original report/sample.")

# Make titles clickable (Markdown format)
filtered_df = filtered_df.copy()
filtered_df["Title"] = filtered_df.apply(lambda r: f"[{r['Title']}]({r['Link']})", axis=1)

# Show a concise table
st.write(
    filtered_df[["Published", "Source", "Title", "Threat Actor", "CVEs"]]
    .reset_index(drop=True)
    .to_markdown(index=False)
)

# Download
st.download_button(
    "Download as CSV",
    filtered_df.to_csv(index=False),
    "threat_intel_enriched.csv",
    "text/csv"
)



