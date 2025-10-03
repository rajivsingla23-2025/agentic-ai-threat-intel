# pages/agent_summary.py — AGENT PAGE
import json
import streamlit as st
from data_pipeline import build_dashboard_df
from vendor_feeds_catalogue import feeds
from agent_runner import run_agent

st.set_page_config(page_title="Agentic AI Summary", layout="wide")

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
section[data-testid="stSidebar"] .element-container {
  margin-bottom: 0rem !important;
  padding-bottom: 0rem !important;
}
section[data-testid="stSidebar"] h1,
section[data-testid="stSidebar"] h2,
section[data-testid="stSidebar"] h3 {
  margin-top: 0rem !important;
  margin-bottom: 0rem !important;
  padding-top: 0rem !important;
  padding-bottom: 0rem !important;
}
section[data-testid="stSidebar"] label {
  margin-bottom: 0rem !important;
  padding-bottom: 0rem !important;
}
section[data-testid="stSidebar"] textarea,
section[data-testid="stSidebar"] input,
section[data-testid="stSidebar"] select {
  margin-top: 0rem !important;
  margin-bottom: 0rem !important;
  padding-top: 0.2rem !important;   /* tiny inner padding so text isn't clipped */
  padding-bottom: 0.2rem !important;
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

st.sidebar.markdown("### Navigation")
st.sidebar.page_link("1_Dashboard.py", label="🛡️ Dashboard")
st.sidebar.page_link("pages/2_Agentic_AI_Summary.py", label="🕵️ Agentic AI Summary")
st.sidebar.divider()

st.title("🕵️ Agentic AI Summary")

# Pull inputs from session (set on the dashboard sidebar)
query = st.session_state.get("agent_query", "").strip()
approve = bool(st.session_state.get("agent_approve", False))

# If nothing in session (e.g., opened page directly), show a tiny fallback input
if not query:
    query = st.text_input("Enter a query (fallback if opened directly):", "")
    approve = st.checkbox("Approve actions (Slack/Jira)", value=False)

@st.cache_data(ttl=15*60)
def get_df_for_agent():
    return build_dashboard_df(
        feeds,
        top_n=600,       # give agent more history within 30 days
        days_back=30,
        enable_page_scrape=False
    )

# @st.cache_data(ttl=15*60)
# def get_df_for_agent():
#    # Give agent more history so 14–30 day windows work better
#    return build_dashboard_df(feeds, top_n=300)

if query:
    df = get_df_for_agent()
    res = run_agent(query, df, approve=approve)

    st.markdown("## 📝 Agent Summary")
    st.markdown(res["summary_md"], unsafe_allow_html=True)

    st.markdown("### Proposed Actions")
    for a in res.get("actions", []):
        st.write(f"- {a['title']} → `{a['type']}`")

    if res.get("executed"):
        st.success("Actions executed:")
        st.json(res["executed"])

    with st.expander("🔍 Agent Audit Trail"):
        # Make JSON safe (handles pandas.Timestamp etc.)
        st.code(json.dumps(res.get("audit", {}), indent=2, default=str))
        
        
    # EPSS legend (handy here too)
    st.markdown("""
    ---
    **ℹ️ EPSS Score & Percentile Guide**

    - **EPSS score** → Probability a CVE will be exploited in the next 30 days (0.0 to 1.0).  
       • Example: `0.94` = 94% likelihood of exploitation.  
    - **Percentile (p)** → Rank among all CVEs by exploit likelihood.  
       • Example: `p100` = top 1% of all CVEs (highest risk). `p91` = top 10% of all CVEs. `p84` = top 17% of all CVEs.

    **How to prioritize**  
    - ✅ **CISA KEV** → Must patch immediately (already exploited).  
    - ⚠️ **EPSS ≥ 0.5 (50%)** → Elevated risk, should prioritize remediation.  
    - 🚨 **EPSS ≥ 0.9 (90%) and p95+** → Critical risk, treat as patch-now even if not in KEV.  
    - 🔒 **CVSS** → Measures potential severity, not exploitation likelihood; use with EPSS/KEV for context.
    ---
    """)
    
else:
    st.info("Use the **🤖 Intel Agent** section on the dashboard sidebar, then click **Run Agent →**.")


    
