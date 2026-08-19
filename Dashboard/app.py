import streamlit as st
from pathlib import Path
from Components.agent_card import render as render_agents
from Components.executive_report import render as render_report
from Components.timeline import render as render_timeline
from Components.runtime_stats import render as render_runtime
from Components.evidence_panel import render as render_evidence
from Components.download_report import render as render_download
from Components.section import render as section
from datetime import datetime
from zoneinfo import ZoneInfo
from textwrap import dedent
# ============================================
# Page Configuration
# ============================================

st.set_page_config(
    page_title="TRUSTNET",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============================================
# Load CSS
# ============================================

css_path = Path(__file__).parent / "assets" / "style.css"

if css_path.exists():
    with open(css_path, encoding="utf-8") as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

# ============================================
# Session State
# ============================================

defaults = {
    "investigation_running": False,
    "completed": False,
    "current_stage": 0,
    "report": None,
    "timeline": [],
    "runtime": {},
    "evidence": {},
    "agents": {},
    "query": ""
}

for k, v in defaults.items():
    if k not in st.session_state:
        st.session_state[k] = v

# ============================================
# Sidebar
# ============================================

with st.sidebar:

    st.markdown(
        """
        <h2 style='margin-bottom:0'>
         TRUSTNET
        </h2>
        """,
        unsafe_allow_html=True
    )

    st.caption("Multi-Agent Cyber Investigation")

    st.divider()

    st.markdown("### Investigation Status")

    if st.session_state.completed:
        st.success("Completed")
    elif st.session_state.investigation_running:
        st.warning("Running")
    else:
        st.info("Idle")

    st.divider()

    st.markdown("### Agents")

    st.markdown(" Coordinator")

    st.markdown(" Phishing")

    st.markdown(" Threat Hunter")

    st.markdown(" SOC Alert Triage")

    st.divider()

    st.markdown(
        """
        **Version**

        TRUSTNET v1.0

        Enterprise Investigation Console
        """
    )

# ============================================
# Header
# ============================================

@st.fragment(run_every="1s")
def render_header():

    current_time = datetime.now(
        ZoneInfo("Asia/Kolkata")
    ).strftime("%H:%M:%S")

    header_html = (
        '<div class="main-header">'
        '<div class="header-content">'

        '<div class="header-brand">'
        '<h1>TRUSTNET</h1>'
        '<p>Enterprise Multi-Agent Cyber Investigation Platform</p>'
        '</div>'

        '<div class="header-wave">'
        '<div class="wave-line wave-one"></div>'
        '<div class="wave-line wave-two"></div>'
        '<div class="wave-line wave-three"></div>'
        '</div>'

        '<div class="system-time">'
        '<div class="system-label">SYSTEM TIME</div>'
        f'<div class="system-clock">{current_time}</div>'
        '<div class="system-zone">UTC +05:30</div>'
        '</div>'

        '</div>'
        '</div>'
    )

    st.markdown(
        header_html,
        unsafe_allow_html=True
    )


render_header()
# ============================================
# Investigation Section
# ============================================

section(
    "Investigation",
    "Submit an incident for autonomous investigation.",
)

investigation_container = st.container()

from Components.investigation_form import render as render_investigation

from utils.api import run_investigation

with investigation_container:
    render_investigation(run_investigation)


# ============================================
# Agent Cards
# ============================================

section(
    "Specialist Agents",
    "Results from every autonomous agent.",
)

agent_container = st.container()

with agent_container:
    render_agents()

# ============================================
# Executive Report
# ============================================

section(
    "Executive Report",
    "High-level investigation outcome.",
)

report_container = st.container()

with report_container:
    render_report()

# ============================================
# Timeline
# ============================================

left, right = st.columns([2, 1])

with left:

    section(
    "Timeline",
    "Chronological investigation events.",
)

    timeline_container = st.container()

    with timeline_container:
        render_timeline()


with right:

    section(
    "Runtime",
    "Execution metrics.",
)

    runtime_container = st.container()

    with runtime_container:
        render_runtime()

# ============================================
# Evidence
# ============================================

section(
    "Indicators of Compromise",
    "Evidence collected during investigation.",
)

evidence_container = st.container()

with evidence_container:
    render_evidence()

# ============================================
# Download
# ============================================

section(
    "Export Report",
    "Download investigation artifacts.",
)

download_container = st.container()

with download_container:
    render_download()

# ============================================
# Footer
# ============================================

st.markdown(
    """
<div style="text-align:center;
padding:25px;
color:#94A3B8;
font-size:14px;">
TRUSTNET • Enterprise Multi-Agent Investigation Dashboard
</div>
""",
    unsafe_allow_html=True
)