import streamlit as st


def _status_color(status):

    status = status.lower()

    if status == "completed":
        return "status-success"

    if status == "running":
        return "status-running"

    if status == "waiting":
        return "status-warning"

    if status == "partial":
        return "status-warning"

    if status == "failed":
        return "status-danger"

    return "status-danger"


def render_agent(
    title,
    status="Waiting",
    risk="-",
    confidence="-",
    summary="No analysis yet.",
    tools=None,
):

    if tools is None:
        tools = []

    badge = _status_color(status)

    tools_html = ""

    if len(tools) == 0:

        tools_html = "<li>No tools executed</li>"

    else:

        for tool in tools:

            tools_html += f"<li>{tool}</li>"

    st.markdown(
        f"""
<div class="dashboard-card agent-card">

<div style="display:flex;
justify-content:space-between;
align-items:center;">

<div>

<h3 style="margin:0;">
{title}
</h3>

</div>

<div>

<span class="{badge}">
{status}
</span>

</div>

</div>

<hr style="border:1px solid #334155;">

<b>Risk</b>

<p>{risk}</p>

<b>Confidence</b>

<p>{confidence}</p>

<b>Summary</b>

<p>{summary}</p>

<b>Tools Executed</b>

<ul>

{tools_html}

</ul>

</div>
""",
        unsafe_allow_html=True,
    )


def render():

    agents = st.session_state.agents

    phishing = agents.get(
        "phishing",
        {
            "status": "Waiting",
            "risk": "-",
            "confidence": "-",
            "summary": "Waiting for investigation.",
            "tools": [],
        },
    )

    threat = agents.get(
        "threat",
        {
            "status": "Waiting",
            "risk": "-",
            "confidence": "-",
            "summary": "Waiting for investigation.",
            "tools": [],
        },
    )

    soc = agents.get(
        "soc",
        {
            "status": "Waiting",
            "risk": "-",
            "confidence": "-",
            "summary": "Waiting for investigation.",
            "tools": [],
        },
    )

    col1, col2, col3 = st.columns(3)

    with col1:

        render_agent(
            "Phishing Agent",
            phishing["status"],
            phishing["risk"],
            phishing["confidence"],
            phishing["summary"],
            phishing["tools"],
        )

    with col2:

        render_agent(
            "Threat Hunter",
            threat["status"],
            threat["risk"],
            threat["confidence"],
            threat["summary"],
            threat["tools"],
        )

    with col3:

        render_agent(
            "SOC Alert Triage",
            soc["status"],
            soc["risk"],
            soc["confidence"],
            soc["summary"],
            soc["tools"],
        )