import streamlit as st


def _badge(level):

    level = str(level).lower()

    if level in ["critical", "high"]:
        css = "status-danger"

    elif level in ["medium", "moderate"]:
        css = "status-warning"

    elif level in ["low"]:
        css = "status-success"

    else:
        css = "status-running"

    return f'<span class="{css}">{level.title()}</span>'


def render():

    report = st.session_state.report

    if report is None:

        st.markdown(
            """
            <div class="dashboard-card fade-up">

            <h3>Executive Report</h3>

            <p>
            Run an investigation to generate the executive report.
            </p>

            </div>
            """,
            unsafe_allow_html=True,
        )

        return

    executive_summary = report.get(
        "executive_summary",
        "No executive summary available."
    )

    overall_risk = report.get("overall_risk", "Unknown")

    confidence = report.get(
        "confidence",
        "-"
    )

    verdict = report.get(
        "verdict",
        "Pending"
    )

    recommendations = report.get(
        "recommendations",
        []
    )

    st.markdown(
        f"""
<div class="dashboard-card fade-up">

<h2 style="margin-bottom:10px;">
Executive Report
</h2>

<hr style="border:1px solid #334155;">

<h4>Overall Risk</h4>

{_badge(overall_risk)}

<br><br>

<h4>Confidence</h4>

<p style="font-size:18px;">
<b>{confidence}</b>
</p>

<h4>Final Verdict</h4>

<p style="font-size:20px;font-weight:600;">
{verdict}
</p>

<h4>Executive Summary</h4>

<p>
{executive_summary}
</p>

</div>
""",
        unsafe_allow_html=True,
    )

    if recommendations:

        st.markdown("### Recommended Actions")

        for rec in recommendations:

            st.markdown(
                f"""
<div class="dashboard-card recommendation-card">

{rec}

</div>
""",
                unsafe_allow_html=True,
            )