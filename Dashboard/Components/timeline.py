import streamlit as st
from datetime import datetime


def add_event(agent, message):
    """
    Adds a new event to the investigation timeline.
    """

    if "timeline" not in st.session_state:
        st.session_state.timeline = []

    st.session_state.timeline.append(
        {
            "time": datetime.now().strftime("%H:%M:%S"),
            "agent": agent,
            "message": message,
        }
    )


def render():

    timeline = st.session_state.timeline

    st.markdown(
        """
        <div class="dashboard-card fade-up">
            <h3>Investigation Timeline</h3>
            <p>Chronological execution of the investigation.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if len(timeline) == 0:

        st.info("No investigation events yet.")

        return

    for event in timeline:

        st.markdown(
            f"""
<div class="dashboard-card timeline-item">

<div style="display:flex;
justify-content:space-between;
align-items:center;">

<div>

<b>{event["time"]}</b>

</div>

<div>

<b>{event["agent"]}</b>

</div>

</div>

<div style="margin-top:10px;">

{event["message"]}

</div>

</div>
""",
            unsafe_allow_html=True,
        )