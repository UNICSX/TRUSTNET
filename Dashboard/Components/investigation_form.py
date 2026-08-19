import streamlit as st
from utils.api import run_investigation


def render(run_callback=None):
    """
    Incident Description Panel

    Parameters
    ----------
    run_callback : function
        Function that starts the backend investigation.
        Example:
            run_callback(query)
    """

    st.markdown(
        """
        <div class="dashboard-card fade-up">
        <h3 style="margin-bottom:5px;">Start New Investigation</h3>
        <p style="margin-top:0;">
        Submit an email, URL, IOC, alert, or incident description.
        TRUSTNET will coordinate all specialist agents automatically.
        </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if "query" not in st.session_state:
        st.session_state.query = ""

    st.session_state.query = st.text_area(
        "Investigation input",
        value=st.session_state.query,
        placeholder="""
Example:

Received an email from support@micros0ft-security.com asking users to
verify their Office365 credentials immediately.

The email contains:

https://micros0ft-login-security.xyz

Please investigate whether this is a phishing campaign.
""",
        height=220,
        label_visibility="collapsed",
    )

    left, right = st.columns([5, 1])

    with left:

        if st.session_state.query.strip():

            st.success(" Investigation input ready")

        else:

            st.info("Enter an investigation request to continue.")

    with right:

        start = st.button(
            " Start Investigation",
            use_container_width=True,
            type="primary",
        )

    if start:

        if not st.session_state.query.strip():

            st.warning("Please enter an investigation request.")

            st.stop()

        st.session_state.investigation_running = True
        st.session_state.completed = False
        st.session_state.current_stage = 0

        st.session_state.timeline = []
        st.session_state.runtime = {}
        st.session_state.evidence = {}
        st.session_state.agents = {}
        st.session_state.report = None

        if run_callback is not None:

            with st.spinner("Launching multi-agent investigation..."):

                result = run_callback(st.session_state.query)

            # if result is not None:

            #     st.session_state.report = result
            # result = run_callback(st.session_state.query)
            st.session_state.completed = True
            st.session_state.investigation_running = False

            st.success("Investigation completed successfully.")

        else:

            st.info(
                "Backend callback not connected yet.\n"
                "UI state initialized successfully."
            )