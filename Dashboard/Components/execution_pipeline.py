import streamlit as st
import textwrap
STAGES = [
    ("🧠", "Coordinator"),
    ("📧", "Phishing"),
    ("🌐", "Threat Hunter"),
    ("🚨", "SOC Alert Triage")
]


def _status_badge(status: str):
    status = status.lower()

    if status == "completed":
        return '<span class="status-success">Completed</span>'

    if status == "running":
        return '<span class="status-running">Running</span>'

    if status == "waiting":
        return '<span class="status-warning">Waiting</span>'

    if status == "partial":
        return '<span class="status-warning">Partial</span>'

    if status == "failed":
        return '<span class="status-danger">Failed</span>'    

    return '<span class="status-danger">Unknown</span>'


def render():

    current = st.session_state.current_stage
    # st.write("PIPELINE COMPONENT LOADED")

    # # def render():
    # st.markdown(
    #     "<h1 style='color:red'>HELLO TRUSTNET</h1>",
    #     unsafe_allow_html=True,
    # )
    st.markdown(
        """
        <div class="dashboard-card fade-up">
        <h3>⚡ Live Investigation Pipeline</h3>
        <p>Coordinator orchestrates the specialist agents.</p>
        </div>
        """,
        unsafe_allow_html=True
    )

    cols = st.columns(len(STAGES))

    for index, ((icon, name), col) in enumerate(zip(STAGES, cols)):

        with col:

            # if current > index:
            #     status = "Completed"

            # elif current == index and st.session_state.investigation_running:
            #     status = "Running"

            # else:
            #     status = "Waiting"

            if st.session_state.completed:
                status = "Completed"

            elif current > index:
                status = "Completed"

            elif current == index and st.session_state.investigation_running:
                status = "Running"

            else:
                status = "Waiting"

            st.markdown(
                textwrap.dedent(
                    f"""
                    <div class="dashboard-card agent-card"
                        style="text-align:center; min-height:180px;">

                        <div style="font-size:42px;">
                            {icon}
                        </div>

                        <h4 style="margin-bottom:8px;">
                            {name}
                        </h4>

                        {_status_badge(status)}

                    </div>
                    """
                ),
                unsafe_allow_html=True,
            )

    progress = min((current + 1) / len(STAGES), 1.0)
    # st.progress(progress)

    # if progress > 1:
    #     progress = 1.0

    st.progress(progress)