import json
import streamlit as st


def render():

    report = st.session_state.report

    st.markdown(
        """
        <div class="dashboard-card fade-up">

        <h3>Investigation Report</h3>

        <p>
        Export the complete investigation report for auditing,
        incident response, or compliance.
        </p>

        </div>
        """,
        unsafe_allow_html=True,
    )

    if report is None:

        st.info("No report available yet.")

        return

    report_json = json.dumps(
        report,
        indent=4,
        ensure_ascii=False
    )

    st.download_button(
        label="Download Investigation Report",
        data=report_json,
        file_name="final_report.json",
        mime="application/json",
        use_container_width=True,
    )

    with st.expander("Preview Report"):

        st.json(report)