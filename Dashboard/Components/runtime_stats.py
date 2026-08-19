import streamlit as st


def render():

    runtime = st.session_state.runtime

    agents_executed = runtime.get("agents_executed", 0)
    tools_executed = runtime.get("tools_executed", 0)
    runtime_seconds = runtime.get("runtime", "0.0 s")
    plans_generated = runtime.get("plans_generated", 0)
    confidence = runtime.get("confidence", "-")

    st.markdown(
        """
        <div class="dashboard-card fade-up">
            <h3> Runtime Statistics</h3>
            <p>Live investigation metrics.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    col1, col2 = st.columns(2)

    with col1:
        st.metric("Agents", agents_executed)

    with col2:
        st.metric("Tools", tools_executed)

    col3, col4 = st.columns(2)

    with col3:
        st.metric("Plans", plans_generated)

    with col4:
        st.metric("Confidence", confidence)

    st.metric("Runtime", runtime_seconds)