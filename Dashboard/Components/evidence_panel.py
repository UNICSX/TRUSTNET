import streamlit as st


def _render_section(title, items):
    """
    Render a single IOC category.
    """

    st.markdown(
        f"""
<div class="dashboard-card">

<h4>{title}</h4>

</div>
""",
        unsafe_allow_html=True,
    )

    if not items:
        st.info(f"No {title.lower()} identified.")
        return

    for item in items:
        st.markdown(
            f"""
            <div class="ioc-value">
                {item}
            </div>
            """,
            unsafe_allow_html=True,
        )


def render():

    evidence = st.session_state.evidence

    domains = evidence.get("domains", [])
    urls = evidence.get("urls", [])
    ips = evidence.get("ips", [])
    users = evidence.get("users", [])
    processes = evidence.get("processes", [])
    artifacts = evidence.get("artifacts", [])

    st.markdown(
        """
<div class="dashboard-card fade-up">

<h3>Indicators of Compromise</h3>

<p>
Evidence collected by all specialist agents during the investigation.
</p>

</div>
""",
        unsafe_allow_html=True,
    )

    col1, col2 = st.columns(2)

    with col1:

        _render_section("Domains", domains)

        _render_section("IP Addresses", ips)

        _render_section("Users", users)

    with col2:

        _render_section("URLs", urls)

        _render_section("Processes", processes)

        _render_section("Artifacts", artifacts)