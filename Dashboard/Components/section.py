import streamlit as st


def render(title, subtitle=""):

    st.markdown(
        f"""<div class="section-header">
<div class="section-title">{title}</div>
<div class="section-subtitle">{subtitle}</div>
</div>""",
        unsafe_allow_html=True,
    )