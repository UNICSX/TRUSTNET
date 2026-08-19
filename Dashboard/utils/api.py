import time
import traceback

import streamlit as st
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from coordinator import Coordinator
from phishing_agent import PhishingAgent
from threat_hunter.threat_agent import ThreatHunterAgent
from soc.soc_agent import SOCAgent

phishing = PhishingAgent()
threat = ThreatHunterAgent()
soc = SOCAgent()

coordinator = Coordinator(
    phishing_agent=phishing,
    threat_agent=threat,
    soc_agent=soc,
)


def run_investigation(query: str):
    """
    Entry point called by the dashboard.

    Replace the coordinator call below with your own backend.
    """

    try:

        start = time.time()

        # --------------------------------------------
        # Reset Dashboard State
        # --------------------------------------------

        st.session_state.timeline = []

        st.session_state.runtime = {}

        st.session_state.evidence = {}

        st.session_state.report = None

        st.session_state.current_stage = 0

        # --------------------------------------------
        # Coordinator Running
        # --------------------------------------------

        st.session_state.investigation_running = True

        update_stage(0)

        add_event(
            "🧠 Coordinator",
            "Created investigation plan."
        )

        # --------------------------------------------
        # Execute Real Investigation
        # --------------------------------------------

        result = coordinator.investigate(query)

        # Save the complete report
        report = result.get("executive_report", {})

        st.session_state.report = {
            "overall_risk": result.get("overall_risk", "Unknown"),
            "confidence": f'{result.get("overall_confidence", 0)}%',
            "verdict": report.get("final_verdict", "Pending"),
            "executive_summary": report.get(
                "executive_summary",
                "No executive summary available."
            ),
            "recommendations": report.get(
                "recommended_actions",
                []
            ),
        }

        # Runtime
        runtime = result.get("runtime", {})

        st.session_state.runtime = {
            "agents_executed": runtime.get("completed_agents", 0),
            "tools_executed": runtime.get("tools_executed", 0),
            "plans_generated": runtime.get("plans_generated", 0),
            "runtime": f"{time.time() - start:.2f} sec",
            "confidence": f'{result.get("overall_confidence", 0)}%'
        }

        # --------------------------------------------
        # Evidence
        # --------------------------------------------

        artifacts = result.get("artifacts", {})

        domains = []
        urls = []
        ips = []
        users = []
        processes = []
        other_artifacts = []

        # Include indicators directly from the original investigation case.
        case_text = query or ""

        case_evidence = phishing.extract_case_evidence(
            case_text
        )

        domains.extend(case_evidence.get("domains", []))
        urls.extend(case_evidence.get("urls", []))
        ips.extend(case_evidence.get("ips", []))
        users.extend(case_evidence.get("users", []))

        for key, values in artifacts.items():

            if not isinstance(values, list):
                values = [values]

            for value in values:

                # Flatten nested lists
                if isinstance(value, list):
                    items = value
                else:
                    items = [value]

                for item in items:

                    if key in ["domain", "domains", "sender_domain", "reply_to_domain"]:
                        domains.append(item)

                    elif key in ["url", "urls"]:
                        urls.append(item)

                    elif key in ["ip", "ips", "ip_address", "ip_addresses"]:
                        ips.append(item)

                    elif key in ["user", "users"]:
                        users.append(item)

                    elif key in ["process", "processes"]:
                        processes.append(item)

                    elif key not in [
                        "sender",
                        "reply_to",
                        "attachments",
                        "ioc_count",
                        "attachment_present",
                    ]:
                        other_artifacts.append({
                            key: item
                        })

        # Remove duplicates while preserving order
        domains = list(dict.fromkeys(map(str, domains)))
        urls = list(dict.fromkeys(map(str, urls)))
        ips = list(dict.fromkeys(map(str, ips)))
        users = list(dict.fromkeys(map(str, users)))
        processes = list(dict.fromkeys(map(str, processes)))

        st.session_state.evidence = {
            "domains": domains,
            "urls": urls,
            "ips": ips,
            "users": users,
            "processes": processes,
            "artifacts": other_artifacts,
        }

        # --------------------------------------------
        # Populate Agent Cards
        # --------------------------------------------

        st.session_state.agents = {}

        for wrapper in result.get("wrapper_history", []):

            agent = wrapper.get("agent", "").lower()

            if "phishing" in agent:
                key = "phishing"

            elif "threat" in agent:
                key = "threat"

            elif "soc" in agent:
                key = "soc"

            else:
                continue

            wrapper_status = wrapper.get(
                "status",
                "unknown"
            )

            if wrapper_status == "completed":
                display_status = "Completed"

            elif wrapper_status == "tool_limit_exceeded":
                display_status = "Partial"

            elif wrapper_status == "error":
                display_status = "Failed"

            else:
                display_status = wrapper_status.title()

            agent_result = wrapper.get(
                "result",
                {}
            )

            update_agent(
                name=key,
                status=display_status,
                risk=agent_result.get(
                    "risk",
                    "-"
                ),
                confidence=f'{agent_result.get("confidence", "-")}%',
                summary=agent_result.get(
                    "summary",
                    "No analysis available."
                ),
                tools=wrapper.get(
                    "tools_used",
                    []
                ),
            )

        # --------------------------------------------
        # Populate Timeline
        # --------------------------------------------

        st.session_state.timeline = []

        for event in result.get("execution_graph", []):

            add_event(
                agent=event.get("agent", "Unknown"),
                message=f'{event.get("status", "")}: {event.get("task", "")}'
            )

        # --------------------------------------------
        # Update Live Pipeline
        # --------------------------------------------

        completed = {
            agent.lower()
            for agent in result.get("completed_agents", [])
        }

        failed = {
            agent.lower()
            for agent in result.get("failed_agents",[])
        }
        st.session_state.failed_agents = failed

        # Coordinator always starts
        update_stage(0)

        if "phishing" in completed:
            update_stage(1)

        if "threat" in completed:
            update_stage(2)

        if "soc" in completed:
            update_stage(3)

        # Finish investigation
        st.session_state.completed = True
        st.session_state.investigation_running = False

        return result

    except Exception:

        st.error(traceback.format_exc())

        st.session_state.investigation_running = False

        return None


# ----------------------------------------------------
# Dashboard Helpers
# ----------------------------------------------------

def update_stage(stage):

    st.session_state.current_stage = stage


def update_agent(
    name,
    status,
    risk="-",
    confidence="-",
    summary="",
    tools=None
):

    if tools is None:
        tools = []

    st.session_state.agents[name] = {

        "status": status,

        "risk": risk,

        "confidence": confidence,

        "summary": summary,

        "tools": tools,
    }


def add_event(agent, message):

    from datetime import datetime

    st.session_state.timeline.append({

        "time": datetime.now().strftime("%H:%M:%S"),

        "agent": agent,

        "message": message,
    })