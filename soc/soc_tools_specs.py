"""
soc_tool_specs.py

Tool specifications for the SOC Alert Triage Agent.
"""

from tool_registry import ToolRegistry

from soc.soc_tools import (
    get_parent_process,
    check_process_hash,
    get_user_activity,
    get_asset_criticality,
    lookup_previous_alerts,
    escalate_alert,
)

registry = ToolRegistry()

# ---------------------------------------------------------
# Parent Process
# ---------------------------------------------------------

registry.register(
    name="get_parent_process",
    description="Retrieve the parent process of a suspicious process.",
    parameters={
        "type": "object",
        "properties": {
            "process_name": {
                "type": "string",
                "description": "Name of the suspicious process."
            }
        },
        "required": ["process_name"]
    },
    function=get_parent_process,
)

# ---------------------------------------------------------
# Process Hash Reputation
# ---------------------------------------------------------

registry.register(
    name="check_process_hash",
    description="Check whether a process hash is known to be malicious.",
    parameters={
        "type": "object",
        "properties": {
            "hash_value": {
                "type": "string",
                "description": "Hash of the executable."
            }
        },
        "required": ["hash_value"]
    },
    function=check_process_hash,
)

# ---------------------------------------------------------
# User Activity
# ---------------------------------------------------------

registry.register(
    name="get_user_activity",
    description="Retrieve recent security-related activity for a user.",
    parameters={
        "type": "object",
        "properties": {
            "user": {
                "type": "string",
                "description": "Username to investigate."
            }
        },
        "required": ["user"]
    },
    function=get_user_activity,
)

# ---------------------------------------------------------
# Asset Criticality
# ---------------------------------------------------------

registry.register(
    name="get_asset_criticality",
    description="Determine the business criticality of a host.",
    parameters={
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Hostname to investigate."
            }
        },
        "required": ["host"]
    },
    function=get_asset_criticality,
)

# ---------------------------------------------------------
# Previous Alerts
# ---------------------------------------------------------

registry.register(
    name="lookup_previous_alerts",
    description="Retrieve historical alerts associated with a host.",
    parameters={
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Hostname to investigate."
            }
        },
        "required": ["host"]
    },
    function=lookup_previous_alerts,
)

# ---------------------------------------------------------
# Escalation
# ---------------------------------------------------------

registry.register(
    name="escalate_alert",
    description="Escalate a confirmed security incident to the SOC.",
    parameters={
        "type": "object",
        "properties": {
            "reason": {
                "type": "string",
                "description": "Reason for escalation."
            }
        },
        "required": ["reason"]
    },
    function=escalate_alert,
)