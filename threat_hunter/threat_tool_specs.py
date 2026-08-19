from tool_registry import ToolRegistry

from threat_hunter.threat_tools import (
    get_running_processes,
    get_network_connections,
    check_ip_reputation,
    check_startup_registry,
    get_login_history,
    lookup_mitre_attack,
    escalate_incident,
)

registry = ToolRegistry()

# ---------------------------------------------------------
# Running Processes
# ---------------------------------------------------------

registry.register(
    name="get_running_processes",
    description="Retrieve all running processes on a host.",
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
    function=get_running_processes,
)

# ---------------------------------------------------------
# Network Connections
# ---------------------------------------------------------

registry.register(
    name="get_network_connections",
    description="Retrieve active outbound network connections.",
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
    function=get_network_connections,
)

# ---------------------------------------------------------
# IP Reputation
# ---------------------------------------------------------

registry.register(
    name="check_ip_reputation",
    description="Check whether an IP address is malicious.",
    parameters={
        "type": "object",
        "properties": {
            "ip": {
                "type": "string",
                "description": "IP address."
            }
        },
        "required": ["ip"]
    },
    function=check_ip_reputation,
)

# ---------------------------------------------------------
# Startup Registry
# ---------------------------------------------------------

registry.register(
    name="check_startup_registry",
    description="Inspect startup programs configured on the endpoint.",
    parameters={
        "type": "object",
        "properties": {
            "host": {
                "type": "string"
            }
        },
        "required": ["host"]
    },
    function=check_startup_registry,
)

# ---------------------------------------------------------
# Login History
# ---------------------------------------------------------

registry.register(
    name="get_login_history",
    description="Retrieve recent login history for a user.",
    parameters={
        "type": "object",
        "properties": {
            "user": {
                "type": "string"
            }
        },
        "required": ["user"]
    },
    function=get_login_history,
)

# ---------------------------------------------------------
# MITRE ATT&CK
# ---------------------------------------------------------

registry.register(
    name="lookup_mitre_attack",
    description="Map an indicator to the MITRE ATT&CK framework.",
    parameters={
        "type": "object",
        "properties": {
            "indicator": {
                "type": "string"
            }
        },
        "required": ["indicator"]
    },
    function=lookup_mitre_attack,
)

# ---------------------------------------------------------
# Escalation
# ---------------------------------------------------------

registry.register(
    name="escalate_incident",
    description="Escalate the investigated incident to the SOC.",
    parameters={
        "type": "object",
        "properties": {
            "reason": {
                "type": "string"
            }
        },
        "required": ["reason"]
    },
    function=escalate_incident,
)