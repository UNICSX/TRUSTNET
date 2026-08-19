"""
soc_tools.py

Mock tools for the SOC Alert Triage Agent.
These simulate investigations that a SOC analyst would normally perform.
"""

import random


# ---------------------------------------------------------
# Parent Process Lookup
# ---------------------------------------------------------

def get_parent_process(process_name: str):

    mapping = {
        "powershell.exe": "WINWORD.EXE",
        "cmd.exe": "explorer.exe",
        "rundll32.exe": "explorer.exe",
        "unknown.exe": "powershell.exe",
    }

    return {
        "process": process_name,
        "parent_process": mapping.get(
            process_name,
            "explorer.exe"
        )
    }


# ---------------------------------------------------------
# Process Hash Reputation
# ---------------------------------------------------------

def check_process_hash(hash_value: str):

    malicious_hashes = {
        "ABC123XYZ": "Known Emotet Malware",
        "DEF456AAA": "Known Cobalt Strike Beacon",
    }

    if hash_value in malicious_hashes:

        return {
            "hash": hash_value,
            "reputation": "malicious",
            "reason": malicious_hashes[hash_value],
        }

    return {
        "hash": hash_value,
        "reputation": "clean",
    }


# ---------------------------------------------------------
# User Activity
# ---------------------------------------------------------

def get_user_activity(user: str):

    return {
        "user": user,
        "failed_logins": random.randint(0, 10),
        "vpn_usage": random.choice([True, False]),
        "recent_alerts": random.randint(0, 5),
    }


# ---------------------------------------------------------
# Asset Criticality
# ---------------------------------------------------------

def get_asset_criticality(host: str):

    mapping = {
        "HR-PC01": "Medium",
        "FIN-SERVER": "Critical",
        "CEO-LAPTOP": "Critical",
        "DEV-12": "Low",
    }

    return {
        "host": host,
        "criticality": mapping.get(host, "Medium"),
    }


# ---------------------------------------------------------
# Previous Alerts
# ---------------------------------------------------------

def lookup_previous_alerts(host: str):

    mapping = {
        "HR-PC01": 6,
        "FIN-SERVER": 11,
        "DEV-12": 1,
    }

    return {
        "host": host,
        "previous_alerts": mapping.get(host, 0),
    }


# ---------------------------------------------------------
# Escalate Alert
# ---------------------------------------------------------

def escalate_alert(reason: str):

    return {
        "status": "Escalated",
        "severity": "High",
        "reason": reason,
    }


# ---------------------------------------------------------
# Tool Registry
# ---------------------------------------------------------

TOOL_FUNCTIONS = {
    "get_parent_process": get_parent_process,
    "check_process_hash": check_process_hash,
    "get_user_activity": get_user_activity,
    "get_asset_criticality": get_asset_criticality,
    "lookup_previous_alerts": lookup_previous_alerts,
    "escalate_alert": escalate_alert,
}