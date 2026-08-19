import random


# ---------------------------------------------------------
# 1. Get Running Processes
# ---------------------------------------------------------

def get_running_processes(host: str):
    suspicious_hosts = {
        "HR-PC01": [
            "WINWORD.EXE",
            "powershell.exe",
            "cmd.exe"
        ],
        "WS-102": [
            "chrome.exe",
            "teams.exe",
            "svchost.exe"
        ],
        "WS-205": [
            "explorer.exe",
            "updater.exe",
            "unknown.exe"
        ]
    }

    return {
        "host": host,
        "processes": suspicious_hosts.get(
            host,
            ["explorer.exe", "chrome.exe", "svchost.exe"]
        )
    }


# ---------------------------------------------------------
# 2. Network Connections
# ---------------------------------------------------------

def get_network_connections(host: str):
    data = {
        "FIN-SERVER": [
            "185.243.115.84",
            "10.0.0.5"
        ],
        "HR-PC01": [
            "45.77.201.15"
        ],
        "WS-102": [
            "172.217.160.78"
        ]
    }

    return {
        "host": host,
        "connections": data.get(host, [])
    }


# ---------------------------------------------------------
# 3. IP Reputation
# ---------------------------------------------------------

def check_ip_reputation(ip: str):

    malicious_ips = {
        "185.243.115.84": "Known Command-and-Control Server",
        "45.77.201.15": "Associated with Malware Distribution"
    }

    if ip in malicious_ips:
        return {
            "ip": ip,
            "reputation": "malicious",
            "reason": malicious_ips[ip]
        }

    return {
        "ip": ip,
        "reputation": "clean"
    }


# ---------------------------------------------------------
# 4. Startup Persistence
# ---------------------------------------------------------

def check_startup_registry(host: str):

    suspicious = {
        "WS-205": [
            "unknown.exe"
        ]
    }

    return {
        "host": host,
        "startup_items": suspicious.get(host, [])
    }


# ---------------------------------------------------------
# 5. Failed Login History
# ---------------------------------------------------------

def get_login_history(user: str):

    if user == "charlie":
        return {
            "user": user,
            "failed_attempts": 17,
            "successful_login": True
        }

    return {
        "user": user,
        "failed_attempts": random.randint(0, 2),
        "successful_login": True
    }


# ---------------------------------------------------------
# 6. MITRE ATT&CK Mapping
# ---------------------------------------------------------

def lookup_mitre_attack(indicator: str):

    mapping = {
        "powershell.exe": {
            "technique": "T1059",
            "name": "Command and Scripting Interpreter"
        },
        "unknown.exe": {
            "technique": "T1547",
            "name": "Boot or Logon Autostart Execution"
        },
        "185.243.115.84": {
            "technique": "T1071",
            "name": "Application Layer Protocol"
        }
    }

    return mapping.get(
        indicator,
        {
            "technique": "Unknown",
            "name": "No Mapping Found"
        }
    )


# ---------------------------------------------------------
# 7. Escalate Incident
# ---------------------------------------------------------

def escalate_incident(reason: str):

    return {
        "status": "Escalated",
        "severity": "High",
        "reason": reason
    }


# ---------------------------------------------------------
# Tool Registry
# ---------------------------------------------------------

TOOL_FUNCTIONS = {
    "get_running_processes": get_running_processes,
    "get_network_connections": get_network_connections,
    "check_ip_reputation": check_ip_reputation,
    "check_startup_registry": check_startup_registry,
    "get_login_history": get_login_history,
    "lookup_mitre_attack": lookup_mitre_attack,
    "escalate_incident": escalate_incident,
}