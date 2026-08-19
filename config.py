"""
config.py

Global configuration for the Cybersecurity Multi-Agent Framework.
"""

# ==========================================================
# Common Agent Configuration
# ==========================================================

MAX_AGENT_STEPS = 8

TEMPERATURE = 0.2

MAX_OUTPUT_TOKENS = 1024

MAX_TOOL_CALLS = 10

MAX_RETRIES = 3




# -------------------------------------------------------------
# Agent Name Aliases
# -------------------------------------------------------------

AGENT_ALIASES = {
    # Phishing
    "phishing": "phishing",
    "phishing investigation agent": "phishing",

    # Threat
    "threat": "threat",
    "threat hunter": "threat",
    "threat hunting agent": "threat",

    # SOC
    "soc": "soc",
    "soc alert triage agent": "soc",
}

# ==========================================================
# Models
# ==========================================================

COORDINATOR_MODEL = "openai/gpt-oss-20b"

PHISHING_MODEL = "openai/gpt-oss-20b"

THREAT_MODEL = "openai/gpt-oss-20b"

SOC_MODEL = "openai/gpt-oss-20b"

REPORT_MODEL = "openai/gpt-oss-20b"

# ==========================================================
# Environment Variable Names
# (actual keys remain in .env)
# ==========================================================

COORDINATOR_API_ENV = "GROQ_COORDINATOR_KEY"

PHISHING_API_ENV = "GROQ_PHISHING_KEY"

THREAT_API_ENV = "GROQ_THREAT_KEY"

SOC_API_ENV = "GROQ_SOC_KEY"    
