"""
phishing_tool_specs.py

Tool specifications for the Phishing Investigation Agent.
"""

from tool_registry import ToolRegistry

from tools import (
    check_url_reputation,
    extract_email_metadata,
    check_sender_domain_age,
    flag_for_review,
)

registry = ToolRegistry()

# ---------------------------------------------------------
# URL Reputation
# ---------------------------------------------------------

registry.register(
    name="check_url_reputation",
    description="Check whether a URL is suspicious or likely phishing.",
    parameters={
        "type": "object",
        "properties": {
            "url": {
                "type": "string",
                "description": "URL extracted from the email."
            }
        },
        "required": ["url"]
    },
    function=check_url_reputation,
)

# ---------------------------------------------------------
# Email Metadata
# ---------------------------------------------------------

registry.register(
    name="extract_email_metadata",
    description="Analyze sender, reply-to, subject and body for phishing indicators.",
    parameters={
        "type": "object",
        "properties": {
            "sender": {
                "type": "string"
            },
            "reply_to": {
                "type": "string"
            },
            "subject": {
                "type": "string"
            },
            "body": {
                "type": "string"
            }
        },
        "required": [
            "sender",
            "reply_to",
            "subject",
            "body"
        ]
    },
    function=extract_email_metadata,
)

# ---------------------------------------------------------
# Domain Age
# ---------------------------------------------------------

registry.register(
    name="check_sender_domain_age",
    description="Estimate whether the sender's domain appears newly registered.",
    parameters={
        "type": "object",
        "properties": {
            "domain": {
                "type": "string"
            }
        },
        "required": ["domain"]
    },
    function=check_sender_domain_age,
)

# ---------------------------------------------------------
# Human Escalation
# ---------------------------------------------------------

registry.register(
    name="flag_for_review",
    description="Escalate a suspicious email for human review.",
    parameters={
        "type": "object",
        "properties": {
            "email_id": {
                "type": "integer"
            },
            "reason": {
                "type": "string"
            }
        },
        "required": [
            "email_id",
            "reason"
        ]
    },
    function=flag_for_review,
)