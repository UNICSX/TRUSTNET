"""
=========================================================
Agent Communication Protocol (ACP)
=========================================================

Defines the standard communication protocol used by all
specialist agents and the Coordinator Agent.

Every specialist returns an ACPResponse object.

The Coordinator receives ACPResponse objects, aggregates
them, and optionally converts them to JSON for storage or
display.

=========================================================
"""

from dataclasses import dataclass, field, asdict
from typing import Dict, Any, List
import json


# =========================================================
# Standard Risk Levels
# =========================================================

RISK_LOW = "Low"
RISK_MEDIUM = "Medium"
RISK_HIGH = "High"
RISK_CRITICAL = "Critical"

VALID_RISKS = {
    RISK_LOW,
    RISK_MEDIUM,
    RISK_HIGH,
    RISK_CRITICAL,
}


# =========================================================
# Confidence Limits
# =========================================================

MIN_CONFIDENCE = 0
MAX_CONFIDENCE = 100


# =========================================================
# ACP Message Object
# =========================================================

@dataclass
class ACPMessage:
    """
    Standard task sent from the Coordinator to a specialist agent.
    """

    sender: str
    recipient: str
    task: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(
            self.to_dict(),
            indent=4,
            ensure_ascii=False,
        )

    @classmethod
    def from_dict(cls, data: Dict[str, Any]):
        return cls(**data)

    @classmethod
    def from_json(cls, json_string: str):
        return cls.from_dict(
            json.loads(json_string)
        )




# =========================================================
# ACP Response Object
# =========================================================

@dataclass
class ACPResponse:
    """
    Standard response exchanged between specialist agents
    and the Coordinator.
    """

    # Reporting agent
    agent: str

    # Executive summary
    summary: str

    # Confidence (0-100)
    confidence: int

    # Risk classification
    risk: str

    # Recommended execution plan for Coordinator
    execution_plan: List[Dict[str, Any]] = field(default_factory=list)

    # Structured evidence
    artifacts: Dict[str, Any] = field(default_factory=dict)

    # Human-readable recommendations
    recommendations: List[str] = field(default_factory=list)

    # SUCCESS / FAILED / PARTIAL
    status: str = "SUCCESS"

    # -----------------------------------------------------

    def validate(self) -> None:

        if not self.agent.strip():
            raise ValueError("Agent name cannot be empty.")

        if not self.summary.strip():
            raise ValueError("Summary cannot be empty.")

        if self.risk not in VALID_RISKS:
            raise ValueError(
                f"Invalid risk level: {self.risk}"
            )

        if not (
            MIN_CONFIDENCE
            <= self.confidence
            <= MAX_CONFIDENCE
        ):
            raise ValueError(
                "Confidence must be between 0 and 100."
            )

        for step in self.execution_plan:

            if "agent" not in step:
                raise ValueError(
                    "Execution plan step missing 'agent'."
                )

            if "priority" not in step:
                raise ValueError(
                    "Execution plan step missing 'priority'."
                )

            if "reason" not in step:
                raise ValueError(
                    "Execution plan step missing 'reason'."
                )

    # -----------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:

        self.validate()
        return asdict(self)

    # -----------------------------------------------------

    def to_json(self) -> str:

        self.validate()

        return json.dumps(
            self.to_dict(),
            indent=4,
            ensure_ascii=False,
        )

    # -----------------------------------------------------

    @classmethod
    def from_dict(cls, data: Dict[str, Any]):

        obj = cls(**data)
        obj.validate()

        return obj

    # -----------------------------------------------------

    @classmethod
    def from_json(cls, json_string: str):

        return cls.from_dict(
            json.loads(json_string)
        )


# =========================================================
# Factory Function
# =========================================================

def create_response(
    *,
    agent: str,
    summary: str,
    confidence: int,
    risk: str,
    execution_plan: List[Dict[str, Any]] = None,
    artifacts: Dict[str, Any] = None,
    recommendations: List[str] = None,
    status: str = "SUCCESS",
) -> ACPResponse:
    """
    Convenience factory used by specialist agents.
    """

    response = ACPResponse(
        agent=agent,
        summary=summary,
        confidence=confidence,
        risk=risk,
        execution_plan=execution_plan or [],
        artifacts=artifacts or {},
        recommendations=recommendations or [],
        status=status,
    )

    response.validate()

    return response


# =========================================================
# Example Usage
# =========================================================

if __name__ == "__main__":

    phishing_response = create_response(

        agent="Phishing Investigation Agent",

        summary=(
            "Email impersonates PayPal using a spoofed "
            "domain and contains a credential harvesting URL."
        ),

        confidence=97,

        risk=RISK_HIGH,

        execution_plan=[
            {
                "agent": "Threat Hunter",
                "priority": 1,
                "reason": "Investigate sender domain and URL reputation."
            },
            {
                "agent": "SOC",
                "priority": 2,
                "reason": "Search enterprise logs for related activity."
            }
        ],

        artifacts={
            "sender": "support@paypa1.com",
            "reply_to": "verify@paypa1.com",
            "urls": [
                "http://paypa1-login.com"
            ],
            "ioc_count": 3,
            "attachment_present": False
        },

        recommendations=[
            "Block sender domain.",
            "Investigate malicious URL.",
            "Search mailbox for similar emails."
        ]
    )

    # Coordinator works directly with the object

    print(phishing_response.agent)
    print(phishing_response.summary)
    print(phishing_response.execution_plan)
    print(phishing_response.artifacts)

    # Serialize only if required

    print(phishing_response.to_json())