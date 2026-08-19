"""
phishing_agent.py

Phishing Investigation Specialist Agent
"""

from agent_core import BaseAgent

from phishing_prompts import SYSTEM_PROMPT
from phishing_tool_specs import registry

from config import (
    PHISHING_API_ENV,
    PHISHING_MODEL,
)


class PhishingAgent(BaseAgent):

    def __init__(self):

        super().__init__(
            name="Phishing Investigation Agent",

            api_env=PHISHING_API_ENV,

            model_name=PHISHING_MODEL,

            system_prompt=SYSTEM_PROMPT,

            tools=registry.get_tools(),

            tool_functions=registry.get_tool_functions(),
        )