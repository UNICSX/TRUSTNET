"""
threat_agent.py

Threat Hunting Specialist Agent
"""

from agent_core import BaseAgent

from threat_hunter.threat_prompts import SYSTEM_PROMPT
from threat_hunter.threat_tool_specs import registry

from config import (
    THREAT_API_ENV,
    THREAT_MODEL,
)


class ThreatHunterAgent(BaseAgent):

    def __init__(self):

        super().__init__(
            name="Threat Hunter",

            api_env=THREAT_API_ENV,

            model_name=THREAT_MODEL,

            system_prompt=SYSTEM_PROMPT,

            tools=registry.get_tools(),

            tool_functions=registry.get_tool_functions(),
        )