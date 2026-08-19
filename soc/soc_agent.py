"""
soc_agent.py

SOC Alert Triage Specialist Agent
"""

from agent_core import BaseAgent

from soc.soc_prompts import SYSTEM_PROMPT
from soc.soc_tools_specs import registry

from config import (
    SOC_API_ENV,
    SOC_MODEL,
)


class SOCAgent(BaseAgent):

    def __init__(self):

        super().__init__(
            name="SOC Alert Triage Agent",

            api_env=SOC_API_ENV,

            model_name=SOC_MODEL,

            system_prompt=SYSTEM_PROMPT,

            tools=registry.get_tools(),

            tool_functions=registry.get_tool_functions(),
        )