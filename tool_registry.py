"""
tool_registry.py

Generic Tool Registry for all autonomous agents.

Every agent defines its tools using simple Python dictionaries.

This registry automatically creates:

1. Gemini FunctionDeclaration objects
2. Tool function lookup dictionary
"""
from groq import Groq


class ToolRegistry:

    def __init__(self):

        self._tool_specs = []

    # -----------------------------------------------------
    # Register Tool
    # -----------------------------------------------------

    def register(
        self,
        name: str,
        description: str,
        parameters: dict,
        function,
    ):

        self._tool_specs.append(
            {
                "name": name,
                "description": description,
                "parameters": parameters,
                "function": function,
            }
        )

    # -----------------------------------------------------
    # Groq Tool Objects
    # -----------------------------------------------------

    def get_tools(self):

        tools = []

        for tool in self._tool_specs:

            tools.append(
                {
                    "type": "function",
                    "function": {
                        "name": tool["name"],
                        "description": tool["description"],
                        "parameters": tool["parameters"],
                    },
                }
            )

        return tools    
    # -----------------------------------------------------
    # Python Function Lookup
    # -----------------------------------------------------

    def get_tool_functions(self):

        return {

            tool["name"]: tool["function"]

            for tool in self._tool_specs

        }

    # -----------------------------------------------------
    # Registered Tool Names
    # -----------------------------------------------------

    def list_tools(self):

        return [

            tool["name"]

            for tool in self._tool_specs

        ]

    # -----------------------------------------------------
    # Tool Specifications
    # -----------------------------------------------------

    def get_specs(self):

        return self._tool_specs