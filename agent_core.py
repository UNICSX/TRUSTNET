import copy
import json
import os
import re
import time
from urllib.parse import urlparse

from dotenv import load_dotenv
from groq import Groq

from config import (
    TEMPERATURE,
    MAX_OUTPUT_TOKENS,
    MAX_AGENT_STEPS,
    MAX_TOOL_CALLS,
    MAX_RETRIES,
)
from memory import shared_memory

load_dotenv()


class BaseAgent:
    """Generic autonomous reasoning engine with grounded tool arguments."""

    def __init__(
        self,
        name,
        api_env,
        model_name,
        system_prompt,
        tools,
        tool_functions,
    ):
        self.name = name
        self.api_env = api_env
        self.model_name = model_name
        self.system_prompt = system_prompt
        self.tools = tools
        self.tool_functions = tool_functions

        api_key = os.getenv(api_env)
        if not api_key:
            raise ValueError(f"Environment variable '{api_env}' is not set.")

        self.client = Groq(api_key=api_key)

    def load_memory(self):
        return shared_memory.dump()

    def memory_summary(self):
        mem = self.load_memory()
        return "No previous memory." if not mem else json.dumps(mem, indent=2)

    def remember(self, result):
        if not isinstance(result, dict):
            return

        mapping = {
            "ip": "observed_ips",
            "host": "observed_hosts",
            "user": "observed_users",
            "domain": "observed_domains",
        }

        for key, collection in mapping.items():
            if key in result:
                shared_memory.remember(collection, result[key])

    # =========================================================
    # CASE EVIDENCE / TOOL-GROUNDING
    # =========================================================

    def extract_case_evidence(self, task):
        """
        Extract exact indicators from the CURRENT TASK.

        This is deliberately deterministic. It does not ask the LLM
        to decide what an indicator is and it never invents values.
        """
        task = task or ""
        # Normalize Markdown links to their visible raw value.
        task = re.sub(
            r'\[([^\]]+)\]\([^)]+\)',
            r'\1',
            task,
        )

        evidence = {
            "urls": set(),
            "domains": set(),
            "sender_domains": set(),
            "emails": set(),
            "sender_emails": set(),
            "recipient_emails": set(),
            "reply_to_emails": set(),
            "subjects": set(),
            "bodies": set(),
            "ips": set(),
            "users": set(),
            "hosts": set(),
            "processes": set(),
            "hashes": set(),
            "email_ids": set(),
        }

        # Exact URLs present in the current task.
        url_pattern = r'https?://[^\s<>"\'\]\)]+'
        for match in re.findall(url_pattern, task, flags=re.IGNORECASE):
            evidence["urls"].add(match.rstrip(".,;"))

        # Exact email addresses present in the current task.
        email_pattern = r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'
        all_emails = set(re.findall(email_pattern, task))
        evidence["emails"].update(all_emails)

        # Structured fields. Values are copied exactly from the task.
        def field_value(label, multiline=False):
            if multiline:
                pattern = (
                    rf'(?ims)^\s*{re.escape(label)}\s*:\s*(.*?)'
                    rf'(?=^\s*[A-Za-z][A-Za-z _-]*\s*:\s*|\Z)'
                )
            else:
                pattern = rf'(?im)^\s*{re.escape(label)}\s*:\s*(.*?)\s*$'
            match = re.search(pattern, task)
            return match.group(1).strip() if match else None

        sender = (
            field_value("Email received from")
            or field_value("Sender")
            or field_value("From")
        )
        recipient = field_value("Recipient")
        reply_to = field_value("Reply-To")
        subject = field_value("Subject")
        message = field_value("Message", multiline=True)
        sender_domain = field_value("Sender Domain")
        explicit_domain = field_value("Domain")
        explicit_url = field_value("URL")
        email_id = field_value("Email ID")

        if sender and re.fullmatch(email_pattern, sender):
            evidence["sender_emails"].add(sender)
        if recipient and re.fullmatch(email_pattern, recipient):
            evidence["recipient_emails"].add(recipient)
        if reply_to and re.fullmatch(email_pattern, reply_to):
            evidence["reply_to_emails"].add(reply_to)
        if subject:
            evidence["subjects"].add(subject)
        if message:
            evidence["bodies"].add(message)

        if explicit_url and re.match(r'^https?://', explicit_url, re.IGNORECASE):
            evidence["urls"].add(explicit_url.rstrip(".,;"))

        if sender_domain:
            evidence["domains"].add(sender_domain)
            evidence["sender_domains"].add(sender_domain)
        if explicit_domain:
            evidence["domains"].add(explicit_domain)

        # Domains from verified current-case URLs.
        for url in evidence["urls"]:
            try:
                hostname = urlparse(url).hostname
            except Exception:
                hostname = None
            if hostname:
                evidence["domains"].add(hostname)

        # Domains from verified current-case email addresses.
        for email in evidence["emails"]:
            try:
                domain = email.split("@", 1)[1]
            except (IndexError, AttributeError):
                continue
            if domain:
                evidence["domains"].add(domain)
                if email in evidence["sender_emails"]:
                    evidence["sender_domains"].add(domain)

        # Basic IP extraction from the current task only.
        ip_pattern = (
            r'\b(?:25[0-5]|2[0-4]\d|1?\d?\d)'
            r'(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b'
        )
        evidence["ips"].update(re.findall(ip_pattern, task))

        # Optional structured identifiers.
        if email_id and email_id.isdigit():
            evidence["email_ids"].add(int(email_id))

        # These are only populated from explicitly labelled fields.
        host = field_value("Host")
        user = field_value("User")
        process = field_value("Process")
        hash_value = field_value("Hash") or field_value("Hash Value")

        if host:
            evidence["hosts"].add(host)

        if user:
            evidence["users"].add(user)

        if process:
            evidence["processes"].add(process)

        if hash_value:
            evidence["hashes"].add(hash_value)

        return {
            key: sorted(values, key=lambda value: str(value))
            for key, values in evidence.items()
        }

    def _ground_tools(self, evidence):
        """
        Create per-request copies of the tool schemas.

        The LLM still chooses tools autonomously, but indicator arguments
        are constrained to exact values known from the current case.

        This is important because validation after an LLM tool call is too
        late when the provider rejects an invalid function call itself.
        """
        grounded_tools = copy.deepcopy(self.tools)

        allowed_by_argument = {
            "url": evidence["urls"],
            "domain": evidence["sender_domains"] or evidence["domains"],
            "sender": evidence["sender_emails"] or evidence["emails"],
            "reply_to": evidence["reply_to_emails"] or [""],
            "subject": evidence["subjects"],
            "body": evidence["bodies"],
            "email_id": evidence["email_ids"],
            "host": evidence["hosts"],
            "user": evidence["users"],
            "ip": evidence["ips"],
            "process_name": evidence["processes"],
            "hash_value": evidence["hashes"],

            # MITRE accepts any grounded indicator type.
            "indicator": (
                evidence["ips"]
                + evidence["hosts"]
                + evidence["users"]
                + evidence["processes"]
                + evidence["hashes"]
                + evidence["domains"]
            ),
        }

        # Remove a tool only when one of its required arguments
        # has no grounded evidence available in the current case.
        filtered_tools = []

        for tool in grounded_tools:
            function = tool.get("function", {})
            parameters = function.get("parameters", {})
            required = parameters.get("required", [])

            unavailable = False

            for argument_name in required:
                if argument_name in allowed_by_argument:
                    if not allowed_by_argument[argument_name]:
                        unavailable = True
                        break

            if not unavailable:
                filtered_tools.append(tool)

        grounded_tools = filtered_tools

        for tool in grounded_tools:
            function = tool.get("function", {})
            parameters = function.get("parameters", {})
            properties = parameters.get("properties", {})

            for argument_name, allowed_values in allowed_by_argument.items():
                if argument_name not in properties:
                    continue

                if allowed_values:
                    if argument_name != "indicator":
                        properties[argument_name]["enum"] = list(allowed_values)

                    # Make the grounding rule explicit to the model too.
                    existing_description = properties[argument_name].get(
                        "description", ""
                    )
                    grounding_note = (
                        " Use only one of the exact current-case values "
                        "provided by the schema."
                    )
                    if grounding_note.strip() not in existing_description:
                        properties[argument_name]["description"] = (
                            existing_description + grounding_note
                        ).strip()

        return grounded_tools

    def _validate_tool_arguments(self, tool_name, arguments, evidence):
        """
        Deterministically reject arguments that are not grounded in the
        current case. Returns (valid, reason).

        This is a second defense after schema-level grounding.
        """
        tool_rules = {
            # ---------------------------------------------------------
            # Phishing tools
            # ---------------------------------------------------------

            "check_url_reputation": {
                "url": set(evidence["urls"])
            },

            "check_sender_domain_age": {
                "domain": set(
                    evidence["sender_domains"] or evidence["domains"]
                )
            },

            "extract_email_metadata": {
                "sender": set(
                    evidence["sender_emails"] or evidence["emails"]
                ),
                "reply_to": set(
                    evidence["reply_to_emails"] or [""]
                ),
                "subject": set(evidence["subjects"]),
                "body": set(evidence["bodies"]),
            },

            "flag_for_review": {
                "email_id": set(evidence["email_ids"])
            },

            # ---------------------------------------------------------
            # Threat Hunter tools
            # ---------------------------------------------------------

            "get_running_processes": {
                "host": set(evidence["hosts"])
            },

            "get_network_connections": {
                "host": set(evidence["hosts"])
            },

            "check_ip_reputation": {
                "ip": set(evidence["ips"])
            },

            "check_startup_registry": {
                "host": set(evidence["hosts"])
            },

            "get_login_history": {
                "user": set(evidence["users"])
            },

            "lookup_mitre_attack": {
                "indicator": (
                    set(evidence["ips"])
                    | set(evidence["hosts"])
                    | set(evidence["users"])
                    | set(evidence["domains"])
                )
            },

            # ---------------------------------------------------------
            # SOC Alert Triage tools
            # ---------------------------------------------------------

            "get_asset_criticality": {
                "host": set(evidence["hosts"])
            },

            "lookup_previous_alerts": {
                "host": set(evidence["hosts"])
            },

            "get_user_activity": {
                "user": set(evidence["users"])
            },

            "get_parent_process": {
                "process_name": set(evidence["processes"])
            },

            "check_process_hash": {
                "hash_value": set(evidence["hashes"])
            },

        }

        rules = tool_rules.get(tool_name)
        if not rules:
            return True, None

        for argument_name, allowed_values in rules.items():
            if argument_name not in arguments:
                return False, f"Missing required grounded argument: {argument_name}"

            value = arguments[argument_name]

            if argument_name == "email_id":
                if not isinstance(value, int) or isinstance(value, bool):
                    return False, (
                        "Argument 'email_id' must be an integer."
                    )

                if value not in allowed_values:
                    return False, (
                        f"Untrusted value for 'email_id': {value!r}. "
                        "It is not present in the current-case evidence."
                    )

                continue

            if not isinstance(value, str):
                return False, (
                    f"Argument '{argument_name}' must be a raw string."
                )

            if value not in allowed_values:
                return False, (
                    f"Untrusted value for '{argument_name}': {value!r}. "
                    f"It is not present in the current-case evidence."
                )

            # Prevent Markdown link syntax from entering tool calls.
            if "[" in value or "](" in value:
                return False, (
                    f"Argument '{argument_name}' contains Markdown syntax."
                )

        return True, None

    def execute_tool(self, function_call, tool_trace, evidence):
        tool_name = function_call.name
        arguments = dict(function_call.args)

        valid, reason = self._validate_tool_arguments(
            tool_name,
            arguments,
            evidence,
        )

        if not valid:
            print(
                f"\n[{self.name}] BLOCKED ungrounded tool call: "
                f"{tool_name}({arguments})"
            )

            blocked_result = {
                "error": "ungrounded_tool_arguments",
                "reason": reason,
                "tool": tool_name,
                "arguments": arguments,
            }

            tool_trace.append(
                {
                    "step": len(tool_trace) + 1,
                    "tool": tool_name,
                    "arguments": arguments,
                    "result": blocked_result,
                    "blocked": True,
                }
            )

            return tool_name, blocked_result, False

        print(f"\n[{self.name}] Executing: {tool_name}")
        result = self.tool_functions[tool_name](**arguments)
        self.remember(result)

        tool_trace.append(
            {
                "step": len(tool_trace) + 1,
                "tool": tool_name,
                "arguments": arguments,
                "result": result,
            }
        )

        return tool_name, result, True

    def parse_json(self, text):
        text = text.strip()

        if text.startswith("```json"):
            text = text.replace("```json", "", 1)

        if text.startswith("```"):
            text = text.replace("```", "", 1)

        if text.endswith("```"):
            text = text[:-3]

        text = text.strip()

        try:
            return json.loads(text)
        except Exception as e:
            raise RuntimeError(
                f"{self.name} returned invalid ACP JSON.\n\n{text}"
            ) from e

    def create_conversation(self, task):
        metadata = getattr(
            self,
            "_metadata",
            getattr(self, "metadata", {}),
        )

        previous_findings = metadata.get(
            "previous_findings",
            [],
        )

        original_case = metadata.get(
            "original_case",
            task,
        )

        prompt = f"""
Agent Name:
{self.name}

=========================================================
CURRENT INVESTIGATION — SOURCE OF TRUTH
=========================================================

The CURRENT TASK below is the authoritative source of evidence
for this investigation.

You MUST use the actual indicators, email details, URLs, domains,
IPs, users, hosts, and other facts contained in the CURRENT TASK.

NEVER replace them with example values.

NEVER invent alternative domains, URLs, email addresses, users,
IPs, hosts, or message contents.

If an indicator is not present in the CURRENT TASK or returned
by a tool during THIS investigation, treat it as unknown.

=========================================================
LONG-TERM MEMORY
=========================================================

Memory may contain information observed during the current
investigation.

Memory MUST NOT override or replace evidence from the CURRENT TASK.

{self.memory_summary()}

=========================================================
PREVIOUS SPECIALIST FINDINGS
=========================================================

Previous findings may provide supporting context, but they MUST
NOT introduce new indicators that are unrelated to the CURRENT TASK.

{json.dumps(previous_findings, indent=2)}

=========================================================
ORIGINAL INVESTIGATION CASE
=========================================================

{original_case}

==========================================================
SPECIALIST INVESTIGATION TASK
==========================================================
{task}


=========================================================
CRITICAL TOOL ARGUMENT RULE
=========================================================

When calling a tool, copy indicator values EXACTLY from the
CURRENT TASK or from verified tool results.

Do NOT replace a supplied domain with example.com.
Do NOT replace a supplied URL with https://example.com.
Do NOT replace a supplied email address with example@example.com.
Do NOT convert an indicator into a Markdown link.
Do NOT invent missing values.

Tool arguments must contain the raw value only.

If the CURRENT TASK does not contain enough information for a
tool, do not fabricate an argument.
"""

        return [
            {
                "role": "system",
                "content": self.system_prompt,
            },
            {
                "role": "user",
                "content": prompt,
            },
        ]

    # def generate(self, conversation, tools=None):
    #     """
    #     Send the current conversation to Groq and return the response.

    #     If grounded tool schemas are supplied by the specialist run loop,
    #     use them. Otherwise fall back to the agent's original tool schemas
    #     for existing callers such as the Coordinator.
    #     """
    #     if tools is None:
    #         tools = self.tools
    #     for attempt in range(MAX_RETRIES):
    #         try:
    #             response = self.client.chat.completions.create(
    #                 model=self.model_name,
    #                 messages=conversation,
    #                 tools=tools,
    #                 tool_choice="auto",
    #                 parallel_tool_calls=False,
    #                 temperature=TEMPERATURE,
    #                 max_completion_tokens=MAX_OUTPUT_TOKENS,
    #             )

    #             return response

    #         except Exception as e:
    #             print("\n========== GROQ ERROR ==========")
    #             print(e)
    #             print(f"Attempt {attempt + 1}/{MAX_RETRIES}")
    #             print("==================================")

    #             error_text = str(e)

    #             # Groq tool-validation failures are deterministic.
    #             # Retrying the same request wastes API calls because the
    #             # invalid tool is still unavailable in request.tools.
    #             if (
    #                 "tool_use_failed" in error_text
    #                 or "tool call validation failed" in error_text
    #             ):
    #                 raise

    #             if attempt == MAX_RETRIES - 1:
    #                 raise

    #             time.sleep(2)

    def generate(self, conversation, tools=None , tool_choice = "auto"):
        """
        Send the current conversation to Groq and return the response.

        If grounded tool schemas are supplied by the specialist run loop,
        use them. Otherwise fall back to the agent's original tool schemas
        for existing callers such as the Coordinator.
        """
        if tools is None:
            tools = self.tools

        for attempt in range(MAX_RETRIES):
            try:
                response = self.client.chat.completions.create(
                    model=self.model_name,
                    messages=conversation,
                    tools=tools,
                    tool_choice=tool_choice,
                    parallel_tool_calls=False,
                    temperature=TEMPERATURE,
                    max_completion_tokens=MAX_OUTPUT_TOKENS,
                )

                return response

            except Exception as e:
                print("\n========== GROQ ERROR ==========")
                print(e)
                print(f"Attempt {attempt + 1}/{MAX_RETRIES}")
                print("==================================")

                error_text = str(e)

                # Tool-schema failures are deterministic.
                # Do not waste API calls retrying the same invalid request.
                if (
                    "tool_use_failed" in error_text
                    or "tool call validation failed" in error_text
                ):
                    raise

                if attempt == MAX_RETRIES - 1:
                    raise

                time.sleep(2)

    def run(self, task, metadata=None):
        """
        Execute an autonomous reasoning loop until the LLM finishes
        or MAX_AGENT_STEPS is reached.
        """

        if metadata is None:
            metadata = {}

        self._metadata = metadata

        tool_trace = []
        executed_tool_calls = {}
        tool_calls_executed = 0
        blocked_tool_attempts = 0

        # Deterministic evidence extracted once from the authoritative
        # current task. It is the only source used to constrain initial
        # specialist indicator arguments.
        original_case = metadata.get(
            "original_case",
            task,
        )

        case_evidence = self.extract_case_evidence(original_case)

        print("\n========== CASE EVIDENCE ==========")
        print(json.dumps(case_evidence, indent=2))
        print("====================================")

        conversation = self.create_conversation(task)

        print("\n==============================")
        print(f" Starting Agent: {self.name}")
        print("==============================")

        for step in range(MAX_AGENT_STEPS):
            print(f"\nReasoning Step {step + 1}")

            # Rebuild schemas every turn so the same grounding contract
            # applies to every LLM tool-selection request.
            grounded_tools = self._ground_tools(case_evidence)

            try:
                response = self.generate(conversation, grounded_tools)

            except Exception as e:
                error_text = str(e)

                # Groq rejected a tool call that was not available in the
                # grounded tool set. Do not retry the same invalid request.
                #
                # Instead, perform ONE controlled recovery request with
                # tool use explicitly disabled. The agent must now produce
                # its final ACP using only the evidence and tool results
                # already available.
                if (
                    "tool_use_failed" in error_text
                    or "tool call validation failed" in error_text
                ):
                    print(
                        f"\n[{self.name}] Invalid/unavailable tool call detected."
                    )
                    print(
                        f"[{self.name}] Starting controlled no-tool recovery."
                    )

                    conversation.append(
                        {
                            "role": "user",
                            "content": (
                                "The previous tool request was invalid because "
                                "the requested tool was not available in the "
                                "current investigation tool set. "
                                "Do NOT request another tool. "
                                "Do NOT invent or assume any missing evidence. "
                                "Use only the CURRENT CASE evidence and the "
                                "tool results already present in this conversation. "
                                "Now return the final ACP JSON response."
                            ),
                        }
                    )

                    try:
                        response = self.generate(
                            conversation,
                            tools=[],
                            tool_choice="none",
                        )

                    except Exception as recovery_error:
                        return {
                            "agent": self.name,
                            "status": "error",
                            "error": str(recovery_error),
                            "original_error": error_text,
                            "tool_trace": tool_trace,
                            "memory_snapshot": self.load_memory(),
                            "metadata": metadata,
                        }

                else:
                    return {
                        "agent": self.name,
                        "status": "error",
                        "error": str(e),
                        "tool_trace": tool_trace,
                        "memory_snapshot": self.load_memory(),
                        "metadata": metadata,
                    }

            message = response.choices[0].message

            print("\n========== RAW GROQ RESPONSE ==========")
            print(message)

            if message.tool_calls:
                conversation.append(
                    {
                        "role": "assistant",
                        "content": message.content or "",
                        "tool_calls": [
                            {
                                "id": tc.id,
                                "type": tc.type,
                                "function": {
                                    "name": tc.function.name,
                                    "arguments": tc.function.arguments,
                                },
                            }
                            for tc in message.tool_calls
                        ],
                    }
                )

                for tool_call in message.tool_calls:
                    if tool_calls_executed >= MAX_TOOL_CALLS:
                        print(
                            f"\n[{self.name}] Maximum tool call limit "
                            f"({MAX_TOOL_CALLS}) reached."
                        )

                        return {
                            "agent": self.name,
                            "status": "tool_limit_exceeded",
                            "result": {
                                "reason":
                                f"Maximum of {MAX_TOOL_CALLS} tool calls exceeded."
                            },
                            "tools_used": [
                                item["tool"] for item in tool_trace
                                if not item.get("blocked")
                            ],
                            "tool_trace": tool_trace,
                            "memory_snapshot": self.load_memory(),
                            "metadata": metadata,
                        }

                    class FunctionCall:
                        pass

                    function_call = FunctionCall()
                    function_call.name = tool_call.function.name

                    try:
                        function_call.args = json.loads(
                            tool_call.function.arguments
                        )
                    except Exception as e:
                        blocked_result = {
                            "error": "invalid_tool_arguments_json",
                            "reason": str(e),
                        }
                        conversation.append(
                            {
                                "role": "tool",
                                "tool_call_id": tool_call.id,
                                "content": json.dumps(blocked_result),
                            }
                        )
                        continue

                    tool_name = function_call.name
                    arguments = function_call.args

                    signature = (
                        tool_name,
                        json.dumps(arguments, sort_keys=True),
                    )

                    if signature in executed_tool_calls:
                        print(
                            f"[{self.name}] Skipping duplicate tool call: "
                            f"{tool_name}({arguments})"
                        )
                        result = executed_tool_calls[signature]

                    else:
                        tool_name, result, executed = self.execute_tool(
                            function_call,
                            tool_trace,
                            case_evidence,
                        )

                        executed_tool_calls[signature] = result

                        if executed:
                            tool_calls_executed += 1
                        

                    conversation.append(
                        {
                            "role": "tool",
                            "tool_call_id": tool_call.id,
                            "content": json.dumps(
                                {
                                    "result": result,
                                    "updated_memory": self.load_memory(),
                                }
                            ),
                        }
                    )

                continue

            if message.content:
                final_result = self.parse_json(message.content)

                required_fields = [
                    "summary",
                    "confidence",
                    "risk",
                    "execution_plan",
                    "artifacts",
                    "recommendations",
                    "status",
                ]

                # Some model responses omit fields that have an obvious safe default.
                # Normalize those omissions instead of failing an otherwise usable
                # specialist investigation.
                if "execution_plan" not in final_result:
                    final_result["execution_plan"] = []

                if "status" not in final_result:
                    final_result["status"] = "SUCCESS"

                missing = [
                    field
                    for field in required_fields
                    if field not in final_result
                ]

                if missing:
                    raise RuntimeError(
                        f"{self.name} returned an invalid ACP response. "
                        f"Missing required fields: {missing}"
                    )

                return {
                    "agent": self.name,
                    "status": "completed",
                    "result": final_result,
                    "tools_used": [
                        item["tool"]
                        for item in tool_trace
                        if not item.get("blocked")
                    ],
                    "tool_trace": tool_trace,
                    "memory_snapshot": self.load_memory(),
                    "metadata": metadata,
                }

            return {
                "agent": self.name,
                "status": "error",
                "error": "Unknown Groq response format.",
                "tool_trace": tool_trace,
                "memory_snapshot": self.load_memory(),
                "metadata": metadata,
            }

        return {
            "agent": self.name,
            "status": "max_steps_exceeded",
            "result": {
                "reasoning": "Maximum reasoning steps exceeded."
            },
            "tools_used": [
                item["tool"]
                for item in tool_trace
                if not item.get("blocked")
            ],
            "tool_trace": tool_trace,
            "memory_snapshot": self.load_memory(),
            "metadata": metadata,
        }
