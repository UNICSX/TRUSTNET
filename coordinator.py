"""
coordinator.py

Coordinator Agent
-----------------
The coordinator is the only orchestrator in the system.

Responsibilities:
    • Receive investigation requests
    • Ask the LLM to build an execution plan
    • Delegate work to specialist agents
    • Receive ACP responses
    • Re-plan when necessary
    • Aggregate results
    • Produce final executive report

The coordinator NEVER performs investigations itself.
"""

from __future__ import annotations

import json
import logging
import traceback
from collections import deque
from datetime import datetime
from typing import Any, Dict, List, Optional

from groq import Groq

# from agent_core import BaseAgent
# from acp import ACPMessage, ACPResponse
from agent_core import BaseAgent
from memory import shared_memory
from acp import ACPMessage, ACPResponse

from config import (
    COORDINATOR_API_ENV,
    COORDINATOR_MODEL,
    MAX_AGENT_STEPS,
    TEMPERATURE,
    MAX_OUTPUT_TOKENS,
    AGENT_ALIASES,
)

from coordinator_prompts import (
    SYSTEM_PROMPT,
    build_planning_prompt,
    build_replanning_prompt,
    build_report_prompt,
)
# 1A
# -------------------------------------------------------------------------
# Logging
# -------------------------------------------------------------------------

logger = logging.getLogger("Coordinator")

if not logger.handlers:
    handler = logging.StreamHandler()

    formatter = logging.Formatter(
        "[%(asctime)s] %(levelname)s | %(name)s | %(message)s",
        datefmt="%H:%M:%S",
    )

    handler.setFormatter(formatter)
    logger.addHandler(handler)

logger.setLevel(logging.INFO)


# -------------------------------------------------------------------------
# Coordinator
# -------------------------------------------------------------------------

class Coordinator(BaseAgent):
    """
    Master orchestration agent.

    Responsibilities
    ----------------
    • Plans investigations using Gemini
    • Delegates to specialist agents
    • Receives ACP responses
    • Dynamically replans
    • Aggregates findings
    • Produces executive report

    The coordinator never executes security tools itself.
    """

    def __init__(
        self,
        phishing_agent,
        threat_agent,
        soc_agent,
    ):
        super().__init__(
            name="Coordinator",
            api_env=COORDINATOR_API_ENV,
            model_name=COORDINATOR_MODEL,
            system_prompt=SYSTEM_PROMPT,
            tools=[],
            tool_functions={},
        )

        # -------------------------------------------------------------
        # Dedicated Gemini client
        # -------------------------------------------------------------

        # self.client = genai.Client(api_key=COORDINATOR_API_KEY)

        # self.model_name = COORDINATOR_MODEL
        self.temperature = TEMPERATURE
        self.max_output_tokens = MAX_OUTPUT_TOKENS
        self.max_steps = MAX_AGENT_STEPS

        # -------------------------------------------------------------
        # Specialist registry
        # -------------------------------------------------------------

        self.specialists = {
            "phishing": phishing_agent,
            "threat": threat_agent,
            "soc": soc_agent,
        }

        # -------------------------------------------------------------
        # Runtime state
        # -------------------------------------------------------------

        self.execution_queue = deque()

        self.execution_graph: List[Dict[str, Any]] = []

        self.completed_agents = set()

        self.failed_agents = set()

        self.wrapper_history: List[Dict[str, Any]] = []

        self.acp_history: List[ACPResponse] = []

        self.execution_log: List[Dict[str, Any]] = []

        self.plan_history: List[Dict[str, Any]] = []

        self.metadata: Dict[str, Any] = {}

        self.current_case: Dict[str, Any] = {}

        self.current_step = 0

        logger.info("Coordinator initialized successfully.")


        # 1B
    # ------------------------------------------------------------------
    # Runtime Helpers
    # ------------------------------------------------------------------

    def reset(self):
        """
        Reset all coordinator runtime state before starting a new
        investigation.
        """

        self.execution_queue.clear()

        self.execution_graph.clear()

        self.completed_agents.clear()

        self.failed_agents.clear()

        self.wrapper_history.clear()

        self.acp_history.clear()

        self.execution_log.clear()

        self.plan_history.clear()

        self.metadata = {}

        self.current_case = {}

        self.current_step = 0

        logger.info("Coordinator runtime state reset.")


    def normalize_agent_name(self, name: str) -> str:
        """
        Convert any agent alias into its canonical registry name.
        """

        name = name.lower().strip()

        return AGENT_ALIASES.get(name, name)

    # ------------------------------------------------------------------

    def memory_summary(self) -> str:
        """
        Retrieve the shared long-term memory maintained by BaseAgent.
        """

        try:
            return super().memory_summary()
        except Exception:
            logger.exception("Unable to load shared memory.")
            return "No shared memory available."

    # ------------------------------------------------------------------

    def build_metadata(
        self,
        task: str,
        source: str = "user",
    ) -> Dict[str, Any]:
        """
        Construct metadata attached to every specialist execution.
        """

        metadata = {
            "case_id": f"CASE-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}",
            "created_at": datetime.utcnow().isoformat(),
            "source": source,
            "task": task,
            "original_case": task,
            "coordinator": self.name,
            "steps_completed": 0,
            "max_steps": self.max_steps,
        }

        self.metadata = metadata

        return metadata

    # ------------------------------------------------------------------

    def enqueue(
        self,
        agent_name: str,
        task: str,
        priority: int = 1,
        reason: str = "",
    ) -> None:
        """
        Add a specialist execution request to the runtime queue.
        """

        job = {
            "agent": agent_name.lower(),
            "task": task,
            "priority": priority,
            "reason": reason,
        }

        self.execution_queue.append(job)

        logger.info(
            "Queued %s (priority=%s)",
            agent_name,
            priority,
        )

    # ------------------------------------------------------------------

    def dequeue(self) -> Optional[Dict[str, Any]]:
        """
        Pop the next specialist execution request.
        """

        if not self.execution_queue:
            return None

        queue = sorted(
            list(self.execution_queue),
            key=lambda x: x["priority"],
        )

        self.execution_queue = deque(queue)

        return self.execution_queue.popleft()

    # ------------------------------------------------------------------

    def has_pending_jobs(self) -> bool:
        """
        Returns True if specialists are waiting to execute.
        """

        return len(self.execution_queue) > 0
    
    def should_schedule(self, step: dict) -> bool:
        """
        Decide whether a recommended investigation should be queued.
        """

        agent = self.normalize_agent_name(step["agent"])

        # Only specialists that actually exist in the registry
        # may be scheduled.
        if agent not in self.specialists:
            logger.warning(
                "Ignoring unknown specialist recommendation: '%s'",
                step["agent"],
            )
            return False

        if agent in self.completed_agents:
            return False

        if agent in self.failed_agents:
            return False

        if any(
            queued["agent"] == agent
            for queued in self.execution_queue
        ):
            return False

        return True

    # ------------------------------------------------------------------

    def investigation_context(self) -> Dict[str, Any]:
        """
        Build the current investigation context passed into planning and
        replanning prompts.
        """

        return {
            "metadata": self.metadata,
            "completed_agents": sorted(list(self.completed_agents)),
            "failed_agents": sorted(list(self.failed_agents)),
            "execution_graph": self.execution_graph,
            "current_step": self.current_step,
            "remaining_queue": list(self.execution_queue),

            # Lightweight summaries only
            "findings": [
                {
                    "agent": response.agent,
                    "summary": response.summary,
                    "risk": response.risk,
                    "confidence": response.confidence,
                }
                for response in self.acp_history
            ],
        }
    # -------------------------------------------------------------------------
    # Chunk 2
    # Planning Engine
    # -------------------------------------------------------------------------

    def _call_planner(
        self,
        prompt: str,
    ) -> Dict[str, Any]:
        """
        Execute the coordinator LLM and parse the returned JSON plan.
        """

        conversation = self.create_conversation(prompt)

        response = self.generate(conversation)

        text = response.choices[0].message.content

        # print("\n" + "=" * 80)
        # print("RAW PLANNER RESPONSE")
        # print("=" * 80)
        # print(text)
        # print("=" * 80 + "\n")

        parsed = self.parse_json(text)

        # print("PARSED PLAN:")
        # print(json.dumps(parsed, indent=4))
        # print("=" * 80 + "\n")

        return parsed

    # raise RuntimeError("Coordinator planning model returned no content.")

    # ------------------------------------------------------------------

    def plan(
        self,
        task: str,
    ) -> Dict[str, Any]:
        """
        Initial investigation planning.

        The LLM decides:

            • Which specialists are required
            • Execution order
            • Individual investigation tasks
        """

        logger.info("Planning investigation...")

        planning_prompt = build_planning_prompt(
            user_request=task,
            context=self.investigation_context(),
        )

        plan = self._call_planner(planning_prompt)

        self.plan_history.append(
            {
                "type": "initial_plan",
                "timestamp": datetime.utcnow().isoformat(),
                "plan": plan,
            }
        )

        jobs = plan.get("execution_plan", [])

        if not isinstance(jobs, list):
            raise RuntimeError(
                "Coordinator returned an invalid execution_plan."
            )

        for job in sorted(
            jobs,
            key=lambda x: x.get("priority", 999),
        ):
            agent_name = self.normalize_agent_name(job["agent"])

            if not self.should_schedule(job):
                logger.info(
                    "Skipping duplicate or unavailable specialist: %s",
                    agent_name,
                )
                continue

            self.enqueue(
                agent_name=agent_name,
                task=job["task"],
                priority=job.get("priority", 999),
                reason=job.get("reason", ""),
            )

        logger.info(
            "Planning complete (%d specialist tasks queued).",
            len(jobs),
        )

        return plan

        # ------------------------------------------------------------------

    def replan(
        self,
    ) -> Dict[str, Any]:
        """
        Dynamic replanning.

        After every specialist execution, the Coordinator asks
        Gemini whether another investigation is required.
        """

        logger.info("Evaluating need for dynamic replanning...")

        replanning_prompt = build_replanning_prompt(
            context=self.investigation_context(),
        )

        plan = self._call_planner(replanning_prompt)

        self.plan_history.append(
            {
                "type": "replan",
                "timestamp": datetime.utcnow().isoformat(),
                "plan": plan,
            }
        )

        execute_more = plan.get(
            "continue_investigation",
            False,
        )

        if not execute_more:

            logger.info(
                "Coordinator decided investigation is complete."
            )

            return plan

        jobs = plan.get("execution_plan", [])

        for job in sorted(
            jobs,
            key=lambda x: x.get("priority", 999),
        ): 

            # agent_name = job["agent"].lower()

            # if agent_name in self.completed_agents:
            #     continue

            # if agent_name in self.failed_agents:
            #     continue

            # duplicate = any(
            #     queued["agent"] == agent_name
            #     for queued in self.execution_queue
            # )

            # if duplicate:
            #     continue

            # self.enqueue(
            #     agent_name=agent_name,
            #     task=job["task"],
            #     priority=job.get("priority", 999),
            #     reason=job.get("reason", ""),
            # )
            if not self.should_schedule(job):
             
                continue
            agent_name = self.normalize_agent_name(job["agent"])
            self.enqueue(
                agent_name=agent_name,
                task=job["task"],
                priority=job.get("priority", 999),
                reason=job.get("reason", ""),
                )

        logger.info(
            "Dynamic replanning finished."
        )

        return plan
    # -------------------------------------------------------------------------
    # Chunk 3
    # Execution Engine
    # -------------------------------------------------------------------------

    def wrapper_to_acp(
        self,
        wrapper: Dict[str, Any],
    ) -> ACPResponse:
        """
        Convert a specialist BaseAgent.run() wrapper into a validated
        ACPResponse object.
        """

        result = wrapper.get("result", {})

        if not isinstance(result, dict):
            raise RuntimeError(
                "Specialist returned an invalid result payload."
            )

        wrapper_status = wrapper.get("status", "completed")

        if wrapper_status == "completed":
            acp_status = "SUCCESS"
        elif wrapper_status == "tool_limit_exceeded":
            acp_status = "PARTIAL"
        else:
            acp_status = "FAILED"

        response = ACPResponse.from_dict(
            {
                "agent": wrapper.get("agent", "Unknown"),
                "summary": result.get(
                    "summary",
                    "No summary provided.",
                ),
                "confidence": result.get(
                    "confidence",
                    50,
                ),
                "risk": result.get(
                    "risk",
                    "Low",
                ),
                "execution_plan": result.get(
                    "execution_plan",
                    [],
                ),
                "artifacts": result.get(
                    "artifacts",
                    {},
                ),
                "recommendations": result.get(
                    "recommendations",
                    [],
                ),
                "status": acp_status,
            }
        )

        return response

    # ------------------------------------------------------------------

    def execute_specialist(
        self,
        job: Dict[str, Any],
    ) -> Optional[ACPResponse]:
        """
        Execute a single specialist agent.
        """

        # agent_key = job["agent"].lower().strip()

        # aliases = {
        #     "phishing investigation agent": "phishing",
        #     "phishing": "phishing",
        #     "threat": "threat",
        #     "threat hunter": "threat",
        #     "threat hunting agent": "threat",

        #     "soc": "soc",
        #     "soc alert triage agent": "soc",
        # }

        # agent_key = aliases.get(agent_key, agent_key)
        agent_key = self.normalize_agent_name(job["agent"])

        specialist = self.specialists.get(agent_key)

        if specialist is None:

            logger.error(
                "Unknown specialist '%s'.",
                agent_key,
            )

            self.failed_agents.add(agent_key)

            return None

        logger.info(
            "Executing specialist: %s",
            specialist.name,
        )

        metadata = dict(self.metadata)

        metadata.update(
            {
                "assigned_agent": specialist.name,
                "priority": job["priority"],
                "reason": job["reason"],
                "step": self.current_step,
            }
        )

            # ---------------------------------------------------------
            # Build cross-agent investigation context
            # ---------------------------------------------------------

        previous_findings = []

        for response in self.acp_history:
            previous_findings.append(
                {
                    "agent": response.agent,
                    "summary": response.summary,
                    "risk": response.risk,
                    "confidence": response.confidence,
                    "artifacts": response.artifacts,
                    "recommendations": response.recommendations,
                }
            )

        metadata["previous_findings"] = previous_findings

        try:

            wrapper = specialist.run(
                task=job["task"],
                metadata=metadata,
            )
            print("\n" + "=" * 80)
            print("SPECIALIST WRAPPER")
            print("=" * 80)
            print(json.dumps(wrapper, indent=4, default=str))
            print("=" * 80 + "\n")

            self.wrapper_history.append(wrapper)

            response = self.wrapper_to_acp(wrapper)

            self.acp_history.append(response)

            # ---------------------------------------------------------
            # Queue specialist-recommended follow-up investigations
            # ---------------------------------------------------------

            # for step in response.execution_plan:

            #     agent_name = step["agent"].lower()

            #     if agent_name in self.completed_agents:
            #         continue

            #     if agent_name in self.failed_agents:
            #         continue

            #     duplicate = any(
            #         queued["agent"] == agent_name
            #         for queued in self.execution_queue
            #     )

            #     if duplicate:
            #         continue

            #     self.enqueue(
            #         agent_name=agent_name,
            #         task=step.get("task", ""),
            #         priority=step.get("priority", 999),
            #         reason=step.get(
            #             "reason",
            #             "Recommended by specialist",
            #         ),
            #     )
            # for step in response.execution_plan:
                 
            #     if not self.should_schedule(step):
            #         continue

            #     agent_name = step["agent"].lower()
            #     self.enqueue(
            #         agent_name=agent_name,
            #         task=step.get("task", ""),
            #         priority=step.get("priority", 999),
            #         reason=step.get(
            #             "reason",
            #             "Recommended by specialist",
            #         ),
            #     )

            for step in response.execution_plan:

                if not self.should_schedule(step):
                    
                    continue

                agent_name = self.normalize_agent_name(step["agent"])

                self.enqueue(
                    agent_name=agent_name,
                    task=step.get("task", ""),
                    priority=step.get("priority", 999),
                    reason=step.get(
                        "reason",
                        "Recommended by specialist",
                    ),
                )

            # self.completed_agents.add(agent_key)
            if wrapper.get("status") == "completed":
                self.completed_agents.add(agent_key)
            else:
                self.failed_agents.add(agent_key)

            self.execution_graph.append(
                {
                    "step": self.current_step,
                    "agent": specialist.name,
                    "task": job["task"],
                    "status": response.status,
                    "risk": response.risk,
                    "confidence": response.confidence,
                    "timestamp": datetime.utcnow().isoformat(),
                }
            )

            self.execution_log.append(
                {
                    "agent": specialist.name,
                    "summary": response.summary,
                    "status": response.status,
                }
            )

            self.metadata["steps_completed"] += 1

            if wrapper.get("status") == "completed":
                logger.info(
                    "%s completed successfully.",
                    specialist.name,
                )
            else:
                logger.error(
                    "%s failed with status: %s",
                    specialist.name,
                    wrapper.get("status"),
                )

            return response

        except Exception:

            logger.error(
                traceback.format_exc()
            )

            self.failed_agents.add(agent_key)

            self.execution_graph.append(
                {
                    "step": self.current_step,
                    "agent": specialist.name,
                    "task": job["task"],
                    "status": "FAILED",
                    "timestamp": datetime.utcnow().isoformat(),
                }
            )

            return None

    # ------------------------------------------------------------------

    def execute_queue(self) -> List[ACPResponse]:
        """
        Execute every queued specialist.

        After each successful execution the Coordinator asks
        Gemini whether another specialist should be scheduled.
        """

        logger.info(
            "Beginning specialist execution."
        )

        while self.has_pending_jobs():

            self.current_step += 1

            job = self.dequeue()

            if job is None:
                break

            response = self.execute_specialist(job)

            if response is None:
                continue

            # Only replan if there are no specialists already waiting.
            if self.has_pending_jobs():
                continue


            
            try:
                self.replan()

            except Exception:

                logger.error(
                    "Dynamic replanning failed."
                )

                logger.error(
                    traceback.format_exc()
                )

        logger.info(
            "All queued investigations completed."
        )

        return self.acp_history
    
    # -------------------------------------------------------------------------
    # Chunk 4
    # Aggregation Engine
    # -------------------------------------------------------------------------

    def aggregate_findings(self) -> Dict[str, Any]:
        """
        Aggregate all ACP responses into a single investigation summary.

        The coordinator does not perform investigations here—it only
        combines evidence returned by specialist agents.
        """

        logger.info("Aggregating specialist findings...")

        summaries: List[Dict[str, Any]] = []

        artifacts: Dict[str, List[Any]] = {}

        recommendations = set()

        confidence_values: List[int] = []

        risk_priority = {
            "Low": 1,
            "Medium": 2,
            "High": 3,
            "Critical": 4,
        }

        highest_risk = "Low"

        statuses = []

        for response in self.acp_history:

            summaries.append(
                {
                    "agent": response.agent,
                    "summary": response.summary,
                    "risk": response.risk,
                    "confidence": response.confidence,
                }
            )

            confidence_values.append(
                response.confidence
            )

            statuses.append(
                response.status
            )

            if (
                risk_priority.get(
                    response.risk,
                    0,
                )
                >
                risk_priority.get(
                    highest_risk,
                    0,
                )
            ):
                highest_risk = response.risk

            for key, value in response.artifacts.items():

                artifacts.setdefault(
                    key,
                    [],
                ).append(value)

            recommendations.update(
                response.recommendations
            )

        average_confidence = (
            round(
                sum(confidence_values)
                /
                len(confidence_values)
            )
            if confidence_values
            else 0
        )

        overall_status = (
            "PARTIAL"
            if self.failed_agents
            else "SUCCESS"
        )

        aggregated = {
            "status": overall_status,
            "overall_risk": highest_risk,
            "overall_confidence": average_confidence,
            "completed_agents": sorted(
                list(self.completed_agents)
            ),
            "failed_agents": sorted(
                list(self.failed_agents)
            ),
            "timeline": summaries,
            "artifacts": artifacts,
            "recommendations": sorted(
                recommendations
            ),
            "execution_graph": self.execution_graph,
            # "wrapper_history": self.wrapper_history,
            # "acp_history": [
            #     response.to_dict()
            #     for response in self.acp_history
            # ],
        }

        logger.info(
            "Aggregation complete."
        )

        return aggregated
    
    # -------------------------------------------------------------------------
    # Chunk 5
    # Executive Report
    # -------------------------------------------------------------------------

    def build_executive_report(self) -> Dict[str, Any]:
        """
        Build the final executive report.

        The Coordinator never performs technical analysis here.
        It simply asks the LLM to transform the aggregated
        specialist findings into a human-readable report.
        """

        logger.info("Generating executive report...")

        aggregated = self.aggregate_findings()

        lightweight_context = {
            "metadata": self.metadata,
            "completed_agents": list(self.completed_agents),
            "failed_agents": list(self.failed_agents),
        }

        report_prompt = build_report_prompt(
        investigation_context=lightweight_context,
        aggregated_findings=aggregated,
        )

        report = self._call_planner(report_prompt)

        final_report = {
            "case_metadata": self.metadata,
            "generated_at": datetime.utcnow().isoformat(),
            "executive_report": report,
            "overall_status": aggregated["status"],
            "overall_risk": aggregated["overall_risk"],
            "overall_confidence": aggregated["overall_confidence"],
            "completed_agents": aggregated["completed_agents"],
            "failed_agents": aggregated["failed_agents"],
            "timeline": aggregated["timeline"],
            "artifacts": aggregated["artifacts"],
            "recommendations": aggregated["recommendations"],
            "execution_graph": aggregated["execution_graph"],
            "wrapper_history": self.wrapper_history,
        }

        logger.info("Executive report generated successfully.")

        return final_report

    # ------------------------------------------------------------------

    def export_report(
        self,
        indent: int = 4,
    ) -> str:
        """
        Return the executive report as formatted JSON.
        """

        return json.dumps(
            self.build_executive_report(),
            indent=indent,
            ensure_ascii=False,
            default=str,
        )
    
    # -------------------------------------------------------------------------
    # Chunk 6
    # investigate()
    # -------------------------------------------------------------------------

    def investigate(
        self,
        task: str,
        source: str = "user",
    ) -> Dict[str, Any]:
        """
        Coordinator entry point.

        Investigation lifecycle:

            Reset Runtime
                    ↓
            Build Metadata
                    ↓
            Initial Planning
                    ↓
            Execute Specialists
                    ↓
            Dynamic Replanning
                    ↓
            Aggregate Findings
                    ↓
            Generate Executive Report
        """

        logger.info("=" * 70)
        logger.info("Starting Investigation")
        logger.info("=" * 70)

        self.reset()

        # ---------------------------------------------------------
        # Start a completely fresh investigation case.
        # Prevent observations from a previous case from
        # contaminating the current investigation.
        # Memory remains shared between specialists during
        # THIS investigation.
        # ---------------------------------------------------------
        shared_memory.clear_all()

        self.build_metadata(
            task=task,
            source=source,
        )

        self.current_case = {
            "task": task,
            "started_at": datetime.utcnow().isoformat(),
        }

        try:

            # ---------------------------------------------------------
            # Initial Planning
            # ---------------------------------------------------------

            self.plan(task)

            # ---------------------------------------------------------
            # Specialist Execution
            # ---------------------------------------------------------

            self.execute_queue()

            # ---------------------------------------------------------
            # Final Executive Report
            # ---------------------------------------------------------

            report = self.build_executive_report()

            report["runtime"] = {
                "steps_executed": self.current_step,
                "completed_agents": len(
                    self.completed_agents
                ),
                "failed_agents": len(
                    self.failed_agents
                ),
                "plans_generated": len(
                    self.plan_history
                ),

                "tools_executed": sum(
                    len(wrapper.get("tools_used", []))
                    for wrapper in self.wrapper_history
                )
            }

            report["case"] = {
                **self.current_case,
                "finished_at": datetime.utcnow().isoformat(),
            }

            logger.info("=" * 70)
            logger.info("Investigation Completed")
            logger.info("=" * 70)

            return report

        except Exception:

            logger.error(
                "Coordinator investigation failed."
            )

            logger.error(
                traceback.format_exc()
            )

            return {
                "status": "FAILED",
                "error": traceback.format_exc(),
                "metadata": self.metadata,
                "execution_graph": self.execution_graph,
                "wrapper_history": self.wrapper_history,
                "acp_history": [
                    response.to_dict()
                    for response in self.acp_history
                ],
            }