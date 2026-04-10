"""Browser Use solver — host browser automation with sandbox-backed custom actions."""

from __future__ import annotations

import asyncio
import logging
import shutil
import tempfile
import time
from pathlib import Path
from typing import Any

from backend.cost_tracker import CostTracker
from backend.ctfd import CTFdClient
from backend.message_bus import ChallengeMessageBus
from backend.models import model_id_from_spec
from backend.output_types import StructuredFlagFound
from backend.prompts import ChallengeMeta, build_browser_use_prompt, list_distfiles
from backend.sandbox import DockerSandbox
from backend.solver_base import CANCELLED, ERROR, FLAG_FOUND, GAVE_UP, QUOTA_ERROR, SolverResult
from backend.tools.core import (
    do_bash,
    do_check_findings,
    do_list_files,
    do_read_file,
    do_submit_flag,
    do_webhook_create,
    do_webhook_get_requests,
    do_write_file,
)
from backend.tracing import SolverTracer

logger = logging.getLogger(__name__)


class BrowserUseSolver:
    """Browser Use powered solver that keeps browser state across bumps."""

    def __init__(
        self,
        model_spec: str,
        challenge_dir: str,
        meta: ChallengeMeta,
        ctfd: CTFdClient,
        cost_tracker: CostTracker,
        settings: object,
        cancel_event: asyncio.Event | None = None,
        no_submit: bool = False,
        submit_fn=None,
        message_bus: ChallengeMessageBus | None = None,
        notify_coordinator=None,
    ) -> None:
        self.model_spec = model_spec
        self.model_id = model_id_from_spec(model_spec)
        self.challenge_dir = challenge_dir
        self.meta = meta
        self.ctfd = ctfd
        self.cost_tracker = cost_tracker
        self.settings = settings
        self.cancel_event = cancel_event or asyncio.Event()
        self.no_submit = no_submit
        self.submit_fn = submit_fn
        self.message_bus = message_bus
        self.notify_coordinator = notify_coordinator

        self.sandbox = DockerSandbox(
            image=getattr(settings, "sandbox_image", "ctf-sandbox"),
            challenge_dir=challenge_dir,
            memory_limit=getattr(settings, "container_memory_limit", "4g"),
        )
        self.tracer = SolverTracer(meta.name, self.model_id)
        self.agent_name = f"{meta.name}/{self.model_id}"

        self._browser: Any | None = None
        self._tools: Any | None = None
        self._profile_dir: str | None = None
        self._distfiles_host_dir = str((Path(challenge_dir) / "distfiles").resolve())
        self._available_file_paths: list[str] = []
        self._task_prompt = ""
        self._step_count = 0
        self._flag: str | None = None
        self._confirmed = False
        self._findings = ""
        self._cost_usd = 0.0
        self._bump_insights: str | None = None

    async def start(self) -> None:
        api_key = getattr(self.settings, "browser_use_api_key", "")
        if not api_key:
            raise RuntimeError(
                "Browser Use solver requires BROWSER_USE_API_KEY. "
                "Set it in the environment or .env before using browser-use/* models."
            )

        executable_path = self._resolve_browser_executable()

        await self.sandbox.start()
        self._profile_dir = tempfile.mkdtemp(prefix="ctf-browser-use-profile-")
        self._available_file_paths = [self.sandbox.workspace_dir]
        if Path(self._distfiles_host_dir).exists():
            self._available_file_paths.append(self._distfiles_host_dir)

        distfile_names = list_distfiles(self.challenge_dir)
        self._task_prompt = build_browser_use_prompt(
            self.meta,
            distfile_names,
            workspace_host_dir=self.sandbox.workspace_dir,
            distfiles_host_dir=self._distfiles_host_dir,
        )

        from browser_use import Browser

        self._tools = self._build_tools()
        self._browser = Browser(
            executable_path=executable_path,
            headless=getattr(self.settings, "browser_use_headless", True),
            keep_alive=True,
            downloads_path=self.sandbox.workspace_dir,
            user_data_dir=self._profile_dir,
        )

        self.tracer.event("start", challenge=self.meta.name, model=self.model_id)
        logger.info(f"[{self.agent_name}] Browser Use solver started")

    def _resolve_browser_executable(self) -> str:
        configured = getattr(self.settings, "browser_use_executable_path", "").strip()
        if configured:
            if Path(configured).exists():
                return configured
            raise RuntimeError(
                f"BROWSER_USE_EXECUTABLE_PATH does not exist: {configured}"
            )

        for candidate in ("google-chrome", "chromium", "chromium-browser"):
            resolved = shutil.which(candidate)
            if resolved:
                return resolved

        raise RuntimeError(
            "Browser Use solver requires a host Chrome/Chromium executable. "
            "Install google-chrome/chromium or set BROWSER_USE_EXECUTABLE_PATH."
        )

    def _build_tools(self) -> Any:
        from browser_use import ActionResult, Tools

        tools = Tools(exclude_actions=["read_file", "write_file", "replace_file"])

        @tools.action(description="Execute a bash command in the Docker sandbox.")
        async def bash(command: str, timeout_seconds: int = 60) -> ActionResult:
            result = await do_bash(self.sandbox, command, timeout_seconds)
            return ActionResult(extracted_content=result)

        @tools.action(description="List files inside the Docker sandbox.")
        async def list_files(path: str = "/challenge/distfiles") -> ActionResult:
            result = await do_list_files(self.sandbox, path)
            return ActionResult(extracted_content=result)

        @tools.action(description="Read a file from the Docker sandbox.")
        async def read_file(path: str) -> ActionResult:
            result = await do_read_file(self.sandbox, path)
            return ActionResult(extracted_content=str(result))

        @tools.action(description="Write a file into the Docker sandbox.")
        async def write_file(path: str, content: str) -> ActionResult:
            result = await do_write_file(self.sandbox, path, content)
            return ActionResult(extracted_content=result)

        @tools.action(description="Submit a candidate flag to CTFd for verification.")
        async def submit_flag(flag: str) -> ActionResult:
            normalized = flag.strip()
            if self.no_submit:
                result = f'DRY RUN - would submit "{normalized}"'
                return ActionResult(extracted_content=result)

            if self.submit_fn:
                display, confirmed = await self.submit_fn(normalized)
            else:
                display, confirmed = await do_submit_flag(self.ctfd, self.meta.name, normalized)

            if confirmed:
                self._confirmed = True
                self._flag = normalized
                self._findings = f"Flag found via browser-use submit_flag: {normalized}"
                display = (
                    f"{display}\nFlag confirmed. Stop now and return the structured flag output."
                )
            return ActionResult(
                extracted_content=display,
                is_done=confirmed or None,
                success=confirmed or None,
            )

        @tools.action(description="Create a webhook.site token for out-of-band callbacks.")
        async def webhook_create() -> ActionResult:
            result = await do_webhook_create()
            return ActionResult(extracted_content=result)

        @tools.action(description="Read requests received by a webhook.site token.")
        async def webhook_get_requests(uuid: str) -> ActionResult:
            result = await do_webhook_get_requests(uuid)
            return ActionResult(extracted_content=result)

        @tools.action(description="Check for new findings from sibling solvers.")
        async def check_findings() -> ActionResult:
            result = await do_check_findings(self.message_bus, self.model_spec)
            return ActionResult(extracted_content=result)

        @tools.action(description="Send a strategic message to the coordinator.")
        async def notify_coordinator(message: str) -> ActionResult:
            if self.notify_coordinator:
                await self.notify_coordinator(message)
                return ActionResult(extracted_content="Message sent to coordinator.")
            return ActionResult(extracted_content="No coordinator connected.")

        return tools

    def _build_run_prompt(self) -> str:
        if self._bump_insights:
            prompt = (
                f"{self._task_prompt}\n\n"
                "## New Insights From Other Solvers\n"
                f"{self._bump_insights}\n\n"
                "Continue from the current browser state and sandbox workspace. "
                "Try a different technical approach and avoid repeating failed ideas."
            )
            self._bump_insights = None
            return prompt

        if self._step_count == 0:
            return self._task_prompt

        return (
            f"{self._task_prompt}\n\n"
            "Continue from the current browser state and sandbox workspace. "
            "Try a different approach than before."
        )

    async def _on_new_step(self, browser_state_summary: Any, agent_output: Any, step: int) -> None:
        self._step_count = max(self._step_count, step)
        actions = []
        for action in getattr(agent_output, "action", []) or []:
            if hasattr(action, "model_dump"):
                actions.append(action.model_dump(mode="json", exclude_none=True))
            else:
                actions.append(str(action))
        summary = (
            f"URL={getattr(browser_state_summary, 'url', '')} | "
            f"Title={getattr(browser_state_summary, 'title', '')} | "
            f"Next={getattr(agent_output, 'next_goal', '')} | "
            f"Actions={actions}"
        )
        self._findings = summary[:2000]
        self.tracer.model_response(summary, step)
        self.tracer.event(
            "browser_step",
            step=step,
            url=getattr(browser_state_summary, "url", ""),
            title=getattr(browser_state_summary, "title", ""),
            next_goal=getattr(agent_output, "next_goal", ""),
            actions=actions,
        )

    async def _should_stop(self) -> bool:
        return self.cancel_event.is_set()

    def _make_agent(self, task: str) -> Any:
        from browser_use import Agent, ChatBrowserUse

        return Agent(
            task=task,
            llm=ChatBrowserUse(
                model=self.model_id,
                api_key=getattr(self.settings, "browser_use_api_key", ""),
            ),
            browser=self._browser,
            tools=self._tools,
            output_model_schema=StructuredFlagFound,
            available_file_paths=self._available_file_paths,
            register_new_step_callback=self._on_new_step,
            register_should_stop_callback=self._should_stop,
            calculate_cost=True,
            display_files_in_done_text=False,
            enable_signal_handler=False,
        )

    def _apply_usage_summary(self, history: Any, duration_seconds: float) -> None:
        usage = getattr(history, "usage", None)
        if not usage:
            return

        self.cost_tracker.record_precomputed(
            self.agent_name,
            self.model_id,
            input_tokens=getattr(usage, "total_prompt_tokens", 0),
            output_tokens=getattr(usage, "total_completion_tokens", 0),
            cache_read_tokens=getattr(usage, "total_prompt_cached_tokens", 0),
            cost_usd=float(getattr(usage, "total_cost", 0.0)),
            provider_spec="browser-use",
            duration_seconds=duration_seconds,
        )
        agent_usage = self.cost_tracker.by_agent.get(self.agent_name)
        self._cost_usd = agent_usage.cost_usd if agent_usage else self._cost_usd
        self.tracer.usage(
            getattr(usage, "total_prompt_tokens", 0),
            getattr(usage, "total_completion_tokens", 0),
            getattr(usage, "total_prompt_cached_tokens", 0),
            self._cost_usd,
        )

    def _extract_structured_output(self, history: Any) -> StructuredFlagFound | None:
        output = getattr(history, "structured_output", None)
        if output is None:
            return None
        if isinstance(output, StructuredFlagFound):
            return output
        if hasattr(output, "model_dump"):
            return StructuredFlagFound.model_validate(output.model_dump())
        if isinstance(output, dict):
            return StructuredFlagFound.model_validate(output)
        return None

    def _finish_from_history(self, history: Any, duration_seconds: float) -> SolverResult:
        self._apply_usage_summary(history, duration_seconds)

        final_result = ""
        if hasattr(history, "final_result"):
            result = history.final_result()
            final_result = result if isinstance(result, str) else str(result)
        if final_result:
            self._findings = final_result[:2000]

        structured = self._extract_structured_output(history)
        if structured:
            self._flag = structured.flag
            self._findings = f"Flag found via {structured.method}: {structured.flag}"
            if self.no_submit:
                self._confirmed = True

        run_steps = history.number_of_steps() if hasattr(history, "number_of_steps") else 0
        agent_usage = self.cost_tracker.by_agent.get(self.agent_name)
        total_cost = agent_usage.cost_usd if agent_usage else self._cost_usd
        run_cost = float(getattr(getattr(history, "usage", None), "total_cost", total_cost))

        if self._confirmed and self._flag:
            return self._result(FLAG_FOUND, run_steps=run_steps, run_cost=run_cost)
        return self._result(GAVE_UP, run_steps=run_steps, run_cost=run_cost)

    async def run_until_done_or_gave_up(self) -> SolverResult:
        if not self._browser:
            await self.start()

        t0 = time.monotonic()
        try:
            agent = self._make_agent(self._build_run_prompt())
            history = await agent.run(max_steps=100)
            self.tracer.event(
                "turn_complete",
                duration=round(time.monotonic() - t0, 1),
                steps=history.number_of_steps() if hasattr(history, "number_of_steps") else 0,
            )
            return self._finish_from_history(history, time.monotonic() - t0)
        except asyncio.CancelledError:
            return self._result(CANCELLED)
        except Exception as e:
            error_str = str(e)
            logger.error(f"[{self.agent_name}] Error: {e}", exc_info=True)
            self._findings = f"Error: {e}"
            self.tracer.event("error", error=error_str)
            if any(k in error_str.lower() for k in ("quota", "rate", "capacity", "429")):
                return self._result(QUOTA_ERROR)
            if self.cancel_event.is_set():
                return self._result(CANCELLED)
            return self._result(ERROR)

    def bump(self, insights: str) -> None:
        self._bump_insights = insights
        self.tracer.event("bump", insights=insights[:500])
        logger.info(f"[{self.agent_name}] Bumped with sibling insights")

    def _result(self, status: str, run_steps: int | None = None, run_cost: float | None = None) -> SolverResult:
        self.tracer.event("finish", status=status, flag=self._flag, confirmed=self._confirmed)
        return SolverResult(
            flag=self._flag,
            status=status,
            findings_summary=self._findings[:2000],
            step_count=run_steps if run_steps is not None else self._step_count,
            cost_usd=run_cost if run_cost is not None else self._cost_usd,
            log_path=self.tracer.path,
        )

    async def stop(self) -> None:
        self.tracer.event("stop", step_count=self._step_count)
        self.tracer.close()
        if self._browser:
            try:
                self._browser.stop()
            except Exception:
                try:
                    self._browser.kill()
                except Exception:
                    pass
            self._browser = None
        if self._profile_dir:
            shutil.rmtree(self._profile_dir, ignore_errors=True)
            self._profile_dir = None
        if self.sandbox:
            await self.sandbox.stop()
