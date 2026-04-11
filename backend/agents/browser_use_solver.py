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
from backend.models import model_id_from_spec, solver_label
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
        self.tracer = SolverTracer(meta.name, self.model_spec)
        self.agent_name = solver_label(meta.name, self.model_spec)

        self._browser: Any | None = None
        self._agent: Any | None = None
        self._tools: Any | None = None
        self._profile_dir: str | None = None
        self._distfiles_host_dir = str((Path(challenge_dir) / "distfiles").resolve())
        self._env_file_path = self._resolve_env_file_path()
        self._available_file_paths: list[str] = []
        self._task_prompt = ""
        self._step_count = 0
        self._flag: str | None = None
        self._confirmed = False
        self._findings = ""
        self._cost_usd = 0.0
        self._bump_insights: str | None = None

    def _refresh_available_file_paths(self) -> None:
        current_paths = set()

        workspace_root = Path(self.sandbox.workspace_dir)
        if workspace_root.exists():
            current_paths.add(str(workspace_root.resolve()))
            for file_path in workspace_root.rglob("*"):
                if file_path.is_file():
                    current_paths.add(str(file_path.resolve()))

        distfiles_root = Path(self._distfiles_host_dir)
        if distfiles_root.exists():
            current_paths.add(str(distfiles_root.resolve()))
            for file_path in distfiles_root.rglob("*"):
                if file_path.is_file():
                    current_paths.add(str(file_path.resolve()))

        if self._env_file_path:
            env_path = Path(self._env_file_path)
            if env_path.exists():
                current_paths.add(str(env_path.resolve()))

        updated_paths = sorted(current_paths)
        if self._available_file_paths:
            self._available_file_paths[:] = updated_paths
        else:
            self._available_file_paths = updated_paths

        if self._agent is not None:
            self._agent.available_file_paths = self._available_file_paths

    def _resolve_browser_upload_path(self, path: str) -> str | None:
        self._refresh_available_file_paths()

        workspace_root = Path(self.sandbox.workspace_dir).resolve()
        distfiles_root = Path(self._distfiles_host_dir).resolve()
        candidates: list[Path] = []

        raw_path = Path(path)
        if raw_path.is_absolute():
            candidates.append(raw_path)

        workspace_prefix = "/challenge/workspace/"
        distfiles_prefix = "/challenge/distfiles/"
        if path.startswith(workspace_prefix):
            candidates.append(workspace_root / path.removeprefix(workspace_prefix))
        if path.startswith(distfiles_prefix):
            candidates.append(distfiles_root / path.removeprefix(distfiles_prefix))

        basename = Path(path).name
        if basename:
            candidates.append(workspace_root / basename)
            candidates.append(distfiles_root / basename)

        seen: set[str] = set()
        for candidate in candidates:
            try:
                resolved = candidate.resolve()
            except FileNotFoundError:
                resolved = candidate.absolute()

            resolved_str = str(resolved)
            if resolved_str in seen:
                continue
            seen.add(resolved_str)

            if not resolved.exists() or not resolved.is_file():
                continue

            if resolved.is_relative_to(workspace_root) or resolved.is_relative_to(distfiles_root):
                return resolved_str

        return None

    @staticmethod
    def _resolve_env_file_path() -> str | None:
        env_file = Path(".env").resolve()
        if env_file.exists():
            return str(env_file)
        return None

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
        self._available_file_paths = []
        self._refresh_available_file_paths()

        distfile_names = list_distfiles(self.challenge_dir)
        self._task_prompt = build_browser_use_prompt(
            self.meta,
            distfile_names,
            workspace_host_dir=self.sandbox.workspace_dir,
            distfiles_host_dir=self._distfiles_host_dir,
            env_file_path=self._env_file_path,
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

        self.tracer.event(
            "start",
            challenge=self.meta.name,
            model=self.model_spec,
            model_id=self.model_id,
        )
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
        from browser_use.browser import BrowserSession
        from browser_use.browser.events import TypeTextEvent, UploadFileEvent

        tools = Tools(exclude_actions=["read_file", "write_file", "replace_file"])
        if "upload_file" in tools.registry.registry.actions:
            del tools.registry.registry.actions["upload_file"]

        async def _input_secret_value(
            secret_name: str,
            secret_value: str,
            index: int,
            browser_session: BrowserSession,
            clear: bool = True,
        ) -> ActionResult:
            if not secret_value:
                return ActionResult(error=f"{secret_name} is not configured in .env or solver settings.")

            node = await browser_session.get_element_by_index(index)
            if node is None:
                msg = f"Element index {index} not available - page may have changed. Try refreshing browser state."
                logger.warning(f"⚠️ {msg}")
                return ActionResult(extracted_content=msg)

            event = browser_session.event_bus.dispatch(
                TypeTextEvent(
                    node=node,
                    text=secret_value,
                    clear=clear,
                    is_sensitive=True,
                    sensitive_key_name=secret_name,
                )
            )
            await event
            input_metadata = await event.event_result(raise_if_any=True, raise_if_none=False)
            msg = f"Typed {secret_name}"
            return ActionResult(
                extracted_content=msg,
                long_term_memory=msg,
                metadata=input_metadata if isinstance(input_metadata, dict) else None,
            )

        @tools.action(description="Execute a bash command in the Docker sandbox.")
        async def bash(command: str, timeout_seconds: int = 60) -> ActionResult:
            result = await do_bash(self.sandbox, command, timeout_seconds)
            self._refresh_available_file_paths()
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
            self._refresh_available_file_paths()
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

        @tools.action(
            description=(
                "Upload a file to an input element by index. Accepts `/challenge/workspace/...`, "
                "`/challenge/distfiles/...`, or the matching host path."
            )
        )
        async def upload_file(index: int, path: str, browser_session) -> ActionResult:
            resolved_path = self._resolve_browser_upload_path(path)
            if not resolved_path:
                return ActionResult(
                    error=(
                        f"File path {path} is not available for upload. "
                        "Use a file under `/challenge/workspace` or `/challenge/distfiles`."
                    )
                )

            node = await browser_session.get_element_by_index(index)
            if node is None:
                msg = f"Element index {index} not available - page may have changed. Try refreshing browser state."
                logger.warning(f"⚠️ {msg}")
                return ActionResult(extracted_content=msg)

            event = browser_session.event_bus.dispatch(
                UploadFileEvent(
                    node=node,
                    file_path=resolved_path,
                )
            )
            await event
            await event.event_result(raise_if_any=True, raise_if_none=False)
            msg = f"Uploaded file {resolved_path}"
            return ActionResult(
                extracted_content=msg,
                long_term_memory=msg,
            )

        @tools.action(description="Type the configured CTFd API token into an element by index.")
        async def input_ctfd_token(index: int, browser_session, clear: bool = True) -> ActionResult:
            return await _input_secret_value("ctfd_token", self.ctfd.token, index, browser_session, clear)

        @tools.action(description="Type the configured CTFd username into an element by index.")
        async def input_ctfd_username(index: int, browser_session, clear: bool = True) -> ActionResult:
            return await _input_secret_value("ctfd_username", self.ctfd.username, index, browser_session, clear)

        @tools.action(description="Type the configured CTFd password into an element by index.")
        async def input_ctfd_password(index: int, browser_session, clear: bool = True) -> ActionResult:
            return await _input_secret_value("ctfd_password", self.ctfd.password, index, browser_session, clear)

        @tools.action(description="Type the configured CTFd site password into an element by index.")
        async def input_ctfd_site_password(
            index: int,
            browser_session,
            clear: bool = True,
        ) -> ActionResult:
            return await _input_secret_value(
                "ctfd_site_password",
                self.ctfd.site_password,
                index,
                browser_session,
                clear,
            )

        @tools.action(description="Send a strategic message to the coordinator.")
        async def notify_coordinator(message: str) -> ActionResult:
            if self.notify_coordinator:
                await self.notify_coordinator(message)
                return ActionResult(extracted_content="Message sent to coordinator.")
            return ActionResult(extracted_content="No coordinator connected.")

        return tools

    def _build_run_prompt(self) -> str:
        secure_input_hint = ""
        if self.ctfd.token or self.ctfd.username or self.ctfd.password or self.ctfd.site_password:
            env_source = "the repo `.env` file"
            if self._env_file_path:
                env_source = f"`{self._env_file_path}`"
            secure_input_hint = (
                "\n8. If a page asks for CTFd auth, use the dedicated `input_ctfd_*` actions "
                f"backed by values from {env_source}. `input_ctfd_token` uses `CTFD_TOKEN`. "
                "Do not type placeholder names or env var names into the page."
            )

        if self._bump_insights:
            prompt = (
                f"{self._task_prompt}\n\n"
                "## New Insights From Other Solvers\n"
                f"{self._bump_insights}\n\n"
                "Continue from the current browser state and sandbox workspace. "
                "Try a different technical approach and avoid repeating failed ideas."
            )
            self._bump_insights = None
            return prompt + secure_input_hint

        if self._step_count == 0:
            return self._task_prompt + secure_input_hint

        return (
            f"{self._task_prompt}\n\n"
            "Continue from the current browser state and sandbox workspace. "
            "Try a different approach than before."
            f"{secure_input_hint}"
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

        agent = Agent(
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
        self._agent = agent
        return agent

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
            history = await agent.run(max_steps=300)
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
        self._agent = None
        if self._profile_dir:
            shutil.rmtree(self._profile_dir, ignore_errors=True)
            self._profile_dir = None
        if self.sandbox:
            await self.sandbox.stop()
