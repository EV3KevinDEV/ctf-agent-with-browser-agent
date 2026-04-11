from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

from backend.agents.browser_use_solver import BrowserUseSolver
from backend.agents.solver import Solver
from backend.agents.swarm import ChallengeSwarm
from backend.cost_tracker import CostTracker
from backend.ctfd import CTFdClient
from backend.model_selection import BROWSER_USE_MODEL_SPEC
from backend.prompts import ChallengeMeta
from backend.solver_base import FLAG_FOUND


def _settings(**overrides):
    base = {
        "sandbox_image": "ctf-sandbox",
        "container_memory_limit": "4g",
        "browser_use_api_key": "test-browser-use-key",
        "browser_use_executable_path": "",
        "browser_use_headless": True,
    }
    base.update(overrides)
    return SimpleNamespace(**base)


def _meta() -> ChallengeMeta:
    return ChallengeMeta(
        name="web challenge",
        category="web",
        value=100,
        description="Solve the site.",
        connection_info="http://localhost:8000",
    )


def test_swarm_routes_browser_use_solver() -> None:
    swarm = ChallengeSwarm(
        challenge_dir=".",
        meta=_meta(),
        ctfd=CTFdClient(),
        cost_tracker=CostTracker(),
        settings=_settings(),
    )

    browser_solver = swarm._create_solver(BROWSER_USE_MODEL_SPEC)
    default_solver = swarm._create_solver("azure/gpt-5.4")

    assert isinstance(browser_solver, BrowserUseSolver)
    assert isinstance(default_solver, Solver)


def test_browser_use_start_requires_api_key() -> None:
    solver = BrowserUseSolver(
        model_spec="browser-use/bu-latest",
        challenge_dir=".",
        meta=_meta(),
        ctfd=CTFdClient(),
        cost_tracker=CostTracker(),
        settings=_settings(browser_use_api_key=""),
    )

    with pytest.raises(RuntimeError, match="BROWSER_USE_API_KEY"):
        asyncio.run(solver.start())


def test_browser_use_start_requires_browser_executable(monkeypatch: pytest.MonkeyPatch) -> None:
    solver = BrowserUseSolver(
        model_spec="browser-use/bu-latest",
        challenge_dir=".",
        meta=_meta(),
        ctfd=CTFdClient(),
        cost_tracker=CostTracker(),
        settings=_settings(),
    )

    monkeypatch.setattr("backend.agents.browser_use_solver.shutil.which", lambda _: None)

    with pytest.raises(RuntimeError, match="Chrome/Chromium"):
        asyncio.run(solver.start())


def test_browser_use_usage_summary_is_recorded() -> None:
    tracker = CostTracker()
    solver = BrowserUseSolver(
        model_spec="browser-use/bu-latest",
        challenge_dir=".",
        meta=_meta(),
        ctfd=CTFdClient(),
        cost_tracker=tracker,
        settings=_settings(),
    )

    history = SimpleNamespace(
        usage=SimpleNamespace(
            total_prompt_tokens=120,
            total_prompt_cached_tokens=20,
            total_completion_tokens=45,
            total_cost=1.75,
        )
    )

    solver._apply_usage_summary(history, duration_seconds=3.5)

    usage = tracker.by_agent[solver.agent_name]
    assert usage.usage.input_tokens == 120
    assert usage.usage.cache_read_tokens == 20
    assert usage.usage.output_tokens == 45
    assert usage.cost_usd == pytest.approx(1.75)
    assert usage.duration_seconds == pytest.approx(3.5)


def test_confirmed_flag_returns_flag_found() -> None:
    solver = BrowserUseSolver(
        model_spec="browser-use/bu-latest",
        challenge_dir=".",
        meta=_meta(),
        ctfd=CTFdClient(),
        cost_tracker=CostTracker(),
        settings=_settings(),
    )
    solver._confirmed = True
    solver._flag = "flag{browser-use}"

    history = SimpleNamespace(
        usage=None,
        structured_output=None,
        final_result=lambda: "",
        number_of_steps=lambda: 4,
    )

    result = solver._finish_from_history(history, duration_seconds=1.2)

    assert result.status == FLAG_FOUND
    assert result.flag == "flag{browser-use}"
    assert result.step_count == 4


def test_browser_use_agent_does_not_pass_sensitive_data(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    class FakeAgent:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    class FakeChatBrowserUse:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

    fake_browser_use = ModuleType("browser_use")
    fake_browser_use.Agent = FakeAgent
    fake_browser_use.ChatBrowserUse = FakeChatBrowserUse
    monkeypatch.setitem(sys.modules, "browser_use", fake_browser_use)

    solver = BrowserUseSolver(
        model_spec="browser-use/bu-latest",
        challenge_dir=".",
        meta=_meta(),
        ctfd=CTFdClient(
            base_url="https://ctf.umasscybersec.org/",
            token="ctfd-token",
            username="KLabs",
            password="site-pass",
        ),
        cost_tracker=CostTracker(),
        settings=_settings(),
    )
    solver._browser = object()
    solver._tools = object()
    solver._available_file_paths = ["/challenge/workspace"]

    solver._make_agent("test task")

    assert "sensitive_data" not in captured
    assert captured["available_file_paths"] == ["/challenge/workspace"]


def test_browser_use_refreshes_uploadable_host_paths_in_place(tmp_path: Path) -> None:
    solver = BrowserUseSolver(
        model_spec="browser-use/bu-latest",
        challenge_dir=".",
        meta=_meta(),
        ctfd=CTFdClient(),
        cost_tracker=CostTracker(),
        settings=_settings(),
    )

    workspace_dir = tmp_path / "workspace"
    distfiles_dir = tmp_path / "distfiles"
    env_file = tmp_path / ".env"
    workspace_dir.mkdir()
    distfiles_dir.mkdir()
    env_file.write_text("CTFD_TOKEN=test\n", encoding="utf-8")
    exploit_file = workspace_dir / "exploit.txt"
    distfile = distfiles_dir / "payload.txt"
    exploit_file.write_text("exploit", encoding="utf-8")
    distfile.write_text("payload", encoding="utf-8")

    solver.sandbox.workspace_dir = str(workspace_dir)
    solver._distfiles_host_dir = str(distfiles_dir)
    solver._env_file_path = str(env_file)
    solver._available_file_paths = ["stale-path"]
    original_paths = solver._available_file_paths
    solver._agent = SimpleNamespace(available_file_paths=["old-agent-list"])

    solver._refresh_available_file_paths()

    assert solver._available_file_paths is original_paths
    assert str(workspace_dir.resolve()) in solver._available_file_paths
    assert str(exploit_file.resolve()) in solver._available_file_paths
    assert str(distfiles_dir.resolve()) in solver._available_file_paths
    assert str(distfile.resolve()) in solver._available_file_paths
    assert str(env_file.resolve()) in solver._available_file_paths
    assert solver._agent.available_file_paths is solver._available_file_paths


def test_browser_use_tools_include_ctfd_auth_input_actions() -> None:
    from browser_use.dom.views import NodeType

    solver = BrowserUseSolver(
        model_spec="browser-use/bu-latest",
        challenge_dir=".",
        meta=_meta(),
        ctfd=CTFdClient(
            base_url="https://ctf.umasscybersec.org/",
            token="ctfd-token",
            username="KLabs",
            password="site-pass",
            site_password="gate-pass",
        ),
        cost_tracker=CostTracker(),
        settings=_settings(),
    )
    tools = solver._build_tools()

    action_names = tools.registry.registry.actions.keys()

    assert "input_ctfd_token" in action_names
    assert "input_ctfd_username" in action_names
    assert "input_ctfd_password" in action_names
    assert "input_ctfd_site_password" in action_names

    class FakeEvent:
        def __init__(self, event):
            self.event = event

        def __await__(self):
            async def _done():
                return None

            return _done().__await__()

        async def event_result(self, raise_if_any=True, raise_if_none=False):
            return {"actual_value": self.event.text}

    class FakeEventBus:
        def __init__(self) -> None:
            self.dispatched = None

        def dispatch(self, event):
            self.dispatched = event
            return FakeEvent(event)

    class FakeBrowserSession:
        def __init__(self) -> None:
            self.event_bus = FakeEventBus()
            self.cdp_client = object()

        async def get_element_by_index(self, index: int):
            return SimpleNamespace(
                node_id=index,
                backend_node_id=index,
                session_id=None,
                frame_id=None,
                target_id="test-tab",
                node_type=NodeType.ELEMENT_NODE,
                node_name="INPUT",
                node_value="",
                attributes={},
                is_scrollable=False,
                is_visible=True,
                absolute_position=None,
            )

    async def run_action() -> None:
        browser_session = FakeBrowserSession()

        result = await tools.registry.execute_action(
            "input_ctfd_token",
            {"index": 7, "clear": True},
            browser_session=browser_session,
        )

        assert result.extracted_content == "Typed ctfd_token"
        assert browser_session.event_bus.dispatched.text == "ctfd-token"

    asyncio.run(run_action())


def test_browser_use_upload_file_action_resolves_workspace_path(tmp_path: Path) -> None:
    from browser_use.dom.views import NodeType

    solver = BrowserUseSolver(
        model_spec="browser-use/bu-latest",
        challenge_dir=".",
        meta=_meta(),
        ctfd=CTFdClient(),
        cost_tracker=CostTracker(),
        settings=_settings(),
    )

    workspace_dir = tmp_path / "workspace"
    distfiles_dir = tmp_path / "distfiles"
    workspace_dir.mkdir()
    distfiles_dir.mkdir()
    exploit_file = workspace_dir / "exploit.html"
    exploit_file.write_text("<html></html>", encoding="utf-8")

    solver.sandbox.workspace_dir = str(workspace_dir)
    solver._distfiles_host_dir = str(distfiles_dir)
    tools = solver._build_tools()

    class FakeEvent:
        def __init__(self, event):
            self.event = event

        def __await__(self):
            async def _done():
                return None

            return _done().__await__()

        async def event_result(self, raise_if_any=True, raise_if_none=False):
            return None

    class FakeEventBus:
        def __init__(self) -> None:
            self.dispatched = None

        def dispatch(self, event):
            self.dispatched = event
            return FakeEvent(event)

    class FakeBrowserSession:
        def __init__(self) -> None:
            self.event_bus = FakeEventBus()
            self.cdp_client = object()

        async def get_element_by_index(self, index: int):
            return SimpleNamespace(
                node_id=index,
                backend_node_id=index,
                session_id=None,
                frame_id=None,
                target_id="test-tab",
                node_type=NodeType.ELEMENT_NODE,
                node_name="INPUT",
                node_value="",
                attributes={"type": "file"},
                is_scrollable=False,
                is_visible=True,
                absolute_position=None,
            )

    async def run_action() -> None:
        browser_session = FakeBrowserSession()

        result = await tools.registry.execute_action(
            "upload_file",
            {"index": 5, "path": "/challenge/workspace/exploit.html"},
            browser_session=browser_session,
        )

        assert result.extracted_content == f"Uploaded file {exploit_file.resolve()}"
        assert browser_session.event_bus.dispatched.file_path == str(exploit_file.resolve())

    asyncio.run(run_action())


def test_browser_use_run_prompt_uses_auth_actions() -> None:
    solver = BrowserUseSolver(
        model_spec="browser-use/bu-latest",
        challenge_dir=".",
        meta=_meta(),
        ctfd=CTFdClient(base_url="https://ctf.umasscybersec.org/", token="ctfd-token"),
        cost_tracker=CostTracker(),
        settings=_settings(),
    )
    solver._task_prompt = "base prompt"
    solver._env_file_path = "/repo/.env"

    prompt = solver._build_run_prompt()

    assert "input_ctfd_" in prompt
    assert "/repo/.env" in prompt
    assert "<secret>ctfd_token</secret>" not in prompt
