from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from backend.agents.browser_use_solver import BrowserUseSolver
from backend.agents.solver import Solver
from backend.agents.swarm import ChallengeSwarm
from backend.cost_tracker import CostTracker
from backend.ctfd import CTFdClient
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

    browser_solver = swarm._create_solver("browser-use/bu-latest")
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
