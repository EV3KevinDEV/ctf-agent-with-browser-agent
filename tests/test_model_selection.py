from __future__ import annotations

from types import SimpleNamespace

from backend.model_selection import (
    BROWSER_USE_MODEL_SPEC,
    challenge_looks_browser_needed,
    select_models_for_challenge,
)
from backend.prompts import ChallengeMeta


def _settings(**overrides):
    base = {
        "browser_use_auto_enable": True,
        "browser_use_api_key": "test-key",
        "browser_use_executable_path": "",
    }
    base.update(overrides)
    return SimpleNamespace(**base)


def test_browser_needed_for_web_category() -> None:
    meta = ChallengeMeta(name="web-1", category="web", description="x")
    assert challenge_looks_browser_needed(meta) is True


def test_browser_needed_for_http_connection() -> None:
    meta = ChallengeMeta(name="web-2", category="misc", connection_info="https://target.local")
    assert challenge_looks_browser_needed(meta) is True


def test_browser_not_needed_for_non_web() -> None:
    meta = ChallengeMeta(name="crypto-1", category="crypto", description="rsa warmup")
    assert challenge_looks_browser_needed(meta) is False


def test_select_models_auto_adds_browser_use(monkeypatch) -> None:
    monkeypatch.setattr("backend.model_selection.shutil.which", lambda _: "/usr/bin/google-chrome")
    meta = ChallengeMeta(name="web-3", category="web", description="browser task")

    selected = select_models_for_challenge(
        ["claude-sdk/claude-opus-4-6/medium"],
        meta,
        _settings(),
    )

    assert selected == ["claude-sdk/claude-opus-4-6/medium", BROWSER_USE_MODEL_SPEC]


def test_select_models_no_duplicate_if_already_present(monkeypatch) -> None:
    monkeypatch.setattr("backend.model_selection.shutil.which", lambda _: "/usr/bin/google-chrome")
    base = ["claude-sdk/claude-opus-4-6/medium", BROWSER_USE_MODEL_SPEC]
    meta = ChallengeMeta(name="web-4", category="web")

    selected = select_models_for_challenge(base, meta, _settings())

    assert selected == base


def test_select_models_skips_when_missing_key(monkeypatch) -> None:
    monkeypatch.setattr("backend.model_selection.shutil.which", lambda _: "/usr/bin/google-chrome")
    meta = ChallengeMeta(name="web-5", category="web")

    selected = select_models_for_challenge(
        ["claude-sdk/claude-opus-4-6/medium"],
        meta,
        _settings(browser_use_api_key=""),
    )

    assert selected == ["claude-sdk/claude-opus-4-6/medium"]


def test_select_models_skips_when_auto_disabled(monkeypatch) -> None:
    monkeypatch.setattr("backend.model_selection.shutil.which", lambda _: "/usr/bin/google-chrome")
    meta = ChallengeMeta(name="web-6", category="web")

    selected = select_models_for_challenge(
        ["claude-sdk/claude-opus-4-6/medium"],
        meta,
        _settings(browser_use_auto_enable=False),
    )

    assert selected == ["claude-sdk/claude-opus-4-6/medium"]
