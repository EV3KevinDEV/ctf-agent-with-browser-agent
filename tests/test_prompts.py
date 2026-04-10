from __future__ import annotations

from backend.prompts import ChallengeMeta, build_browser_use_prompt


def test_build_browser_use_prompt_preserves_localhost_and_browser_first() -> None:
    meta = ChallengeMeta(
        name="browser challenge",
        category="web",
        value=250,
        description="Use a browser to solve it.",
        connection_info="http://localhost:8000/login",
    )

    prompt = build_browser_use_prompt(
        meta,
        ["app.js", "seed.txt"],
        workspace_host_dir="/tmp/workspace",
        distfiles_host_dir="/tmp/distfiles",
    )

    assert "http://localhost:8000/login" in prompt
    assert "host.docker.internal" not in prompt
    assert "FIRST ACTION REQUIRED" in prompt
    assert "open the target URL in the browser immediately" in prompt
    assert "web_fetch" not in prompt
