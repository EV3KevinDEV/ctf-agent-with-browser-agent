"""System prompt builder + ChallengeMeta."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from backend.tools.core import IMAGE_EXTS_FOR_VISION as IMAGE_EXTS


@dataclass
class ChallengeMeta:
    name: str = "Unknown"
    category: str = ""
    value: int = 0
    description: str = ""
    tags: list[str] = field(default_factory=list)
    connection_info: str = ""
    hints: list[dict[str, Any]] = field(default_factory=list)
    solves: int = 0

    @classmethod
    def from_yaml(cls, path: str | Path) -> ChallengeMeta:
        with open(path) as f:
            data = yaml.safe_load(f) or {}
        return cls(
            name=data.get("name", "Unknown"),
            category=data.get("category", ""),
            value=data.get("value", 0),
            description=data.get("description", ""),
            tags=data.get("tags", []),
            connection_info=data.get("connection_info", ""),
            hints=data.get("hints", []),
            solves=data.get("solves", 0),
        )


def list_distfiles(challenge_dir: str) -> list[str]:
    dist = Path(challenge_dir) / "distfiles"
    if not dist.exists():
        return []
    return sorted(f.name for f in dist.iterdir() if f.is_file())


def _rewrite_connection_info(conn: str) -> str:
    """Replace localhost/127.0.0.1 with host.docker.internal for bridge networking."""
    if not conn:
        return conn
    conn = re.sub(r"\blocalhost\b", "host.docker.internal", conn)
    conn = re.sub(r"\b127\.0\.0\.1\b", "host.docker.internal", conn)
    return conn


def build_prompt(
    meta: ChallengeMeta,
    distfile_names: list[str],
    container_arch: str = "unknown",
    has_named_tools: bool = True,
) -> str:
    """Build the system prompt.

    has_named_tools: True for Pydantic AI solver (has view_image, webhook_create, etc.
    as discrete tools). False for Claude SDK (bash-only — model should use
    steghide/exiftool/curl instead). Codex has named dynamic tools so uses True.
    """
    conn_info = _rewrite_connection_info(meta.connection_info.strip())

    lines: list[str] = [
        "You are an expert CTF solver. Find the real flag for the challenge below.",
        "",
    ]

    if conn_info:
        lines += [
            "> **FIRST ACTION REQUIRED**: Your very first tool call MUST connect to the service.",
            f"> Run: `{conn_info}` (use a heredoc or pwntools script as shown below).",
            "> Do NOT explore the sandbox filesystem first. The flag is on the service, not in the container.",
            "",
        ]

    lines += [
        "## Challenge",
        f"**Name**    : {meta.name}",
        f"**Category**: {meta.category or 'Unknown'}",
        f"**Points**  : {meta.value or '?'}",
        f"**Arch**    : {container_arch}",
    ]
    if meta.tags:
        lines.append(f"**Tags**    : {', '.join(meta.tags)}")
    lines += ["", "## Description", meta.description or "_No description provided._", ""]

    if conn_info:
        if re.match(r"^https?://", conn_info):
            hint = "This is a **web service**. Use `bash` with `curl`/`python3 requests`, or use `web_fetch`."
        elif conn_info.startswith("nc "):
            hint = (
                "This is a **TCP service**. Each `bash` call is a fresh process — "
                "use a heredoc to send multiple lines in one shot:\n"
                "```\n"
                f"{conn_info} <<'EOF'\ncommand1\ncommand2\nEOF\n"
                "```\n"
                "Or write a Python `socket` / `pwntools` script for stateful interaction."
            )
        else:
            hint = "Connect using the details above."
        lines += ["## Service Connection", "```", conn_info, "```", hint, ""]

    if distfile_names:
        lines.append("## Attached Files")
        for name in distfile_names:
            ext = Path(name).suffix.lower()
            is_img = ext in IMAGE_EXTS
            if is_img and has_named_tools:
                suffix = "  <- **IMAGE: call `view_image` immediately** (fix magic bytes first if corrupt)"
            elif is_img:
                suffix = "  <- **IMAGE: use `exiftool`, `steghide`, `zsteg`, `strings` via bash**"
            else:
                suffix = ""
            lines.append(f"- `/challenge/distfiles/{name}`{suffix}")
        lines.append("")

    visible_hints = [h for h in meta.hints if h.get("content")]
    if visible_hints:
        lines.append("## Hints")
        for h in visible_hints:
            lines.append(f"- {h['content']}")
        lines.append("")

    # pyghidra is always installed in the sandbox — show for RE/pwn/misc categories
    # or when distfiles contain binaries (non-text files)
    cat_lower = (meta.category or "").lower()
    if cat_lower in ("reverse", "reversing", "re", "pwn", "binary", "misc", ""):
        lines += [
            "## Binary Analysis",
            "**pyghidra** is installed for decompilation. Use it via bash:",
            "```python",
            "import pyghidra",
            "with pyghidra.open_program('/challenge/distfiles/binary') as flat_api:",
            "    listing = flat_api.currentProgram.getListing()",
            "    # Iterate functions, decompile, etc.",
            "```",
            "Also available: radare2 (`r2`), gdb, angr, capstone.",
            "",
        ]

    if has_named_tools:
        image_hint = "**Images: call `view_image` FIRST, before any other analysis.**"
        web_hint = "Web: fuzz params, check JS source, cookies, robots.txt. For XSS/SSRF: use `webhook_create`."
        submit_hint = "**Verify every candidate with `submit_flag`** before reporting."
    else:
        image_hint = "**Images: use `exiftool`, `steghide`, `zsteg`, `strings`, `xxd` via bash.**"
        web_hint = "Web: fuzz params, check JS source, cookies, robots.txt. For XSS/SSRF: use `curl` to webhook.site."
        submit_hint = "**Verify every candidate with `submit_flag '<flag>'`** (bash command) before reporting."

    lines += [
        "",
        "## Instructions",
        "**Use tools immediately. Do not describe — execute.**",
        "",
        "1. " + ("Connect to the service now." if conn_info else "Inspect distfiles now."),
        "2. Keep using tools until you have the flag.",
        "3. **Be creative and thorough** — try the obvious path, then explore further:",
        "   - Hidden files, env vars, backup files, HTTP headers, error messages, timing, encoding tricks.",
        f"   - {image_hint}",
        f"   - {web_hint}",
        (
            "   - Crypto: identify algorithm, weak keys, nonce reuse, padding oracles. "
            "For RSA: use `RsaCtfTool`, sage ECM, or `cado-nfs`."
        ),
        "   - Pwn: `stty raw -echo` before launching vulnerable binaries over nc.",
        '4. **Ignore placeholder flags** — `CTF{flag}`, `CTF{placeholder}` are not real flags.',
        f"5. {submit_hint}",
        "6. Once CORRECT: output `FLAG: <value>` on its own line.",
        "7. Do not guess. Do not ask. Cover maximum surface area.",
    ]

    return "\n".join(lines)


def build_browser_use_prompt(
    meta: ChallengeMeta,
    distfile_names: list[str],
    workspace_host_dir: str,
    distfiles_host_dir: str,
    env_file_path: str | None = None,
) -> str:
    """Build a Browser Use specific task prompt.

    Browser Use runs on the host, so localhost/127.0.0.1 must remain unchanged.
    Sandbox-backed custom actions still operate on /challenge paths inside Docker.
    """
    conn_info = meta.connection_info.strip()

    lines: list[str] = [
        "You are an expert browser-driven CTF solver.",
        "Use the browser for interactive web work and the custom sandbox actions for shell, files, and flag submission.",
        "",
    ]

    if conn_info:
        lines += [
            "> **FIRST ACTION REQUIRED**: If the target is HTTP/HTTPS, open the target URL in the browser immediately.",
            f"> Navigate to: `{conn_info}`",
            "> Keep `localhost` and `127.0.0.1` exactly as written because the browser runs on the host.",
            "",
        ]

    lines += ["## Secure Auth"]
    if env_file_path:
        lines.append(f"Repo env file: `{env_file_path}`")
    lines += [
        "If a page asks for the CTFd API token, call `input_ctfd_token` on the token field.",
        "`input_ctfd_token` types the real value of `CTFD_TOKEN` loaded from `.env`.",
        "If a page asks for the CTFd username, password, or site password, use the matching `input_ctfd_*` action.",
        "These actions type the real values loaded from `.env` and solver settings.",
    ]
    lines += [
        "Do not type placeholder labels, env var names, or literal `<secret>...</secret>` tags into the page.",
        "",
    ]

    lines += [
        "## Challenge",
        f"**Name**    : {meta.name}",
        f"**Category**: {meta.category or 'Unknown'}",
        f"**Points**  : {meta.value or '?'}",
    ]
    if meta.tags:
        lines.append(f"**Tags**    : {', '.join(meta.tags)}")
    lines += ["", "## Description", meta.description or "_No description provided._", ""]

    if conn_info:
        lines += [
            "## Service Connection",
            "```",
            conn_info,
            "```",
            (
                "If this is a browser challenge, use browser actions like navigate, click, input, "
                "extract, evaluate, upload_file, and done."
            ),
            "",
        ]

    if distfile_names:
        lines.append("## Attached Files")
        for name in distfile_names:
            lines.append(f"- Sandbox path: `/challenge/distfiles/{name}`")
        lines.append("")

    visible_hints = [h for h in meta.hints if h.get("content")]
    if visible_hints:
        lines.append("## Hints")
        for h in visible_hints:
            lines.append(f"- {h['content']}")
        lines.append("")

    lines += [
        "## Tooling",
        "Browser actions: search, navigate, click, input, scroll, extract, evaluate, upload_file, screenshot, done.",
        (
            "Custom sandbox actions: bash, list_files, read_file, write_file, submit_flag, "
            "webhook_create, webhook_get_requests, check_findings, notify_coordinator."
        ),
        (
            "Auth actions: input_ctfd_token, input_ctfd_username, input_ctfd_password, "
            "input_ctfd_site_password."
        ),
        "Sandbox paths: `/challenge/distfiles` is read-only, `/challenge/workspace` is writable.",
        f"Browser upload host path for distfiles: `{distfiles_host_dir}`",
        f"Browser download/generated host path: `{workspace_host_dir}`",
        "Anything downloaded by the browser appears inside the sandbox at `/challenge/workspace`.",
        (
            "Important: when you create a file for browser upload, write it with `bash` to "
            "`/challenge/workspace/<name>` inside the sandbox, then call `upload_file` with either "
            f"`/challenge/workspace/<name>` or the matching host path `{workspace_host_dir}/<name>`."
        ),
        "",
        "## Instructions",
        "1. If the challenge is web-based, open the target URL in the browser first.",
        "2. Use browser-native actions for dynamic pages, auth flows, JS-heavy apps, and uploads.",
        "3. Use sandbox actions for curl/bash/scripts, local file inspection, exploit code, and post-download analysis.",
        "4. Use `check_findings` periodically to pick up sibling discoveries.",
        "5. Use `submit_flag` to verify every real candidate before finishing.",
        "6. Once the flag is confirmed, stop and return structured output with `type=flag_found`, the exact `flag`, and a brief `method`.",
        "7. Do not rely on tools from other backends; stick to browser-native actions and the custom sandbox actions listed above.",
    ]

    return "\n".join(lines)
