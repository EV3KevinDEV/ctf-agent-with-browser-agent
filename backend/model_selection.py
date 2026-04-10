"""Challenge-aware solver model selection."""

from __future__ import annotations

import logging
import shutil
from pathlib import Path

from backend.prompts import ChallengeMeta

logger = logging.getLogger(__name__)

BROWSER_USE_MODEL_SPEC = "browser-use/bu-latest"


def challenge_looks_browser_needed(meta: ChallengeMeta) -> bool:
    """Heuristic: detect challenges that likely need a real browser."""
    category = (meta.category or "").strip().lower()
    if "web" in category:
        return True

    conn = (meta.connection_info or "").strip().lower()
    if conn.startswith("http://") or conn.startswith("https://"):
        return True

    desc = (meta.description or "").lower()
    web_signals = (
        "javascript",
        "xss",
        "csrf",
        "cookie",
        "dom",
        "browser",
        "websocket",
    )
    return any(sig in desc for sig in web_signals)


def _browser_use_available(settings: object) -> bool:
    """Check whether Browser Use can be started on this host."""
    api_key = getattr(settings, "browser_use_api_key", "").strip()
    if not api_key:
        return False

    configured_path = getattr(settings, "browser_use_executable_path", "").strip()
    if configured_path:
        return Path(configured_path).exists()

    for candidate in ("google-chrome", "chromium", "chromium-browser"):
        if shutil.which(candidate):
            return True
    return False


def select_models_for_challenge(
    base_model_specs: list[str],
    meta: ChallengeMeta,
    settings: object,
) -> list[str]:
    """Return per-challenge model specs, auto-adding browser-use when useful."""
    specs = list(base_model_specs)
    if any(spec.startswith("browser-use/") for spec in specs):
        return specs

    auto_enable = getattr(settings, "browser_use_auto_enable", True)
    if not auto_enable:
        return specs

    if not challenge_looks_browser_needed(meta):
        return specs

    if not _browser_use_available(settings):
        logger.info(
            "[%s] Browser-like challenge detected, but Browser Use prerequisites "
            "are missing (BROWSER_USE_API_KEY and host Chrome/Chromium).",
            meta.name,
        )
        return specs

    specs.append(BROWSER_USE_MODEL_SPEC)
    logger.info(
        "[%s] Auto-enabled %s for browser-heavy challenge.",
        meta.name,
        BROWSER_USE_MODEL_SPEC,
    )
    return specs
