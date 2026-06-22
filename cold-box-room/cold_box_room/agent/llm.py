"""Anthropic client helpers — prompt caching (ported from cold-box-final)."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from cold_box_room.r1.paths import REPO_ROOT


def _dotenv_candidates() -> list[Path]:
    candidates: list[Path] = []
    explicit = os.environ.get("COLD_BOX_DOTENV", "").strip()
    if explicit:
        candidates.append(Path(explicit).expanduser())
    candidates.extend(
        [
            REPO_ROOT.parent / ".env",
            REPO_ROOT / ".env",
            Path.cwd() / ".env",
            Path("/opt/postmortem/.env"),
        ]
    )
    seen: set[Path] = set()
    unique: list[Path] = []
    for path in candidates:
        resolved = path.expanduser()
        if resolved in seen:
            continue
        seen.add(resolved)
        unique.append(resolved)
    return unique


def load_dotenv() -> None:
    for path in _dotenv_candidates():
        if not path.is_file():
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = val
        return


def anthropic_api_key() -> str:
    key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    if not key or "paste" in key.lower():
        raise RuntimeError(
            "ANTHROPIC_API_KEY missing — set ANTHROPIC_API_KEY or add it to "
            f"{REPO_ROOT.parent / '.env'} (or set COLD_BOX_DOTENV)"
        )
    return key


def anthropic_model(explicit: str | None = None) -> str:
    return (
        explicit
        or os.environ.get("COLD_BOX_AGENT_MODEL")
        or os.environ.get("ANTHROPIC_MODEL")
        or "claude-sonnet-4-20250514"
    ).strip()


def prompt_cache_enabled() -> bool:
    raw = os.environ.get("ANTHROPIC_PROMPT_CACHE", "1").strip().lower()
    return raw not in {"0", "false", "no", "off"}


def prompt_cache_ttl() -> str | None:
    raw = os.environ.get("ANTHROPIC_PROMPT_CACHE_TTL", "").strip().lower()
    if raw in {"1h", "60m", "hour"}:
        return "1h"
    return None


def cache_control_block() -> dict[str, str]:
    ttl = prompt_cache_ttl()
    if ttl:
        return {"type": "ephemeral", "ttl": ttl}
    return {"type": "ephemeral"}


def static_system_block(text: str) -> str | list[dict[str, Any]]:
    if prompt_cache_enabled():
        return [{"type": "text", "text": text, "cache_control": cache_control_block()}]
    return text


def cached_tools(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not prompt_cache_enabled() or not tools:
        return tools
    out = [dict(t) for t in tools]
    out[-1] = {**out[-1], "cache_control": cache_control_block()}
    return out


def log_usage(response: Any) -> dict[str, int | None]:
    usage = getattr(response, "usage", None)
    if usage is None:
        return {}
    data = {
        "input_tokens": getattr(usage, "input_tokens", None),
        "output_tokens": getattr(usage, "output_tokens", None),
        "cache_read_input_tokens": getattr(usage, "cache_read_input_tokens", None),
        "cache_creation_input_tokens": getattr(usage, "cache_creation_input_tokens", None),
    }
    if os.environ.get("ANTHROPIC_LOG_USAGE", "").strip().lower() in {"1", "true", "yes"}:
        print("[anthropic usage]", json.dumps(data, sort_keys=True), flush=True)
    return data
