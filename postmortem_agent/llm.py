"""Minimal Anthropic client for live investigation mode (stdlib only)."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any


class LLMError(RuntimeError):
    pass


def anthropic_api_key() -> str:
    key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    if not key or "paste" in key.lower():
        raise LLMError("ANTHROPIC_API_KEY is required for --mode llm")
    return key


def decide_next_action(
    *,
    system: str,
    messages: list[dict[str, Any]],
    model: str | None = None,
) -> dict[str, Any]:
    """Return parsed JSON action from the model."""
    model = model or os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-20250514")
    body = {
        "model": model,
        "max_tokens": 1024,
        "system": system,
        "messages": messages,
    }
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=json.dumps(body).encode("utf-8"),
        headers={
            "content-type": "application/json",
            "x-api-key": anthropic_api_key(),
            "anthropic-version": "2023-06-01",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise LLMError(f"Anthropic API error {exc.code}: {detail}") from exc

    text_blocks = [
        block.get("text", "")
        for block in payload.get("content", [])
        if block.get("type") == "text"
    ]
    raw = "".join(text_blocks).strip()
    if raw.startswith("```"):
        raw = raw.split("\n", 1)[-1]
        if raw.endswith("```"):
            raw = raw.rsplit("```", 1)[0]
    try:
        action = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise LLMError(f"LLM returned non-JSON: {raw[:500]}") from exc
    if not isinstance(action, dict):
        raise LLMError("LLM action must be a JSON object")
    return action
