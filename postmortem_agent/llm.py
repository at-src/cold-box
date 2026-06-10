"""Anthropic Messages API client for live investigation mode (stdlib only)."""

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
        raise LLMError(
            "ANTHROPIC_API_KEY is required for --llm. "
            "Set it in /opt/postmortem/.env (see .env.example) and run: source bin/load-agent-env"
        )
    return key


def anthropic_model(explicit: str | None = None) -> str:
    return explicit or os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-20250514").strip()


def prompt_cache_enabled() -> bool:
    """Enable Anthropic prompt caching (see dont-commit-main-plan/claudecahce.md)."""
    raw = os.environ.get("ANTHROPIC_PROMPT_CACHE", "1").strip().lower()
    return raw not in {"0", "false", "no", "off"}


def prompt_cache_ttl() -> str | None:
    """Return cache TTL if set (5m default, or 1h)."""
    raw = os.environ.get("ANTHROPIC_PROMPT_CACHE_TTL", "").strip().lower()
    if raw in {"1h", "60m", "hour"}:
        return "1h"
    return None


def _cache_control_block() -> dict[str, str]:
    ttl = prompt_cache_ttl()
    if ttl:
        return {"type": "ephemeral", "ttl": ttl}
    return {"type": "ephemeral"}


def static_system_block(text: str, *, cache: bool = True) -> str | list[dict[str, Any]]:
    """Format system prompt; cache stable prefixes per Anthropic prompt caching guidance."""
    if cache and prompt_cache_enabled():
        return [{"type": "text", "text": text, "cache_control": _cache_control_block()}]
    return text


def _extract_text(payload: dict[str, Any]) -> str:
    text_blocks = [
        block.get("text", "")
        for block in payload.get("content", [])
        if block.get("type") == "text"
    ]
    return "".join(text_blocks).strip()


def _strip_json_fence(raw: str) -> str:
    if raw.startswith("```"):
        raw = raw.split("\n", 1)[-1]
        if raw.endswith("```"):
            raw = raw.rsplit("```", 1)[0]
    return raw.strip()


def _extract_json_object(raw: str) -> dict[str, Any]:
    """Parse a JSON object from model output that may include prose or fences."""
    raw = _strip_json_fence(raw.strip())
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass

    decoder = json.JSONDecoder()
    for index, char in enumerate(raw):
        if char != "{":
            continue
        try:
            parsed, _ = decoder.raw_decode(raw[index:])
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            return parsed

    raise LLMError(f"LLM returned non-JSON: {raw[:500]}")


def parse_json_response(raw: str) -> dict[str, Any]:
    parsed = _extract_json_object(raw)
    if not isinstance(parsed, dict):
        raise LLMError("LLM action must be a JSON object")
    return parsed


def complete_messages(
    *,
    system: str | list[dict[str, Any]],
    messages: list[dict[str, Any]],
    model: str | None = None,
    max_tokens: int = 1024,
    use_prompt_cache: bool | None = None,
) -> dict[str, Any]:
    """Call Anthropic Messages API; return full response payload."""
    model_id = anthropic_model(model)
    body: dict[str, Any] = {
        "model": model_id,
        "max_tokens": max_tokens,
        "system": system,
        "messages": messages,
    }
    cache_on = prompt_cache_enabled() if use_prompt_cache is None else use_prompt_cache
    if cache_on:
        body["cache_control"] = _cache_control_block()

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

    if os.environ.get("ANTHROPIC_LOG_USAGE", "").strip().lower() in {"1", "true", "yes"}:
        usage = payload.get("usage") or {}
        print(
            "[anthropic usage]",
            json.dumps(
                {
                    "input_tokens": usage.get("input_tokens"),
                    "output_tokens": usage.get("output_tokens"),
                    "cache_read_input_tokens": usage.get("cache_read_input_tokens"),
                    "cache_creation_input_tokens": usage.get("cache_creation_input_tokens"),
                },
                sort_keys=True,
            ),
            flush=True,
        )
    return payload


def decide_next_action(
    *,
    system: str | list[dict[str, Any]],
    messages: list[dict[str, Any]],
    model: str | None = None,
    max_tokens: int = 1024,
    use_prompt_cache: bool | None = None,
) -> dict[str, Any]:
    """Return parsed JSON action from the model."""
    payload = complete_messages(
        system=system,
        messages=messages,
        model=model,
        max_tokens=max_tokens,
        use_prompt_cache=use_prompt_cache,
    )
    return parse_json_response(_extract_text(payload))
