"""Anthropic LLM client and prompt caching."""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from postmortem_agent.llm import (
    complete_messages,
    parse_json_response,
    prompt_cache_enabled,
    static_system_block,
)


def test_static_system_block_adds_cache_control(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_PROMPT_CACHE", "1")
    block = static_system_block("static analyst instructions")
    assert isinstance(block, list)
    assert block[0]["cache_control"] == {"type": "ephemeral"}


def test_complete_messages_includes_top_level_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_PROMPT_CACHE", "1")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-key")

    captured: dict = {}

    def fake_urlopen(req, timeout=0):  # noqa: ARG001
        captured["body"] = json.loads(req.data.decode("utf-8"))
        payload = json.dumps(
            {
                "content": [{"type": "text", "text": '{"action":"done","hypothesis":"ok","confidence":0.5}'}],
                "usage": {"input_tokens": 10, "output_tokens": 5, "cache_read_input_tokens": 1000},
            }
        ).encode("utf-8")

        class Resp:
            def read(self):
                return payload

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        return Resp()

    with patch("urllib.request.urlopen", fake_urlopen):
        complete_messages(
            system=static_system_block("system"),
            messages=[{"role": "user", "content": "{}"}],
        )

    assert captured["body"]["cache_control"] == {"type": "ephemeral"}
    assert isinstance(captured["body"]["system"], list)


def test_parse_json_response_strips_fence() -> None:
    parsed = parse_json_response('```json\n{"action":"done"}\n```')
    assert parsed["action"] == "done"


def test_parse_json_response_extracts_trailing_json() -> None:
    raw = (
        "I'll start with evidence survey.\n\n"
        '{"action":"tool","tool":"evidence_survey","arguments":{"case_relpath":"."},"reason":"inventory"}'
    )
    parsed = parse_json_response(raw)
    assert parsed["tool"] == "evidence_survey"


def test_prompt_cache_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_PROMPT_CACHE", "0")
    assert prompt_cache_enabled() is False
    assert static_system_block("x") == "x"
