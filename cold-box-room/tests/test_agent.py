"""Agent engine unit tests (no live LLM)."""

from cold_box_room.agent.engine import _build_system
from cold_box_room.agent.llm import cached_tools, prompt_cache_enabled, static_system_block
from cold_box_room.agent.prompts import LAYER1_SYSTEM_PROMPT
from cold_box_room.agent.tools import TOOL_SCHEMAS


def test_prompt_cache_blocks(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_PROMPT_CACHE", "1")
    block = static_system_block("hello")
    assert isinstance(block, list)
    assert block[0]["cache_control"]["type"] == "ephemeral"
    tools = cached_tools(TOOL_SCHEMAS[:2])
    assert "cache_control" in tools[-1]


def test_prompt_cache_disabled(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_PROMPT_CACHE", "0")
    assert prompt_cache_enabled() is False
    assert static_system_block("hello") == "hello"
    assert cached_tools(TOOL_SCHEMAS[:2]) == TOOL_SCHEMAS[:2]


def test_system_prompt_has_no_tool_schema_dump():
    block = _build_system()
    text = block if isinstance(block, str) else block[0]["text"]
    assert text == LAYER1_SYSTEM_PROMPT
    assert "SIFT-" not in text
    assert "input_schema" not in text
