"""Anthropic tool-use loop for cold-box-room Layer 1 runs."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from cold_box_room.agent.llm import (
    anthropic_api_key,
    anthropic_model,
    cached_tools,
    load_dotenv,
    log_usage,
    prompt_cache_enabled,
    static_system_block,
)
from cold_box_room.agent.prompts import (
    DEFAULT_LAYER1_GOAL,
    DEFAULT_ROOM_A_GOAL,
    DEFAULT_ROOM_B_GOAL,
    LAYER1_SYSTEM_PROMPT,
    ROOM_A_SYSTEM_PROMPT,
    ROOM_B_SYSTEM_PROMPT,
)
from cold_box_room.agent.situation import (
    format_case_situation_briefing,
    format_room_a_briefing,
    format_room_b_briefing,
)
from cold_box_room.agent.tools import (
    LAYER1_TOOL_SCHEMAS,
    ROOM_A_TOOL_SCHEMAS,
    ROOM_B_TOOL_SCHEMAS,
    TOOL_SCHEMAS,
    dispatch_tool,
    tool_result_json,
)
from cold_box_room.r1.hallway import current_room
from cold_box_room.r1.paths import case_records_dir
from cold_box_room.r2.tool_log import read_tool_log

SUBMIT_ONLY_SCHEMA = [t for t in LAYER1_TOOL_SCHEMAS if t["name"] == "submit_layer1_writeup"]


def _run_tool_loop(
    *,
    client: Any,
    model_name: str,
    system: str | list[dict[str, Any]],
    tools: list[dict[str, Any]],
    messages: list[dict[str, Any]],
    case_id: str,
    max_turns: int,
    extra_headers: dict[str, str],
    stop_on: str,
) -> dict[str, Any]:
    """Shared Anthropic tool loop. stop_on: 'promoted' | 'ready_for_room2' | 'ready_for_room3'."""
    promoted = False
    gate_open = False
    tool_calls = 0
    last_result: dict[str, Any] | None = None
    turn = 0

    for turn in range(1, max_turns + 1):
        kwargs: dict[str, Any] = {
            "model": model_name,
            "max_tokens": 8192,
            "system": system,
            "tools": tools,
            "messages": messages,
        }
        if extra_headers:
            kwargs["extra_headers"] = extra_headers

        response = client.messages.create(**kwargs)
        usage = log_usage(response)
        _log_event(
            case_id,
            {
                "type": "assistant",
                "turn": turn,
                "stop_reason": response.stop_reason,
                "usage": usage,
            },
        )

        tool_uses = [block for block in response.content if block.type == "tool_use"]
        if response.stop_reason == "end_turn" and not tool_uses:
            messages.append({"role": "assistant", "content": response.content})
            if promoted or gate_open:
                break
            messages.append({"role": "user", "content": "Continue."})
            continue
        if not tool_uses:
            break

        messages.append({"role": "assistant", "content": response.content})
        tool_results: list[dict[str, Any]] = []

        for block in tool_uses:
            name = block.name
            args = block.input if isinstance(block.input, dict) else {}
            if "case_id" not in args and case_id:
                args = {**args, "case_id": case_id}
            if name == "submit_layer1_writeup" and "self_score" in args:
                from cold_box_room.r2.analyst_log import normalize_self_score

                try:
                    args = {**args, "self_score": normalize_self_score(args["self_score"])}
                except Exception:
                    pass
            try:
                result = dispatch_tool(name, args)
            except Exception as exc:
                result = {"ok": False, "error": str(exc), "case_id": case_id}
            tool_calls += 1
            _log_event(
                case_id,
                {
                    "type": "tool",
                    "turn": turn,
                    "tool": name,
                    "input": args,
                    "output_summary": {
                        k: result.get(k)
                        for k in (
                            "ok",
                            "audit_id",
                            "tool_id",
                            "exit_code",
                            "promoted",
                            "gate_open",
                            "ready_for_room2",
                            "ready_for_room3",
                            "room",
                            "error",
                            "blocked_reasons",
                            "scratch_file",
                            "step_id",
                        )
                        if k in result
                    },
                },
            )
            last_result = result
            if stop_on == "promoted" and name == "submit_layer1_writeup" and result.get("promoted"):
                promoted = True
            if stop_on == "ready_for_room2" and name == "formalize_plan_a" and result.get(
                "ready_for_room2"
            ):
                gate_open = True
            if stop_on == "ready_for_room3" and name == "formalize_plan_b" and result.get(
                "ready_for_room3"
            ):
                gate_open = True
            tool_results.append(
                {
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": tool_result_json(result),
                }
            )

        messages.append({"role": "user", "content": tool_results})
        if promoted or gate_open:
            break

    return {
        "promoted": promoted,
        "gate_open": gate_open,
        "tool_calls": tool_calls,
        "turns_used": turn,
        "last_result": last_result,
        "messages": messages,
    }


def run_room_a_agent(
    *,
    case_id: str,
    goal: str,
    max_turns: int = 15,
    model: str | None = None,
) -> dict[str, Any]:
    load_dotenv()
    try:
        import anthropic
    except ImportError as exc:
        raise RuntimeError("pip install anthropic") from exc

    client = anthropic.Anthropic(api_key=anthropic_api_key())
    model_name = anthropic_model(model)
    system = static_system_block(ROOM_A_SYSTEM_PROMPT)
    tools = cached_tools(ROOM_A_TOOL_SCHEMAS)
    extra_headers: dict[str, str] = {}
    if prompt_cache_enabled():
        extra_headers["anthropic-beta"] = "prompt-caching-2024-07-31"

    briefing = format_room_a_briefing(case_id)
    messages: list[dict[str, Any]] = [
        {"role": "user", "content": f"**GOAL:** {goal}\n\n{briefing}"}
    ]
    _log_event(
        case_id,
        {
            "type": "session_start",
            "room": "A",
            "goal": goal,
            "model": model_name,
            "prompt_cache": prompt_cache_enabled(),
        },
    )

    loop = _run_tool_loop(
        client=client,
        model_name=model_name,
        system=system,
        tools=tools,
        messages=messages,
        case_id=case_id,
        max_turns=max_turns,
        extra_headers=extra_headers,
        stop_on="ready_for_room2",
    )

    if not loop["gate_open"]:
        from cold_box_room.room_a import room_a_checkpoint

        cp = room_a_checkpoint(case_id)
        if cp.get("ready_for_room2"):
            loop["gate_open"] = True

    final_room = current_room(case_id)
    summary = {
        "ok": loop["gate_open"],
        "case_id": case_id,
        "room": final_room,
        "gate_open": loop["gate_open"],
        "ready_for_room2": loop["gate_open"],
        "tool_calls": loop["tool_calls"],
        "turns_used": loop["turns_used"],
        "last_gate": loop["last_result"],
        "reasoning_log": str(_reasoning_path(case_id)),
        "prompt_cache": prompt_cache_enabled(),
    }
    _log_event(case_id, {"type": "session_end", "room_a": summary})
    return summary


def run_room_b_agent(
    *,
    case_id: str,
    goal: str,
    max_turns: int = 15,
    model: str | None = None,
) -> dict[str, Any]:
    load_dotenv()
    try:
        import anthropic
    except ImportError as exc:
        raise RuntimeError("pip install anthropic") from exc

    client = anthropic.Anthropic(api_key=anthropic_api_key())
    model_name = anthropic_model(model)
    system = static_system_block(ROOM_B_SYSTEM_PROMPT)
    tools = cached_tools(ROOM_B_TOOL_SCHEMAS)
    extra_headers: dict[str, str] = {}
    if prompt_cache_enabled():
        extra_headers["anthropic-beta"] = "prompt-caching-2024-07-31"

    briefing = format_room_b_briefing(case_id)
    messages: list[dict[str, Any]] = [
        {"role": "user", "content": f"**GOAL:** {goal}\n\n{briefing}"}
    ]
    _log_event(
        case_id,
        {
            "type": "session_start",
            "room": "B",
            "goal": goal,
            "model": model_name,
            "prompt_cache": prompt_cache_enabled(),
        },
    )

    loop = _run_tool_loop(
        client=client,
        model_name=model_name,
        system=system,
        tools=tools,
        messages=messages,
        case_id=case_id,
        max_turns=max_turns,
        extra_headers=extra_headers,
        stop_on="ready_for_room3",
    )

    if not loop["gate_open"]:
        from cold_box_room.room_b import room_b_checkpoint

        cp = room_b_checkpoint(case_id)
        if cp.get("ready_for_room3"):
            loop["gate_open"] = True

    final_room = current_room(case_id)
    summary = {
        "ok": loop["gate_open"],
        "case_id": case_id,
        "room": final_room,
        "gate_open": loop["gate_open"],
        "ready_for_room3": loop["gate_open"],
        "tool_calls": loop["tool_calls"],
        "turns_used": loop["turns_used"],
        "last_gate": loop["last_result"],
        "reasoning_log": str(_reasoning_path(case_id)),
        "prompt_cache": prompt_cache_enabled(),
    }
    _log_event(case_id, {"type": "session_end", "room_b": summary})
    return summary



def _reasoning_path(case_id: str):
    return case_records_dir(case_id) / "AGENT_RUN.jsonl"


def _log_event(case_id: str, event: dict[str, Any]) -> None:
    event = {"ts": datetime.now(timezone.utc).isoformat(), **event}
    path = _reasoning_path(case_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, ensure_ascii=False) + "\n")


def _build_system() -> str | list[dict[str, Any]]:
    """Static syllabus only — tool defs come from the API tools param, not the prompt."""
    return static_system_block(LAYER1_SYSTEM_PROMPT)


def _force_submit_writeup(
    *,
    client: Any,
    model_name: str,
    system: str | list[dict[str, Any]],
    messages: list[dict[str, Any]],
    case_id: str,
    extra_headers: dict[str, str],
) -> dict[str, Any] | None:
    tool_log = read_tool_log(case_id, limit=15)
    digest = json.dumps(
        {
            "recent_tool_log": tool_log.get("entries", [])[-10:],
            "tool_logbook_excerpt": (tool_log.get("markdown") or "")[-4000:],
        },
        ensure_ascii=False,
        indent=2,
    )[:8000]
    final_messages = list(messages) + [
        {
            "role": "user",
            "content": (
                "Turn budget exhausted. Before submit: every plan_a.py step must be "
                "resolved via apply_plan_a_step_status (plan score ≥ 70%). "
                "Call submit_layer1_writeup once with your findings, "
                "self_score (integer 1–10 only, not a percentage), and why based on work so far.\n\n"
                f"{digest}"
            ),
        }
    ]
    kwargs: dict[str, Any] = {
        "model": model_name,
        "max_tokens": 8192,
        "system": system,
        "tools": cached_tools(SUBMIT_ONLY_SCHEMA),
        "messages": final_messages,
    }
    if extra_headers:
        kwargs["extra_headers"] = extra_headers
    try:
        response = client.messages.create(**kwargs)
        usage = log_usage(response)
        _log_event(
            case_id,
            {
                "type": "assistant",
                "turn": "finalize",
                "stop_reason": response.stop_reason,
                "usage": usage,
                "forced_submit": True,
            },
        )
        if response.stop_reason != "tool_use":
            return None
        for block in response.content:
            if block.type != "tool_use" or block.name != "submit_layer1_writeup":
                continue
            args = block.input if isinstance(block.input, dict) else {}
            if "case_id" not in args:
                args = {**args, "case_id": case_id}
            if "self_score" in args:
                from cold_box_room.r2.analyst_log import normalize_self_score

                try:
                    args = {**args, "self_score": normalize_self_score(args["self_score"])}
                except Exception:
                    pass
            result = dispatch_tool("submit_layer1_writeup", args)
            _log_event(
                case_id,
                {
                    "type": "tool",
                    "turn": "finalize",
                    "tool": "submit_layer1_writeup",
                    "input": args,
                    "output_summary": result,
                    "forced": True,
                },
            )
            return result
    except Exception as exc:
        _log_event(case_id, {"type": "finalize_error", "error": str(exc)[:500]})
    return None


def run_layer1_agent(
    *,
    case_id: str,
    goal: str,
    max_turns: int = 45,
    model: str | None = None,
) -> dict[str, Any]:
    load_dotenv()

    try:
        import anthropic
    except ImportError as exc:
        raise RuntimeError("pip install anthropic") from exc

    client = anthropic.Anthropic(api_key=anthropic_api_key())
    model_name = anthropic_model(model)
    system = _build_system()
    tools = cached_tools(LAYER1_TOOL_SCHEMAS)

    extra_headers: dict[str, str] = {}
    if prompt_cache_enabled():
        extra_headers["anthropic-beta"] = "prompt-caching-2024-07-31"

    briefing = format_case_situation_briefing(case_id)
    messages: list[dict[str, Any]] = [
        {
            "role": "user",
            "content": (
                f"**GOAL:** {goal}\n\n"
                f"{briefing}"
            ),
        }
    ]

    _log_event(
        case_id,
        {
            "type": "session_start",
            "goal": goal,
            "model": model_name,
            "prompt_cache": prompt_cache_enabled(),
        },
    )

    loop = _run_tool_loop(
        client=client,
        model_name=model_name,
        system=system,
        tools=tools,
        messages=messages,
        case_id=case_id,
        max_turns=max_turns,
        extra_headers=extra_headers,
        stop_on="promoted",
    )
    promoted = loop["promoted"]
    tool_calls = loop["tool_calls"]
    turn = loop["turns_used"]
    last_submit = None
    messages = loop["messages"]

    if not promoted:
        last_submit = _force_submit_writeup(
            client=client,
            model_name=model_name,
            system=system,
            messages=messages,
            case_id=case_id,
            extra_headers=extra_headers,
        )
        if last_submit and last_submit.get("promoted"):
            promoted = True

    final_room = current_room(case_id)
    summary = {
        "ok": promoted,
        "case_id": case_id,
        "room": final_room,
        "promoted_to_room_b": promoted,
        "promoted_to_r3": promoted,
        "tool_calls": tool_calls,
        "turns_used": turn,
        "last_submit": last_submit,
        "reasoning_log": str(_reasoning_path(case_id)),
        "prompt_cache": prompt_cache_enabled(),
    }
    _log_event(
        case_id,
        {"type": "session_end", "promoted": promoted, "summary": summary},
    )
    return summary
