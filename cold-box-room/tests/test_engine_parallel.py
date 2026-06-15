"""Parallel tool dispatch in agent engine."""

import time
from types import SimpleNamespace

from cold_box_room.agent import engine


def test_dispatch_tool_blocks_runs_in_parallel(monkeypatch):
    calls: list[tuple[str, float]] = []

    def fake_dispatch(name, args):
        delay = 0.15 if name == "slow_tool" else 0.05
        time.sleep(delay)
        calls.append((name, time.monotonic()))
        return {"ok": True, "tool": name}

    monkeypatch.setattr(engine, "dispatch_tool", fake_dispatch)
    monkeypatch.setattr(engine, "_log_event", lambda *a, **k: None)

    blocks = [
        SimpleNamespace(name="slow_tool", id="1", input={}),
        SimpleNamespace(name="fast_tool", id="2", input={}),
    ]
    t0 = time.monotonic()
    results = engine._dispatch_tool_blocks(tool_uses=blocks, turn=1, case_id="x")
    elapsed = time.monotonic() - t0
    assert len(results) == 2
    assert results[0][0].name == "slow_tool"
    assert results[1][0].name == "fast_tool"
    assert elapsed < 0.25
    assert {name for name, _ in calls} == {"slow_tool", "fast_tool"}
