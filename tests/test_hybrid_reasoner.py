"""Hybrid reasoner — policy coverage floor before LLM."""

from __future__ import annotations

from postmortem_agent.reasoner_hybrid import HybridReasoner
from postmortem_agent.reasoner_policy import policy_coverage_floor
from postmortem_agent.state import AgentConfig
from postmortem_verify.models import RuleResult


def test_policy_floor_runs_disk_parse_usb_when_r21_skipped() -> None:
    config = AgentConfig(case_id="t", evidence_case="nist-pc-only")
    survey = {
        "kinds_present": ["registry_hive"],
        "files": [
            {
                "kind": "registry_hive",
                "relpath": "extracted/part0/Windows/System32/config/SYSTEM",
            }
        ],
    }
    verifier = [RuleResult("R21", "usb_exfil", "skipped", "no usb input", [])]
    action = policy_coverage_floor(
        verifier=verifier,
        results={},
        survey=survey,
        config=config,
        executed=set(),
        failed=set(),
    )
    assert action is not None
    assert action["tool"] == "disk_parse_usb"
    assert "hybrid policy floor" in action["reason"]


def test_hybrid_delegates_to_llm_when_floor_clear(monkeypatch) -> None:
    config = AgentConfig(case_id="t", evidence_case=".", mode="hybrid")
    hybrid = HybridReasoner(config)

    monkeypatch.setattr(
        "postmortem_agent.reasoner_llm.policy_coverage_floor",
        lambda **kwargs: None,
    )
    monkeypatch.setattr(
        "postmortem_agent.reasoner_llm.LLMReasoner.decide",
        lambda self, **kwargs: {
            "action": "tool",
            "tool": "mem_pslist",
            "arguments": {"memory_relpath": "mem.raw"},
            "reason": "llm choice",
        },
    )

    action = hybrid.decide(
        goal="test",
        survey={"kinds_present": ["memory_image"], "files": []},
        catalog={"tools": {}},
        skills=[],
        results={"disk_parse_usb": [{"ok": True, "args": {"artifact_relpath": "x"}}]},
        verifier=[],
        hypothesis="testing",
        lessons=[],
        pattern_hints=[],
    )
    assert action["tool"] == "mem_pslist"
    assert action["reason"] == "llm choice"


def test_coverage_floor_once_per_scheduled_task_rule() -> None:
    from postmortem_agent.reasoner_policy import policy_coverage_floor

    config = AgentConfig(case_id="t", evidence_case=".")
    survey = {
        "files": [
            {"kind": "scheduled_task", "relpath": "extracted/Tasks/TaskA"},
            {"kind": "scheduled_task", "relpath": "extracted/Tasks/TaskB"},
        ]
    }
    verifier = [RuleResult("R13", "scheduled_task", "skipped", "no tasks", [])]
    executed = {"disk_parse_scheduled_tasks:{\"artifact_relpath\": \"extracted/Tasks/TaskA\"}"}
    results = {
        "disk_parse_scheduled_tasks": [
            {"ok": True, "args": {"artifact_relpath": "extracted/Tasks/TaskA"}},
        ]
    }
    action = policy_coverage_floor(
        verifier=verifier,
        results=results,
        survey=survey,
        config=config,
        executed=executed,
        failed=set(),
    )
    assert action is None


def test_policy_floor_runs_setupapi_when_r12_skipped() -> None:
    config = AgentConfig(case_id="t", evidence_case=".")
    survey = {
        "files": [
            {
                "kind": "setupapi_log",
                "relpath": "disk/Windows/INF/setupapi.dev.log",
            }
        ]
    }
    verifier = [RuleResult("R12", "usb_initial_access", "skipped", "setupapi USB input missing", [])]
    action = policy_coverage_floor(
        verifier=verifier,
        results={},
        survey=survey,
        config=config,
        executed=set(),
        failed=set(),
    )
    assert action is not None
    assert action["tool"] == "disk_parse_setupapi"
    assert action["arguments"]["artifact_relpath"] == "disk/Windows/INF/setupapi.dev.log"


def test_policy_floor_runs_reg_system_profile_on_disk_case(tmp_path) -> None:
    from postmortem_agent.reasoner_policy import policy_coverage_floor

    extract = tmp_path / "extracted"
    extract.mkdir()
    config = AgentConfig(case_id="t", evidence_case="nist-pc-only", extracted_root=extract)
    survey = {
        "kinds_present": ["registry_hive"],
        "files": [
            {"kind": "registry_hive", "relpath": "extracted/part0/Windows/System32/config/SOFTWARE"},
            {"kind": "registry_hive", "relpath": "extracted/part0/Windows/System32/config/SYSTEM"},
        ],
    }
    action = policy_coverage_floor(
        verifier=[],
        results={},
        survey=survey,
        config=config,
        executed=set(),
        failed=set(),
    )
    assert action is not None
    assert action["tool"] == "reg_system_profile"


def test_pcap_baseline_runs_net_http_on_nitroba_like_survey() -> None:
    from postmortem_agent.reasoner_policy import _pcap_baseline_action, _pcap_led_case

    survey = {
        "kinds_present": ["case_directory", "pcap"],
        "files": [{"kind": "pcap", "relpath": "nitroba/nitroba.pcap"}],
    }
    assert _pcap_led_case(survey) is True
    action = _pcap_baseline_action(
        results={},
        survey=survey,
        config=AgentConfig(case_id="t", evidence_case="nitroba"),
        executed=set(),
        failed=set(),
    )
    assert action is not None
    assert action["tool"] == "net_http_extract"
    assert action["arguments"]["artifact_relpath"] == "nitroba/nitroba.pcap"


def test_pcap_led_false_when_registry_present() -> None:
    from postmortem_agent.reasoner_policy import _pcap_led_case

    survey = {"kinds_present": ["pcap", "registry_hive"], "files": []}
    assert _pcap_led_case(survey) is False


def test_first_prefetch_prefers_wasp_name() -> None:
    from postmortem_agent.reasoner_policy import _first_prefetch_relpath

    survey = {
        "files": [
            {"kind": "prefetch", "relpath": "extracted/Windows/Prefetch/NOTEPAD.EXE-ABC.pf"},
            {"kind": "prefetch", "relpath": "extracted/Windows/Prefetch/123WASP_SETUP.EXE-XYZ.pf"},
        ]
    }
    assert "123WASP" in (_first_prefetch_relpath(survey) or "")
