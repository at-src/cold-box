"""Verifier orchestration."""

from __future__ import annotations

from postmortem_verify.models import RuleResult, VerifyContext
from postmortem_verify.rules import (
    rule_r1_hidden_process,
    rule_r2_no_execution_trail,
    rule_r3_phantom_logon,
    rule_r4_timestomp,
    rule_r5_ghost_binary,
    rule_r6_orphan_connection,
)

ALL_RULES = [
    rule_r1_hidden_process,
    rule_r2_no_execution_trail,
    rule_r3_phantom_logon,
    rule_r4_timestomp,
    rule_r5_ghost_binary,
    rule_r6_orphan_connection,
]


def run_r1(ctx: VerifyContext) -> RuleResult:
    return rule_r1_hidden_process(ctx)


def run_verifier(ctx: VerifyContext) -> list[RuleResult]:
    """Run all implemented verifier rules."""
    return [rule(ctx) for rule in ALL_RULES]
