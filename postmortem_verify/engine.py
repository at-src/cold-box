"""Verifier orchestration."""

from __future__ import annotations

from postmortem_verify.models import RuleResult, VerifyContext
from postmortem_verify.rules import rule_r1_hidden_process


def run_r1(ctx: VerifyContext) -> RuleResult:
    return rule_r1_hidden_process(ctx)


def run_verifier(ctx: VerifyContext) -> list[RuleResult]:
    """Run all implemented verifier rules."""
    return [run_r1(ctx)]
