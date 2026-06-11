"""Verifier orchestration."""

from __future__ import annotations

from postmortem_verify.models import RuleResult, VerifyContext
from postmortem_verify.rules import (
    rule_r1_hidden_process,
    rule_r10_linux_persistence,
    rule_r11_ghost_service,
    rule_r12_usb_initial_access,
    rule_r13_scheduled_task,
    rule_r14_suspicious_ioc,
    rule_r15_timeline_correlation,
    rule_r16_unusual_execution,
    rule_r18_cmd_leftover,
    rule_r19_web_attack,
    rule_r20_structured_log_alert,
    rule_r21_removable_storage,
    rule_r22_cleartext_identity,
    rule_r27_email_exfil,
    rule_r28_cloud_exfil,
    rule_r29_optical_exfil,
    rule_r30_yara_malware,
    rule_r31_linux_memory_isf,
    rule_r2_no_execution_trail,
    rule_r3_phantom_logon,
    rule_r4_timestomp,
    rule_r5_ghost_binary,
    rule_r6_orphan_connection,
    rule_r7_memory_injection,
    rule_r8_dns_exfil,
    rule_r9_http_beacon,
)

ALL_RULES = [
    rule_r1_hidden_process,
    rule_r2_no_execution_trail,
    rule_r3_phantom_logon,
    rule_r4_timestomp,
    rule_r5_ghost_binary,
    rule_r6_orphan_connection,
    rule_r7_memory_injection,
    rule_r8_dns_exfil,
    rule_r9_http_beacon,
    rule_r10_linux_persistence,
    rule_r11_ghost_service,
    rule_r12_usb_initial_access,
    rule_r13_scheduled_task,
    rule_r14_suspicious_ioc,
    rule_r15_timeline_correlation,
    rule_r16_unusual_execution,
    rule_r18_cmd_leftover,
    rule_r19_web_attack,
    rule_r20_structured_log_alert,
    rule_r21_removable_storage,
    rule_r22_cleartext_identity,
    rule_r27_email_exfil,
    rule_r28_cloud_exfil,
    rule_r29_optical_exfil,
    rule_r30_yara_malware,
    rule_r31_linux_memory_isf,
]


def run_r1(ctx: VerifyContext) -> RuleResult:
    return rule_r1_hidden_process(ctx)


def run_verifier(ctx: VerifyContext) -> list[RuleResult]:
    """Run all implemented verifier rules."""
    return [rule(ctx) for rule in ALL_RULES]
