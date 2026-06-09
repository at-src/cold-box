"""Append-only JSONL audit log with hash chain."""

from postmortem_audit.log import AuditEntry, AuditLog, GENESIS_PREV_HASH, digest_result, verify_chain

__all__ = [
    "AuditEntry",
    "AuditLog",
    "GENESIS_PREV_HASH",
    "digest_result",
    "verify_chain",
]
