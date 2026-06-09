"""CLI for evidence manifest and integrity checks."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from postmortem_evidence.guard import EvidencePathError, resolve_read_path
from postmortem_evidence.integrity import IntegritySession
from postmortem_evidence.manifest import build_manifest


def _configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(levelname)s %(message)s")


def cmd_manifest(args: argparse.Namespace) -> int:
    case = Path(args.path).expanduser()
    try:
        if args.local:
            case = case.resolve()
            if not case.is_dir():
                raise ValueError(f"Not a directory: {case}")
            manifest = build_manifest(case, evidence_root=case)
        else:
            case = resolve_read_path(case)
            manifest = build_manifest(case)
    except (EvidencePathError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(manifest, indent=2))
    return 0


def cmd_integrity_begin(args: argparse.Namespace) -> int:
    try:
        case = resolve_read_path(args.path)
    except EvidencePathError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    session = IntegritySession(case_root=case)
    session.begin()
    if args.save:
        out = Path(args.save)
        session.save_baseline(out)
        print(f"baseline saved: {out}", file=sys.stderr)
    for line in session.log:
        print(line, file=sys.stderr)
    return 0


def cmd_integrity_check(args: argparse.Namespace) -> int:
    try:
        case = resolve_read_path(args.path)
    except EvidencePathError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    session = IntegritySession.load_baseline(case, Path(args.baseline))
    result = session.check()
    for line in session.log:
        print(line, file=sys.stderr)
    print(json.dumps(result, indent=2))
    return 0 if result["intact"] else 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Postmortem evidence integrity tools")
    parser.add_argument("-v", "--verbose", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)

    p_manifest = sub.add_parser("manifest", help="SHA-256 manifest for a case directory")
    p_manifest.add_argument("path", help="Case directory path")
    p_manifest.add_argument(
        "--local",
        action="store_true",
        help="Repo-local path (e.g. examples/sample-evidence); skips EVIDENCE_ROOT guard",
    )
    p_manifest.set_defaults(func=cmd_manifest)

    p_begin = sub.add_parser("integrity-begin", help="Record pre-run manifest")
    p_begin.add_argument("path", help="Case directory under EVIDENCE_ROOT")
    p_begin.add_argument("--save", help="Write baseline JSON (e.g. under /cases)")
    p_begin.set_defaults(func=cmd_integrity_begin)

    p_check = sub.add_parser("integrity-check", help="Compare to pre-run baseline")
    p_check.add_argument("path", help="Case directory under EVIDENCE_ROOT")
    p_check.add_argument("--baseline", required=True, help="Baseline JSON from integrity-begin")
    p_check.set_defaults(func=cmd_integrity_check)

    args = parser.parse_args(argv)
    _configure_logging(args.verbose)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
