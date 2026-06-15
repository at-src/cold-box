#!/usr/bin/env python3
"""Score a completed hallway run against a ground-truth benchmark."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from cold_box_room.e2e.accuracy import (  # noqa: E402
    list_benchmarks,
    score_case_accuracy,
    write_accuracy_report,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Score E2E case against ground truth")
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--benchmark", default="terry_usb", choices=list_benchmarks())
    parser.add_argument("--run-id", default="")
    parser.add_argument(
        "--out",
        default="",
        help="Output JSON path (default: e2e-runs/{run-id}-accuracy.json)",
    )
    args = parser.parse_args(argv)

    payload = score_case_accuracy(
        case_id=args.case_id,
        benchmark_id=args.benchmark,
        run_id=args.run_id or args.case_id,
    )
    out = Path(args.out) if args.out else ROOT / "e2e-runs" / f"{payload['run_id']}-accuracy.json"
    write_accuracy_report(payload, out)
    print(json.dumps(payload, indent=2))
    print(f"\nreport: {out}")
    req = payload["required_recall_pct"]
    return 0 if payload.get("complete") and req >= 100.0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
