"""CLI entry point for the finder.

    python -m finder --target-url http://127.0.0.1:5001 --source targets/seeded_flask

Prints a JSON report of confirmed findings and coverage. Reasoning goes through
Vultr Serverless Inference when a key is set; otherwise an offline heuristic runs
and the report says so.
"""

from __future__ import annotations

import argparse
import json
import sys

from finder.pipeline import run_finder


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="finder", description="Cerberus vulnerability finder")
    parser.add_argument("--target-url", required=True, help="Base URL of the running target app")
    parser.add_argument("--source", default=None, help="Path to the target source dir (for static sweep + manifest)")
    parser.add_argument("--max-steps", type=int, default=20)
    parser.add_argument("--wall-clock", type=float, default=90.0)
    args = parser.parse_args(argv)

    report = run_finder(
        args.target_url,
        args.source,
        max_steps=args.max_steps,
        wall_clock_seconds=args.wall_clock,
    )
    print(json.dumps(report.to_dict(), indent=2))
    # Findings are reported in the JSON, not via the exit code; a clean run and a
    # run with findings both exit 0. Only an internal error is a failed process.
    return 0


if __name__ == "__main__":
    sys.exit(main())
