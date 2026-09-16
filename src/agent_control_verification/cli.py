from __future__ import annotations

import argparse
import json

from .demo import run_demo
from .model import Verdict


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="acv",
        description="Verify AI-agent control decisions against observed effects.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    demo = sub.add_parser("demo", help="run the deterministic synthetic demonstration")
    demo.add_argument(
        "--json",
        action="store_true",
        help="emit machine-readable JSON",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    if args.command == "demo":
        cases = run_demo()
        if args.json:
            print(
                json.dumps(
                    [{"case": case.name, **case.result.as_dict()} for case in cases],
                    indent=2,
                    sort_keys=True,
                )
            )
        else:
            for case in cases:
                print(
                    f"{case.result.verdict.value.upper():12} "
                    f"{case.result.property_name:34} {case.name}"
                )

        expected = [
            Verdict.PASS,
            Verdict.FAIL,
            Verdict.FAIL,
            Verdict.FAIL,
        ]
        return 0 if [case.result.verdict for case in cases] == expected else 1

    return 2
