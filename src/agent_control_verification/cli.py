from __future__ import annotations

import argparse
import json
from pathlib import Path

from .demo import run_demo
from .evidence import evidence_bundle_json, load_evidence_bundle, render_evidence_bundle
from .evidence_demo import build_demo_evidence_bundle
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

    evidence_demo = sub.add_parser(
        "evidence-demo",
        help="emit a validated redacted evidence bundle for the deterministic demo",
    )
    evidence_demo.add_argument(
        "--output",
        type=Path,
        help="write the JSON bundle to this path instead of stdout",
    )

    render = sub.add_parser(
        "render-evidence",
        help="validate and render a saved evidence bundle",
    )
    render.add_argument("path", type=Path, help="path to an ACV evidence bundle")

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

    if args.command == "evidence-demo":
        bundle = build_demo_evidence_bundle()
        rendered = evidence_bundle_json(bundle)
        if args.output:
            args.output.write_text(rendered, encoding="utf-8")
        else:
            print(rendered, end="")
        return 0

    if args.command == "render-evidence":
        bundle = load_evidence_bundle(args.path.read_text(encoding="utf-8"))
        print(render_evidence_bundle(bundle))
        return 0

    return 2
