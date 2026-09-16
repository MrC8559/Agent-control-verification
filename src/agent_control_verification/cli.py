from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .codex_evidence import (
    detect_codex_version,
    write_codex_probe_bundle,
)
from .codex_evidence_guard import collect_codex_probe_strict
from .codex_integration import (
    CODEX_TARGET_VERSION,
    CodexIntegrationError,
    prepare_codex_probe,
    run_codex_hook,
)
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

    codex_hook = sub.add_parser(
        "codex-hook",
        help="run the version-pinned Codex hook adapter over JSON from stdin",
    )
    codex_hook.add_argument(
        "--mode",
        required=True,
        choices=("deny", "allow", "observe", "malformed", "exit-error"),
        help="controlled hook behaviour for the probe",
    )
    codex_hook.add_argument(
        "--log",
        required=True,
        type=Path,
        help="append redacted hook evidence to this JSONL file",
    )

    codex_prepare = sub.add_parser(
        "codex-prepare",
        help="create a disposable Codex 0.154.0 probe workspace",
    )
    codex_prepare.add_argument("workspace", type=Path, help="new or empty workspace path")
    codex_prepare.add_argument(
        "--mode",
        choices=("deny", "allow", "malformed", "exit-error"),
        default="deny",
        help="PreToolUse fixture mode",
    )
    codex_prepare.add_argument(
        "--python",
        dest="python_executable",
        help="Python executable used by generated Codex hook commands",
    )

    codex_collect = sub.add_parser(
        "codex-collect",
        help="collect a completed Codex probe into a redacted ACV evidence bundle",
    )
    codex_collect.add_argument("workspace", type=Path, help="prepared Codex probe workspace")
    codex_collect.add_argument(
        "--codex",
        default="codex",
        help="Codex executable used for automatic version detection",
    )
    codex_collect.add_argument(
        "--codex-version",
        help="explicit observed Codex version instead of running `codex --version`",
    )
    codex_collect.add_argument(
        "--output",
        type=Path,
        help="evidence bundle path; defaults inside the probe evidence directory",
    )
    codex_collect.add_argument(
        "--acv-commit",
        help="ACV commit SHA to record in the bundle when known",
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

    if args.command == "codex-hook":
        try:
            stdout, exit_code = run_codex_hook(
                sys.stdin.read(),
                mode=args.mode,
                log_path=args.log,
            )
        except CodexIntegrationError as exc:
            print(f"ACV Codex hook error: {exc}", file=sys.stderr)
            return 2
        if stdout:
            print(stdout)
        return exit_code

    if args.command == "codex-prepare":
        try:
            paths = prepare_codex_probe(
                args.workspace,
                pre_mode=args.mode,
                python_executable=args.python_executable,
            )
        except CodexIntegrationError as exc:
            print(f"ACV Codex probe error: {exc}", file=sys.stderr)
            return 2

        manifest = json.loads(paths.manifest_file.read_text(encoding="utf-8"))
        print(f"Prepared Codex {CODEX_TARGET_VERSION} probe: {paths.workspace}")
        print(f"Hooks: {paths.hooks_file}")
        print(f"Redacted hook log: {paths.log_file}")
        print(f"Marker file: {paths.marker_file}")
        print("Before using the result as evidence, confirm: codex --version")
        print("Prompt:")
        print(manifest["prompt"])
        return 0

    if args.command == "codex-collect":
        try:
            observed_version = args.codex_version or detect_codex_version(args.codex)
            collection = collect_codex_probe_strict(
                args.workspace,
                codex_version=observed_version,
                acv_commit=args.acv_commit,
            )
        except CodexIntegrationError as exc:
            print(f"ACV Codex collection error: {exc}", file=sys.stderr)
            return 2

        if collection.bundle is None:
            print(f"{collection.result.verdict.value.upper()} {collection.result.property_name}")
            print(f"Reason: {collection.result.reason}")
            print("No evidence bundle was written because no actual PreToolUse action could be bound.")
            return 2

        output = args.output or (
            args.workspace.resolve() / ".acv" / "codex-probe" / "evidence.json"
        )
        try:
            write_codex_probe_bundle(output, collection)
        except CodexIntegrationError as exc:
            print(f"ACV Codex collection error: {exc}", file=sys.stderr)
            return 2
        print(render_evidence_bundle(collection.bundle))
        print(f"Saved: {output}")
        return 0

    return 2
