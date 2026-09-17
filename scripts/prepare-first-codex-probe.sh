#!/usr/bin/env bash
set -euo pipefail

MODE="deny"
WORKSPACE=""
CODEX_COMMAND="codex"
PYTHON_COMMAND="python3"

usage() {
  cat <<'EOF'
Usage: bash scripts/prepare-first-codex-probe.sh [options]

Prepare and preflight ACV's first live Codex probe on macOS/Linux.

Options:
  --mode MODE          deny, allow, malformed, or exit-error (default: deny)
  --workspace PATH     disposable workspace path; defaults under $TMPDIR
  --codex COMMAND      Codex executable (default: codex)
  --python COMMAND     Python executable (default: python3)
  -h, --help           show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)
      [[ $# -ge 2 ]] || { echo "--mode requires a value" >&2; exit 2; }
      MODE="$2"
      shift 2
      ;;
    --workspace)
      [[ $# -ge 2 ]] || { echo "--workspace requires a value" >&2; exit 2; }
      WORKSPACE="$2"
      shift 2
      ;;
    --codex)
      [[ $# -ge 2 ]] || { echo "--codex requires a value" >&2; exit 2; }
      CODEX_COMMAND="$2"
      shift 2
      ;;
    --python)
      [[ $# -ge 2 ]] || { echo "--python requires a value" >&2; exit 2; }
      PYTHON_COMMAND="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

case "$MODE" in
  deny|allow|malformed|exit-error) ;;
  *)
    echo "Unsupported mode: $MODE" >&2
    exit 2
    ;;
esac

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
SOURCE_ROOT="$REPO_ROOT/src"

if [[ -n "${PYTHONPATH:-}" ]]; then
  export PYTHONPATH="$SOURCE_ROOT:$PYTHONPATH"
else
  export PYTHONPATH="$SOURCE_ROOT"
fi

if [[ -z "$WORKSPACE" ]]; then
  TMP_BASE="${TMPDIR:-/tmp}"
  TMP_BASE="${TMP_BASE%/}"
  STAMP="$(date +%Y%m%d-%H%M%S)"
  WORKSPACE="$TMP_BASE/acv-codex-$MODE-$STAMP"
fi

if [[ "$WORKSPACE" != /* ]]; then
  WORKSPACE="$(pwd)/$WORKSPACE"
fi

printf 'Checking host and ACV provenance before workspace creation...\n'
"$PYTHON_COMMAND" -m agent_control_verification codex-preflight --codex "$CODEX_COMMAND"

printf '\nPreparing disposable workspace: %s\n' "$WORKSPACE"
"$PYTHON_COMMAND" -m agent_control_verification codex-prepare \
  "$WORKSPACE" \
  --mode "$MODE" \
  --python "$PYTHON_COMMAND"

printf '\nChecking prepared workspace...\n'
"$PYTHON_COMMAND" -m agent_control_verification codex-preflight \
  "$WORKSPACE" \
  --codex "$CODEX_COMMAND"

MANIFEST_PATH="$WORKSPACE/.acv/codex-probe/manifest.json"
PROMPT="$("$PYTHON_COMMAND" -c 'import json, sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["prompt"])' "$MANIFEST_PATH")"

cat <<EOF

Prepared successfully.
Workspace: $WORKSPACE
Mode: $MODE
Prompt:
$PROMPT

When Codex usage is available:
  1. cd "$WORKSPACE"
  2. Run Codex and submit the prompt above exactly once.
  3. Review and trust the generated project hook only if Codex asks.
  4. Do not edit acv-marker.txt manually.
  5. Exit Codex after the attempt.
  6. From the ACV checkout, collect with:
     $PYTHON_COMMAND -m agent_control_verification codex-collect "$WORKSPACE" --codex "$CODEX_COMMAND"
  7. Independently validate the saved bundle with:
     $PYTHON_COMMAND -m agent_control_verification render-evidence "$WORKSPACE/.acv/codex-probe/evidence.json"

Preflight readiness is not evidence that the host enforces the control. The live run and collection establish that separately.
EOF
