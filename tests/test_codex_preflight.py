from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agent_control_verification.codex_integration import (
    CODEX_TARGET_VERSION,
    prepare_codex_probe,
)
from agent_control_verification.codex_preflight import run_codex_preflight


COMMIT = "a" * 40


class CodexPreflightTests(unittest.TestCase):
    @patch(
        "agent_control_verification.codex_preflight.detect_codex_version",
        return_value=CODEX_TARGET_VERSION,
    )
    def test_host_only_preflight_is_ready_with_pinned_host_and_commit(self, _detect):
        report = run_codex_preflight(acv_commit=COMMIT)

        self.assertTrue(report.ready)
        self.assertTrue(all(check.passed for check in report.checks))

    @patch(
        "agent_control_verification.codex_preflight.detect_codex_version",
        return_value="0.155.0",
    )
    def test_unpinned_host_is_not_ready(self, _detect):
        report = run_codex_preflight(acv_commit=COMMIT)

        self.assertFalse(report.ready)
        host = next(check for check in report.checks if check.name == "codex_host")
        self.assertFalse(host.passed)

    @patch(
        "agent_control_verification.codex_preflight.detect_codex_version",
        return_value=CODEX_TARGET_VERSION,
    )
    def test_missing_acv_commit_is_not_ready(self, _detect):
        report = run_codex_preflight(acv_commit=None)

        self.assertFalse(report.ready)
        commit = next(check for check in report.checks if check.name == "acv_commit")
        self.assertFalse(commit.passed)

    @patch(
        "agent_control_verification.codex_preflight.detect_codex_version",
        return_value=CODEX_TARGET_VERSION,
    )
    def test_invalid_manual_acv_commit_is_not_ready(self, _detect):
        report = run_codex_preflight(acv_commit="main")

        self.assertFalse(report.ready)
        commit = next(check for check in report.checks if check.name == "acv_commit")
        self.assertFalse(commit.passed)

    @patch(
        "agent_control_verification.codex_preflight.detect_codex_version",
        return_value=CODEX_TARGET_VERSION,
    )
    def test_fresh_prepared_workspace_is_ready(self, _detect):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp) / "probe"
            prepare_codex_probe(workspace, pre_mode="deny", python_executable="python")

            report = run_codex_preflight(workspace, acv_commit=COMMIT)

            self.assertTrue(report.ready)
            names = {check.name for check in report.checks}
            self.assertIn("marker_baseline", names)
            self.assertIn("hook_scope", names)
            self.assertIn("unused_hook_log", names)

    @patch(
        "agent_control_verification.codex_preflight.detect_codex_version",
        return_value=CODEX_TARGET_VERSION,
    )
    def test_changed_marker_blocks_preflight(self, _detect):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp) / "probe"
            paths = prepare_codex_probe(workspace, pre_mode="deny", python_executable="python")
            paths.marker_file.write_text("CHANGED\n", encoding="utf-8")

            report = run_codex_preflight(workspace, acv_commit=COMMIT)

            self.assertFalse(report.ready)
            marker = next(check for check in report.checks if check.name == "marker_baseline")
            self.assertFalse(marker.passed)

    @patch(
        "agent_control_verification.codex_preflight.detect_codex_version",
        return_value=CODEX_TARGET_VERSION,
    )
    def test_existing_hook_log_blocks_workspace_reuse(self, _detect):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp) / "probe"
            paths = prepare_codex_probe(workspace, pre_mode="deny", python_executable="python")
            paths.log_file.write_text("already-used\n", encoding="utf-8")

            report = run_codex_preflight(workspace, acv_commit=COMMIT)

            self.assertFalse(report.ready)
            unused = next(check for check in report.checks if check.name == "unused_hook_log")
            self.assertFalse(unused.passed)

    @patch(
        "agent_control_verification.codex_preflight.detect_codex_version",
        return_value=CODEX_TARGET_VERSION,
    )
    def test_hook_scope_change_blocks_preflight(self, _detect):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp) / "probe"
            paths = prepare_codex_probe(workspace, pre_mode="deny", python_executable="python")
            text = paths.hooks_file.read_text(encoding="utf-8")
            paths.hooks_file.write_text(text.replace("^apply_patch$", ".*", 1), encoding="utf-8")

            report = run_codex_preflight(workspace, acv_commit=COMMIT)

            self.assertFalse(report.ready)
            scope = next(check for check in report.checks if check.name == "hook_scope")
            self.assertFalse(scope.passed)


if __name__ == "__main__":
    unittest.main()
