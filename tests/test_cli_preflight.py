from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from agent_control_verification.cli import main


COMMIT = "b" * 40


class CliPreflightTests(unittest.TestCase):
    @patch("agent_control_verification.cli.run_codex_preflight")
    @patch("agent_control_verification.cli._detect_acv_commit", return_value=COMMIT)
    def test_preflight_passes_detected_commit_and_workspace(self, detect_commit, run_preflight):
        run_preflight.return_value = SimpleNamespace(ready=True, as_dict=lambda: {"ready": True})
        workspace = Path("probe-workspace")

        with patch("agent_control_verification.cli.render_codex_preflight", return_value="READY"):
            exit_code = main(["codex-preflight", str(workspace), "--codex", "codex-test"])

        self.assertEqual(exit_code, 0)
        detect_commit.assert_called_once_with()
        run_preflight.assert_called_once_with(
            workspace,
            codex_executable="codex-test",
            acv_commit=COMMIT,
        )

    @patch("agent_control_verification.cli.run_codex_preflight")
    @patch("agent_control_verification.cli._detect_acv_commit", return_value=COMMIT)
    def test_failed_preflight_returns_nonzero(self, _detect_commit, run_preflight):
        run_preflight.return_value = SimpleNamespace(ready=False, as_dict=lambda: {"ready": False})

        with patch("agent_control_verification.cli.render_codex_preflight", return_value="NOT READY"):
            exit_code = main(["codex-preflight"])

        self.assertEqual(exit_code, 2)

    @patch("agent_control_verification.cli.run_codex_preflight")
    @patch("agent_control_verification.cli._detect_acv_commit")
    def test_explicit_commit_override_skips_detection(self, detect_commit, run_preflight):
        run_preflight.return_value = SimpleNamespace(ready=True, as_dict=lambda: {"ready": True})

        with patch("agent_control_verification.cli.render_codex_preflight", return_value="READY"):
            exit_code = main(["codex-preflight", "--acv-commit", COMMIT])

        self.assertEqual(exit_code, 0)
        detect_commit.assert_not_called()
        run_preflight.assert_called_once_with(
            None,
            codex_executable="codex",
            acv_commit=COMMIT,
        )


if __name__ == "__main__":
    unittest.main()
