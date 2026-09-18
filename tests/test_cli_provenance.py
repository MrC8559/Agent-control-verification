from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from agent_control_verification.cli import _detect_acv_commit, main
from agent_control_verification.codex_integration import CODEX_TARGET_VERSION
from agent_control_verification.model import Verdict


COMMIT = "a" * 40


class CliProvenanceTests(unittest.TestCase):
    @patch("agent_control_verification.cli.subprocess.run")
    def test_detect_acv_commit_from_enclosing_git_checkout(self, run: Mock):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            (repo / ".git").mkdir(parents=True)
            source = repo / "src" / "agent_control_verification" / "cli.py"
            source.parent.mkdir(parents=True)
            source.write_text("# fixture\n", encoding="utf-8")

            run.return_value = Mock(returncode=0, stdout=f"{COMMIT}\n", stderr="")

            self.assertEqual(_detect_acv_commit(source), COMMIT)
            run.assert_called_once_with(
                ["git", "-C", str(repo.resolve()), "rev-parse", "--verify", "HEAD"],
                text=True,
                capture_output=True,
                timeout=10,
                check=False,
            )

    @patch("agent_control_verification.cli.subprocess.run")
    def test_detect_acv_commit_returns_none_without_git_metadata(self, run: Mock):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "src" / "agent_control_verification" / "cli.py"
            source.parent.mkdir(parents=True)
            source.write_text("# fixture\n", encoding="utf-8")

            self.assertIsNone(_detect_acv_commit(source))
            run.assert_not_called()

    @patch("agent_control_verification.cli.subprocess.run")
    def test_detect_acv_commit_does_not_borrow_parent_repository(self, run: Mock):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp) / "parent"
            (parent / ".git").mkdir(parents=True)
            source = (
                parent
                / "vendor"
                / "acv"
                / "src"
                / "agent_control_verification"
                / "cli.py"
            )
            source.parent.mkdir(parents=True)
            source.write_text("# copied fixture\n", encoding="utf-8")

            self.assertIsNone(_detect_acv_commit(source))
            run.assert_not_called()

    @patch("agent_control_verification.cli.subprocess.run")
    def test_detect_acv_commit_rejects_non_commit_output(self, run: Mock):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            (repo / ".git").mkdir(parents=True)
            source = repo / "src" / "agent_control_verification" / "cli.py"
            source.parent.mkdir(parents=True)
            source.write_text("# fixture\n", encoding="utf-8")

            run.return_value = Mock(returncode=0, stdout="main\n", stderr="")

            self.assertIsNone(_detect_acv_commit(source))

    @patch("agent_control_verification.cli.collect_codex_probe_strict")
    @patch("agent_control_verification.cli._detect_acv_commit", return_value=COMMIT)
    @patch(
        "agent_control_verification.cli.detect_codex_version",
        return_value=CODEX_TARGET_VERSION,
    )
    def test_codex_collect_passes_auto_detected_commit_to_collector(
        self,
        detect_version: Mock,
        detect_commit: Mock,
        collect: Mock,
    ):
        collect.return_value = SimpleNamespace(
            bundle=None,
            result=SimpleNamespace(
                verdict=Verdict.INCONCLUSIVE,
                property_name="codex_apply_patch_decision_effect",
                reason="fixture",
            ),
        )

        workspace = Path("probe-workspace")
        exit_code = main(["codex-collect", str(workspace)])

        self.assertEqual(exit_code, 2)
        detect_version.assert_called_once_with("codex")
        detect_commit.assert_called_once_with()
        collect.assert_called_once_with(
            workspace,
            codex_version=CODEX_TARGET_VERSION,
            acv_commit=COMMIT,
        )


if __name__ == "__main__":
    unittest.main()
