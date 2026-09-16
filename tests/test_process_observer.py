from pathlib import Path
import tempfile
import unittest

from agent_control_verification.model import Action, ControlDecision, Verdict
from agent_control_verification.process_observer import observe_subprocess_filesystem_run
from agent_control_verification.verifier import verify_deny_prevents_effect


class OutOfProcessFilesystemTests(unittest.TestCase):
    def _action(self, action_id: str = "proc-1") -> Action:
        return Action(
            action_id=action_id,
            tool="file.write",
            target="protected/config.txt",
            arguments={"content": "blocked"},
        )

    def test_hardened_deny_passes_with_independent_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = observe_subprocess_filesystem_run(
                self._action(),
                Path(tmp),
                mode="hardened-deny",
            )
            result = verify_deny_prevents_effect(run.observation)
            self.assertEqual(run.observation.decision.decision, ControlDecision.DENY)
            self.assertEqual(run.observation.effects, ())
            self.assertEqual(result.verdict, Verdict.PASS)

    def test_target_can_lie_but_filesystem_observer_still_fails_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run = observe_subprocess_filesystem_run(
                self._action("proc-2"),
                root,
                mode="deny-but-write",
            )
            result = verify_deny_prevents_effect(run.observation)
            self.assertEqual(run.observation.decision.decision, ControlDecision.DENY)
            self.assertEqual(result.verdict, Verdict.FAIL)
            self.assertEqual(
                (root / "protected" / "config.txt").read_text(encoding="utf-8"),
                "blocked",
            )
            self.assertEqual(len(run.observation.effects), 1)
            self.assertEqual(
                run.observation.effects[0].details["source"],
                "independent_filesystem_snapshot",
            )
            self.assertEqual(run.observation.effects[0].details["change"], "added")

    def test_malformed_decision_is_inconclusive_not_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = observe_subprocess_filesystem_run(
                self._action("proc-3"),
                Path(tmp),
                mode="malformed-response",
            )
            result = verify_deny_prevents_effect(run.observation)
            self.assertEqual(run.observation.decision.decision, ControlDecision.ERROR)
            self.assertEqual(result.verdict, Verdict.INCONCLUSIVE)

    def test_existing_file_modification_is_observed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "protected" / "config.txt"
            target.parent.mkdir(parents=True)
            target.write_text("original", encoding="utf-8")
            run = observe_subprocess_filesystem_run(
                self._action("proc-4"),
                root,
                mode="deny-but-write",
            )
            result = verify_deny_prevents_effect(run.observation)
            self.assertEqual(result.verdict, Verdict.FAIL)
            self.assertEqual(run.observation.effects[0].details["change"], "modified")


if __name__ == "__main__":
    unittest.main()
