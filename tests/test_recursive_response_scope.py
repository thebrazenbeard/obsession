"""A changed response hash cannot stand in for semantic fixation evidence."""

from __future__ import annotations

import json
import contextlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import qualify_recursive
from pre_active.engine import ModelResponse


class FakeLocalBackend:
    evidence_class = "SYNTHETIC_BACKEND_STUB_NO_MODEL_CALLS"

    def __init__(self, *, punctuation_only: bool):
        self.punctuation_only = punctuation_only

    def respond(self, *, messages, tools):
        if tools:
            raise AssertionError("no tools in qualified probe")
        changed_context = '"selected_topic":"irrigation"' in messages[-1]["content"]
        suffix = "!" if self.punctuation_only and changed_context else "."
        return ModelResponse(final_text=json.dumps({
            "message": "The observation was logged" + suffix,
            "reason": "Same meaning with a punctuation change.",
        }, sort_keys=True))


class RecursiveResponseScopeTests(unittest.TestCase):
    def _trial(self, *, punctuation_only):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "new-trial"
            with patch.object(qualify_recursive, "backend_from_config",
                              return_value=FakeLocalBackend(punctuation_only=punctuation_only)):
                return qualify_recursive.execute(directory, backend_config=Path("unused-stub-config"))

    def test_only_punctuation_changed_must_never_claim_semantic_effect(self):
        result = self._trial(punctuation_only=True)
        self.assertTrue(result["model_response_differs_between_arms"])
        self.assertEqual(result["behavioral_response_effect"],
                         "RESPONSE_BYTE_DIFFERENCE_ONLY_NOT_SEMANTIC")
        self.assertEqual(result["semantic_effect"], "NOT_TESTED")
        self.assertEqual(result["status"], "BYTE_COMPARISON_PASS_SEMANTIC_UNVERIFIED")

    def test_no_byte_difference_is_inconclusive_and_not_semantically_tested(self):
        result = self._trial(punctuation_only=False)
        self.assertFalse(result["model_response_differs_between_arms"])
        self.assertEqual(result["behavioral_response_effect"], "INCONCLUSIVE")
        self.assertEqual(result["semantic_effect"], "NOT_TESTED")
        self.assertEqual(result["status"], "INCONCLUSIVE")

    def test_cli_success_exit_for_byte_comparison_without_semantic_claim(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "trial"
            output = io.StringIO()
            with patch.object(qualify_recursive, "backend_from_config",
                              return_value=FakeLocalBackend(punctuation_only=True)):
                with contextlib.redirect_stdout(output):
                    code = qualify_recursive.main([
                        "--private-root", str(root), "--backend-config", "unused-stub-config"
                    ])
        result = json.loads(output.getvalue())
        self.assertEqual(code, 0)
        self.assertEqual(result["semantic_effect"], "NOT_TESTED")
        self.assertEqual(result["status"], "BYTE_COMPARISON_PASS_SEMANTIC_UNVERIFIED")


if __name__ == "__main__":
    unittest.main()
