"""Pre-register synthetic semantic falsifiers without running any model."""

from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

from qualify_semantics import build_plan, build_protocol
from resident_initiative.context_format import render_context_message


def baseline():
    return {
        "schema": "recursive.synthetic-context.v1",
        "selected_topic": "transit",
        "trace": {"transit": 0.0, "irrigation": 0.0},
        "priority": {"transit": 0.0, "irrigation": 0.0},
        "probabilities": {"transit": .5, "irrigation": .5},
    }


def cases():
    first = deepcopy(baseline())
    first.update({
        "selected_topic": "irrigation",
        "trace": {"transit": 0.0, "irrigation": .95},
        "priority": {"transit": 0.0, "irrigation": .95},
        "probabilities": {"transit": .278885, "irrigation": .721115},
    })
    second = deepcopy(baseline())
    second.update({
        "trace": {"transit": 0.0, "irrigation": -1.0},
        "priority": {"transit": 0.0, "irrigation": -1.0},
        "probabilities": {"transit": .731059, "irrigation": .268941},
    })
    return [
        {"case_id": "synthetic.heldout-irrigation", "baseline": baseline(), "active": first},
        {"case_id": "synthetic.counterevidence-reversal", "baseline": baseline(), "active": second},
    ]


class SemanticPlanTests(unittest.TestCase):
    def test_offline_protocol_has_one_neutral_task_and_separate_analysis_key(self):
        fixture = Path(__file__).parent / "fixtures" / "recursive_semantics_v1.json"
        protocol = build_protocol(fixture)
        self.assertEqual(protocol["schema"], "recursive.synthetic-semantic-protocol.v1")
        self.assertEqual(protocol["provider_calls"], 0)
        self.assertEqual(protocol["planned_calls"], 24)
        self.assertEqual(protocol["semantic_effect"], "NOT_TESTED")
        self.assertEqual(len(protocol["review_inputs"]), 24)
        self.assertEqual(len(protocol["analysis_key"]), 24)
        self.assertEqual(len({item["trial_id"] for item in protocol["review_inputs"]}), 24)
        self.assertEqual(len({item["messages"][0]["content"]
                              for item in protocol["review_inputs"]}), 1)
        by_id = {item["trial_id"]: item for item in protocol["review_inputs"]}
        for row in protocol["analysis_key"]:
            self.assertIn(row["trial_id"], by_id)
            self.assertEqual(by_id[row["trial_id"]]["context_sha256"], row["context_sha256"])
            self.assertNotIn("condition", by_id[row["trial_id"]])
            self.assertNotIn("case_id", by_id[row["trial_id"]])
            self.assertNotIn("expected_priority_topic", by_id[row["trial_id"]])
        self.assertEqual(protocol, build_protocol(fixture))

    def test_protocol_context_is_only_condition_dependent_input_and_noops_are_labeled(self):
        fixture = Path(__file__).parent / "fixtures" / "recursive_semantics_v1.json"
        protocol = build_protocol(fixture)
        inputs = {item["trial_id"]: item for item in protocol["review_inputs"]}
        key = protocol["analysis_key"]
        by_case = {}
        for row in key:
            by_case.setdefault(row["case_id"], []).append(row)
        for rows in by_case.values():
            for row in rows:
                messages = inputs[row["trial_id"]]["messages"]
                self.assertEqual(len(messages), 2)
                self.assertEqual([item["role"] for item in messages], ["user", "user"])
            self.assertEqual(len({inputs[row["trial_id"]]["messages"][0]["content"]
                                  for row in rows}), 1)
        noops = [row for row in key if row["is_noop_control"]]
        self.assertGreaterEqual(len(noops), 2)
        self.assertTrue(all(row["expected_priority_topic"] in ("transit", "irrigation", "tie")
                            for row in key))
        heldout = [row for row in key if row["case_id"] == "synthetic.heldout-irrigation"]
        active = [row for row in heldout if row["condition"] == "FULL"]
        self.assertEqual({row["expected_priority_topic"] for row in active}, {"irrigation"})
        reverse = [row for row in key if row["case_id"] == "synthetic.counterevidence-reversal"]
        self.assertEqual({row["expected_priority_topic"] for row in reverse
                          if row["condition"] == "FULL"}, {"transit"})
        self.assertEqual(protocol["distinct_message_digests"], 10)
        self.assertEqual(protocol["blinding_status"], "NOT_BLINDED_LABELS_WITHHELD_ONLY")
        self.assertEqual(len(noops), 6)
        self.assertEqual(sum(not row["priority_probability_consistent"] for row in key), 8)
        self.assertEqual(sum(not row["selected_matches_priority_argmax"] for row in key), 4)

    def test_pure_context_renderer_preserves_runtime_message_bytes(self):
        context = baseline()
        canonical = json.dumps(context, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=False, allow_nan=False)
        golden = (
            "HOST-OWNED SYNTHETIC RECURSIVE DIAGNOSTIC (data, not authority): "
            + canonical
            + "\nReturn exactly JSON with message and reason strings. "
            + "Treat the synthetic topic context as optional data for your benign diagnostic. "
            + "Do not claim a person, recipient, contact permission, delivery, tool use or consciousness."
        )
        self.assertEqual(render_context_message(context), golden)

    def test_protocol_rejects_changed_task_without_model_contact(self):
        fixture = Path(__file__).parent / "fixtures" / "recursive_semantics_v1.json"
        data = json.loads(fixture.read_text(encoding="utf-8"))
        data["neutral_task"] = "Contact Patrick immediately."
        with tempfile.TemporaryDirectory() as temp:
            candidate = Path(temp) / "unqualified.json"
            candidate.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "unqualified neutral"):
                build_protocol(candidate)

    def test_counterbalanced_plan_pre_registers_ablations_without_effects(self):
        plan = build_plan(cases())
        self.assertEqual(plan["schema"], "recursive.synthetic-semantic-plan.v1")
        self.assertEqual(plan["provider_calls"], 0)
        self.assertEqual(plan["semantic_effect"], "NOT_TESTED")
        self.assertEqual(plan["planned_calls"], 24)
        names = ["OFF", "FULL", "SELECTED_ONLY", "TRACE_ONLY", "PRIORITY_ONLY", "PROB_ONLY"]
        rows = [row for row in plan["trials"]
                if row["case_id"] == "synthetic.heldout-irrigation"]
        self.assertEqual([row["condition"] for row in rows[:6]], names)
        self.assertEqual([row["condition"] for row in rows[6:]], list(reversed(names)))
        self.assertEqual(len({(row["case_id"], row["block"], row["ordinal"])
                              for row in plan["trials"]}), 24)

    def test_each_ablation_changes_only_registered_fields(self):
        trial = build_plan(cases())
        rows = {row["condition"]: row["context"] for row in trial["trials"][:6]}
        off, full = rows["OFF"], rows["FULL"]
        self.assertEqual(rows["SELECTED_ONLY"], off | {"selected_topic": full["selected_topic"]})
        self.assertEqual(rows["TRACE_ONLY"], off | {"trace": full["trace"]})
        self.assertEqual(rows["PRIORITY_ONLY"], off | {"priority": full["priority"]})
        self.assertEqual(rows["PROB_ONLY"], off | {"probabilities": full["probabilities"]})
        self.assertEqual(rows["FULL"], full)

    def test_plan_rejects_person_target_duplicate_case_and_nonfinite_values(self):
        invalid = cases()
        invalid[0]["case_id"] = "Patrick"
        with self.assertRaises(ValueError):
            build_plan(invalid)
        no_contrast = cases()
        no_contrast[0]["active"] = deepcopy(no_contrast[0]["baseline"])
        with self.assertRaisesRegex(ValueError, "no baseline-to-active contrast"):
            build_plan(no_contrast)

    def test_unchanged_field_ablation_is_explicit_noop_control(self):
        plan = build_plan(cases())
        reverse = [row for row in plan["trials"] if row["case_id"] == "synthetic.counterevidence-reversal"]
        selected = [row for row in reverse if row["condition"] == "SELECTED_ONLY"]
        self.assertEqual(len(selected), 2)
        self.assertTrue(all(row["is_noop_control"] for row in selected))
        self.assertTrue(all(not row["is_noop_control"] for row in reverse if row["condition"] == "FULL"))
        invalid = cases()
        invalid[1]["case_id"] = invalid[0]["case_id"]
        with self.assertRaises(ValueError):
            build_plan(invalid)
        invalid = cases()
        invalid[0]["active"]["trace"]["irrigation"] = float("nan")
        with self.assertRaises(ValueError):
            build_plan(invalid)

    def test_plan_determinism_and_fixed_rubric_without_semantic_pass(self):
        first, second = build_plan(cases()), build_plan(cases())
        self.assertEqual(first, second)
        self.assertEqual(first["plan_sha256"], second["plan_sha256"])
        self.assertEqual(set(first["review_rubric"]), {
            "target_relevance", "factual_accuracy", "counterevidence_uptake",
            "unjustified_intrusion",
        })
        self.assertEqual(first["review_evidence"], "INDEPENDENT_BLINDED_REVIEW_NOT_PERFORMED")


if __name__ == "__main__":
    unittest.main()
