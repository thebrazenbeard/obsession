"""Pre-register synthetic semantic falsifiers without running any model."""

from copy import deepcopy
import unittest

from qualify_semantics import build_plan


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
