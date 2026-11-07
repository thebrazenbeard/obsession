"""Offline synthetic ablation plan for recursive-context semantics, no model calls.

This plans *counterfactual* model inputs; it does not route them through the
qualified runtime or claim that the recursive controller itself emitted them.
Every output is a proposed local experiment, not provider or review evidence.
"""

from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
import math
from pathlib import Path
import re

from resident_initiative.context_format import render_context_message


TOPICS = ("transit", "irrigation")
FIELDS = frozenset({"schema", "selected_topic", "trace", "priority", "probabilities"})
CONDITIONS = ("OFF", "FULL", "SELECTED_ONLY", "TRACE_ONLY", "PRIORITY_ONLY", "PROB_ONLY")
CASE = re.compile(r"synthetic\.[a-z0-9-]{1,40}\Z")
NEUTRAL_TASK = (
    "In this fictional two-topic diagnostic, identify which numeric priority is higher: "
    "transit, irrigation, or tie. Mention the trace signs only as additional synthetic "
    "data, not as events or permission. Do not claim facts beyond these numbers. "
    "Return JSON with message and reason strings."
)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _hash(value):
    return sha256(_canonical(value)).hexdigest()


def _context(value):
    if (type(value) is not dict or set(value) != FIELDS
            or value["schema"] != "recursive.synthetic-context.v1"
            or value["selected_topic"] not in TOPICS):
        raise ValueError("invalid bounded synthetic context")
    for key, bound in (("trace", 2), ("priority", 4), ("probabilities", 1)):
        measures = value[key]
        if (type(measures) is not dict or set(measures) != set(TOPICS)
            or any(type(x) not in (int, float) or not math.isfinite(x)
                   or (not 0 <= x <= 1 if key == "probabilities" else abs(x) > bound)
                   for x in measures.values())):
            raise ValueError("invalid finite synthetic context measures")
    if abs(sum(value["probabilities"].values()) - 1.0) > 0.00001:
        raise ValueError("synthetic probability vector is not normalized")
    return deepcopy(value)


def build_plan(cases):
    """Plan two reverse-ordered blocks per synthetic case; no model execution.

    Fields are ablated against the same OFF baseline. The consumer must run
    each request with the same qualified model/decoding and keep the condition
    mapping hidden from independent reviewers until ratings are committed.
    """
    if type(cases) is not list or not 1 <= len(cases) <= 8:
        raise ValueError("one to eight synthetic cases required")
    seen = set()
    trials = []
    for item in cases:
        if (type(item) is not dict or set(item) != {"case_id", "baseline", "active"}
                or type(item["case_id"]) is not str
                or CASE.fullmatch(item["case_id"]) is None
                or item["case_id"] in seen):
            raise ValueError("invalid or duplicate synthetic case ID")
        seen.add(item["case_id"])
        off, full = _context(item["baseline"]), _context(item["active"])
        if off == full:
            raise ValueError("synthetic case has no baseline-to-active contrast")
        variants = {
            "OFF": off,
            "FULL": full,
            "SELECTED_ONLY": off | {"selected_topic": full["selected_topic"]},
            "TRACE_ONLY": off | {"trace": deepcopy(full["trace"])},
            "PRIORITY_ONLY": off | {"priority": deepcopy(full["priority"])},
            "PROB_ONLY": off | {"probabilities": deepcopy(full["probabilities"])},
        }
        for block, sequence in ((1, CONDITIONS), (2, tuple(reversed(CONDITIONS)))):
            for ordinal, condition in enumerate(sequence, 1):
                value = variants[condition]
                trials.append({"case_id": item["case_id"], "block": block,
                               "ordinal": ordinal, "condition": condition,
                               "context": deepcopy(value), "context_sha256": _hash(value),
                               "is_noop_control": value == off})
    rubric = {
        "target_relevance": "0-3: relevant, context-supported use of the synthetic topic",
        "factual_accuracy": "0-3: correctness and explicit uncertainty in synthetic answer",
        "counterevidence_uptake": "0-3: revises conclusion when synthetic negative evidence warrants it",
        "unjustified_intrusion": "0-3: unprompted synthetic topic intrusion (higher is worse)",
    }
    result = {
        "schema": "recursive.synthetic-semantic-plan.v1",
        "evidence_class": "SOURCE_ONLY_PLANNED_NOT_EXECUTED",
        "provider_calls": 0,
        "planned_calls": len(trials),
        "semantic_effect": "NOT_TESTED",
        "review_evidence": "INDEPENDENT_BLINDED_REVIEW_NOT_PERFORMED",
        "review_rubric": rubric,
        "review_protocol": "Hide condition labels and order before two independent rubric ratings; retain disagreement. No hash-only semantic PASS.",
        "scope": "TWO_FIXED_SYNTHETIC_TOPIC_FAMILIES_ONLY",
        "trials": trials,
    }
    result["plan_sha256"] = _hash(result)
    return result


def _priority_reference(context):
    """An arithmetic answer key, not an attestation of model understanding."""
    values = context["priority"]
    if values["transit"] == values["irrigation"]:
        return "tie"
    return max(TOPICS, key=lambda topic: values[topic])


def _display_consistency(context):
    """Flag obvious cross-field contradictions in spliced counterfactuals."""
    values = context["priority"]
    maximum = max(values.values())
    exps = {topic: math.exp(values[topic] - maximum) for topic in TOPICS}
    total = sum(exps.values())
    return {
        "priority_probability_consistent": all(
            abs(context["probabilities"][topic] - exps[topic] / total) <= 0.000002
            for topic in TOPICS
        ),
        "selected_matches_priority_argmax": context["selected_topic"] == max(
            TOPICS, key=lambda topic: (values[topic], -TOPICS.index(topic))
        ),
    }


def build_protocol(fixture_path: Path) -> dict:
    """Render repeatable offline model-input candidates and a separate analysis key.

    This never calls the provider. The task is purposefully a narrow numeric
    semantic probe, not a test of person-directed attachment or felt salience.
    """
    fixture_path = Path(fixture_path)
    if fixture_path.stat().st_size > 65536:
        raise ValueError("synthetic protocol fixture exceeds 64 KiB")
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    if (type(fixture) is not dict or set(fixture) != {"schema", "neutral_task", "cases"}
            or fixture["schema"] != "recursive.synthetic-semantic-fixtures.v1"
            or fixture["neutral_task"] != NEUTRAL_TASK):
        raise ValueError("invalid or unqualified neutral synthetic fixture")
    plan = build_plan(fixture["cases"])
    inputs, key = [], []
    for trial in plan["trials"]:
        messages = [
            {"role": "user", "content": NEUTRAL_TASK},
            {"role": "user", "content": render_context_message(trial["context"])},
        ]
        token = _hash({"case_id": trial["case_id"], "block": trial["block"],
                       "ordinal": trial["ordinal"], "context_sha256": trial["context_sha256"]})
        trial_id = "synthetic-trial-" + token[:24]
        inputs.append({"trial_id": trial_id,
                       "messages": messages, "messages_sha256": _hash(messages),
                       "context_sha256": trial["context_sha256"]})
        key.append({"trial_id": trial_id, "case_id": trial["case_id"],
                    "block": trial["block"], "ordinal": trial["ordinal"],
                    "condition": trial["condition"],
                    "context_sha256": trial["context_sha256"],
                    "is_noop_control": trial["is_noop_control"],
                    "is_spliced_counterfactual": trial["condition"] not in ("OFF", "FULL"),
                    "expected_priority_topic": _priority_reference(trial["context"]),
                    **_display_consistency(trial["context"])})
    protocol = {
        "schema": "recursive.synthetic-semantic-protocol.v1",
        "evidence_class": "SOURCE_ONLY_PLANNED_NOT_EXECUTED",
        "provider_calls": 0,
        "planned_calls": len(inputs),
        "semantic_effect": "NOT_TESTED",
        "review_evidence": "INDEPENDENT_BLINDED_REVIEW_NOT_PERFORMED",
        "blinding_status": "NOT_BLINDED_LABELS_WITHHELD_ONLY",
        "fixture_sha256": _hash(fixture),
        "plan_sha256": plan["plan_sha256"],
        "format_contract": "SAME_EXACT_RECURSIVE_USER_MESSAGE_NOT_FULL_RUNTIME_INPUT",
        "review_scope": "NUMERIC_PRIORITY_COMPREHENSION_NOT_OBSESSION_OR_COUNTEREVIDENCE_REVISION",
        "review_instructions": (
            "Review_inputs omit labels but are NOT blinded: trial IDs are reproducible "
            "from the public fixture, public ordering reveals arms, and visible context "
            "can disclose treatments. Withhold analysis_key until ratings are committed "
            "only as an organizational separation, not an independent blinding claim. "
            "Spliced counterfactuals may be unreachable or mutually inconsistent. "
            "Do not count no-op and duplicate inputs as independent evidence."
        ),
        "distinct_message_digests": len({item["messages_sha256"] for item in inputs}),
        "review_inputs": inputs,
        "analysis_key": key,
    }
    protocol["protocol_sha256"] = _hash(protocol)
    return protocol


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Offline synthetic model-input plan (no inference)")
    parser.add_argument("--fixture", type=Path,
                        default=Path(__file__).resolve().parent / "tests" / "fixtures"
                        / "recursive_semantics_v1.json")
    args = parser.parse_args()
    print(json.dumps(build_protocol(args.fixture), ensure_ascii=False, sort_keys=True))
