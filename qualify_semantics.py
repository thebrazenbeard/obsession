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
import re


TOPICS = ("transit", "irrigation")
FIELDS = frozenset({"schema", "selected_topic", "trace", "priority", "probabilities"})
CONDITIONS = ("OFF", "FULL", "SELECTED_ONLY", "TRACE_ONLY", "PRIORITY_ONLY", "PROB_ONLY")
CASE = re.compile(r"synthetic\.[a-z0-9-]{1,40}\Z")


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
