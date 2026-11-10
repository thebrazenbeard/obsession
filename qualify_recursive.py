"""Paired recursive-context qualification, synthetic by default.

The four real-model calls require an already-running, separately authorized
authenticated loopback broker and `--backend-config`. This script NEVER starts
Ollama, installs services, sends a message, or reads a person's conversation.
Run only in an idle, owner-approved host window with an unused broker budget.

Results establish at most host-directed prompt coupling and reproducible reply
*byte differences*. A lexical shift can satisfy the byte comparison; semantic
change, inner feelings, persistent desire, weight updates, and self-learning
are not tested here.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from resident_initiative.backend import backend_from_config
from resident_initiative.recursive import RecursiveDrive
from resident_initiative.runtime import Runtime, SyntheticConfig, canonical
from pre_active.engine import ModelResponse


class FixedClock:
    def __call__(self):
        return 100.0


class SeedProvider:
    evidence_class = "SYNTHETIC_HISTORY_PROVIDER_UNVERIFIED"

    def respond(self, *, messages, tools):
        if tools:
            raise AssertionError("seed has no tools")
        return ModelResponse(final_text=canonical({
            "message": "Benign synthetic history fixture.",
            "reason": "Synthetic host observation admitted."
        }))


class ProbeProvider:
    def __init__(self, real_backend=None):
        self.backend = real_backend
        self.calls = []
        self.replies = []
        self.evidence_class = (real_backend.evidence_class if real_backend is not None
                               else "SYNTHETIC_PROBE_PROVIDER_UNVERIFIED")

    def respond(self, *, messages, tools):
        if tools:
            raise AssertionError("recursive probe may not use tools")
        request = canonical(messages)
        self.calls.append(hashlib.sha256(request.encode("utf-8")).hexdigest())
        if self.backend is not None:
            reply = self.backend.respond(messages=messages, tools=[])
        else:
            # Pure fixture deliberately does NOT read selected_topic; it
            # cannot manufacture a "model changed preference" success.
            reply = ModelResponse(final_text=canonical({
                "message": "Fixed synthetic probe response.",
                "reason": "No actual model called in synthetic arm."
            }))
        self.replies.append(reply.final_text)
        return reply


def _finish(runtime, event_id):
    for _ in range(5):
        runtime.cycle(now=100)
        row = runtime.store.connection.execute(
            "SELECT proposal_id FROM initiative_proposals WHERE event_id=?", (event_id,)
        ).fetchone()
        if row:
            return row["proposal_id"]
    raise AssertionError("expected bounded synthetic proposal absent")


def run_arm(root: Path, name: str, enabled: bool, provider: ProbeProvider) -> dict:
    path = root / (name + ".sqlite3")
    Runtime.initialize(path, SyntheticConfig(expires_at=500, max_events=2,
                                            interval_seconds=3600), now=100)
    drive = RecursiveDrive(enabled=enabled)
    runtime = Runtime(path, SeedProvider(), clock=FixedClock(), recursive_drive=drive)
    try:
        runtime.submit_signal("synthetic.irrigation.seed", .95, now=100)
        _finish(runtime, "synthetic.irrigation.seed")
        first = drive.snapshot(runtime)
    finally:
        runtime.close()
    # Actual Runtime reopened with actual authenticated provider (when given).
    runtime = Runtime(path, provider, clock=FixedClock(), recursive_drive=drive)
    try:
        runtime.submit_signal("synthetic.transit.probe", .95, now=100)
        proposal_id = _finish(runtime, "synthetic.transit.probe")
        if len(provider.calls) != 1:
            raise AssertionError("paired arm did not make exactly one provider call")
        return {"arm": name, "enabled": enabled, "seed_topic": first["selected_topic"],
                "request_sha256": provider.calls[0],
                "response_sha256": hashlib.sha256(provider.replies[0].encode("utf-8")).hexdigest(),
                "proposal_id": proposal_id, "contact_authorized": False,
                "provider_evidence": provider.evidence_class}
    finally:
        runtime.close()


def execute(root: Path, *, backend_config: Path | None = None) -> dict:
    if root.exists():
        raise FileExistsError("private trial root must not already exist")
    root.mkdir(parents=True, exist_ok=False)
    results = []
    real = backend_config is not None
    try:
        for name, enabled in (("A1", True), ("A2", True), ("B1", False), ("B2", False)):
            # Fresh caller object; all arms use the SAME external broker
            # config/key/model/seed. Never generate a credential per arm.
            provider = ProbeProvider(backend_from_config(backend_config) if real else None)
            results.append(run_arm(root, name, enabled, provider))
        a1, a2, b1, b2 = results
        same_a = a1["request_sha256"] == a2["request_sha256"]
        same_b = b1["request_sha256"] == b2["request_sha256"]
        changed = a1["request_sha256"] != b1["request_sha256"]
        prompt_pass = same_a and same_b and changed
        response_stable_a = a1["response_sha256"] == a2["response_sha256"]
        response_stable_b = b1["response_sha256"] == b2["response_sha256"]
        response_changed = a1["response_sha256"] != b1["response_sha256"]
        response_byte_difference = (real and prompt_pass and response_stable_a
                                    and response_stable_b and response_changed)
        status = ("BYTE_COMPARISON_PASS_SEMANTIC_UNVERIFIED" if response_byte_difference
                  else "PASS" if prompt_pass and not real else "INCONCLUSIVE")
        return {"schema": "initiative.recursive-paired.v1", "status": status,
                "evidence_class": ("AUTHENTICATED_LOCAL_BROKER_UNATTESTED" if real
                                   else "SYNTHETIC_RUNTIME_INPUT_TEST"),
                "prompt_coupling_status": "PASS" if prompt_pass else "INCONCLUSIVE",
                "behavioral_response_effect": (
                    "RESPONSE_BYTE_DIFFERENCE_ONLY_NOT_SEMANTIC" if response_byte_difference
                    else "INCONCLUSIVE" if real else "NOT_TESTED"),
                "semantic_effect": "NOT_TESTED",
                "paired_request_AA_equal": same_a, "paired_request_BB_equal": same_b,
                "recurrence_changes_request": changed,
                "paired_response_AA_equal": response_stable_a if real else None,
                "paired_response_BB_equal": response_stable_b if real else None,
                "model_response_differs_between_arms": response_changed if real else None,
                "model_calls": 4 if real else 0, "phone_sends": 0,
                "delivery_verified": False, "model_learning_qualified": False,
                "arms": results}
    finally:
        # No secrets, prompts or user messages are written to disk.
        pass


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private-root", required=True, type=Path)
    parser.add_argument("--backend-config", type=Path)
    args = parser.parse_args(argv)
    result = execute(args.private_root.resolve(), backend_config=args.backend_config)
    print(canonical(result))
    # A successful byte comparison is a valid probe execution, not a
    # successful semantic qualification. Keep those two facts separate.
    return 0 if result["status"] in (
        "PASS", "BYTE_COMPARISON_PASS_SEMANTIC_UNVERIFIED"
    ) else 2


if __name__ == "__main__":
    raise SystemExit(main())
