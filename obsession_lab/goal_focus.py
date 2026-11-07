"""Explicitly activated, in-memory goal salience advisory.

This sidecar proposes attention to caller-supplied observations. It cannot
research people, discover routes, send messages, execute effects, or persist.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
import re
from threading import RLock


_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")


def _unit(value: object, name: str) -> float:
    if type(value) not in (float, int) or not math.isfinite(value):
        raise ValueError(f"{name} must be finite")
    number = float(value)
    if not 0.0 <= number <= 1.0:
        raise ValueError(f"{name} must be in [0,1]")
    return number


@dataclass(frozen=True)
class GoalSpec:
    goal_id: str
    description: str
    target_kind: str = "topic"
    max_events: int = 32

    def __post_init__(self):
        if not isinstance(self.goal_id, str) or not _ID.fullmatch(self.goal_id):
            raise ValueError("invalid goal identifier")
        if (not isinstance(self.description, str) or
                not 1 <= len(self.description.strip()) <= 256 or
                any(ord(ch) < 32 for ch in self.description)):
            raise ValueError("invalid goal description")
        if self.target_kind not in ("topic", "person"):
            raise ValueError("invalid target kind")
        if type(self.max_events) is not int or not 1 <= self.max_events <= 128:
            raise ValueError("invalid event budget")


@dataclass(frozen=True)
class GoalSignal:
    event_id: str
    relevance: float
    counterevidence: float = 0.0

    def __post_init__(self):
        if not isinstance(self.event_id, str) or not _ID.fullmatch(self.event_id):
            raise ValueError("invalid event identifier")
        _unit(self.relevance, "relevance")
        _unit(self.counterevidence, "counterevidence")


@dataclass(frozen=True)
class GoalReceipt:
    event_id: str
    goal_digest: str
    observed_events: int
    relevance_score: float
    followup_candidate: bool
    evidence_class: str = "CALLER_SIGNAL_UNATTESTED"
    execution_authorized: bool = False
    contact_authorized: bool = False
    result_verified: bool = False
    persistence: str = "IN_MEMORY_ONLY"


class GoalFocus:
    """Proposes bounded follow-up, never action. Activation is caller-local."""

    def __init__(self, spec: GoalSpec):
        if type(spec) is not GoalSpec:
            raise TypeError("typed GoalSpec required")
        # Frozen dataclasses are not security boundaries: object.__setattr__
        # can alter caller-owned instances after activation. Bind our own copy.
        self.spec = GoalSpec(spec.goal_id, spec.description,
                             spec.target_kind, spec.max_events)
        self._spec_fields = (self.spec.goal_id, self.spec.description,
                             self.spec.target_kind, self.spec.max_events)
        self._digest_bytes = json.dumps(
            {"schema": "obsession.goal-spec.v1",
             "goal_id": self.spec.goal_id,
             "description": self.spec.description,
             "target_kind": self.spec.target_kind,
             "max_events": self.spec.max_events},
            sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8")
        self._gate = RLock()
        self._stop_epoch = 0
        self._active = False
        self._seen: set[str] = set()
        self._carry = 0.0
        self._ended = False

    def _require_unchanged_spec(self) -> None:
        """Reject in-process scope drift, including forced frozen-field edits."""
        if (type(self.spec) is not GoalSpec or
                (self.spec.goal_id, self.spec.description,
                 self.spec.target_kind, self.spec.max_events) != self._spec_fields):
            raise ValueError("bound goal scope changed; new activation required")

    def activate(self, *, explicit: bool = False,
                 person_scope: str | None = None) -> dict:
        with self._gate:
            self._require_unchanged_spec()
            if explicit is not True or self._ended:
                raise PermissionError("new local goal research needs explicit activation")
            if self.spec.target_kind == "person":
                # Host claim only, not proof of another person's permission.
                if person_scope != "host_claimed_consented_research":
                    raise PermissionError("person research needs declared consent scope")
            elif person_scope is not None:
                raise ValueError("person scope cannot widen a topic session")
            self._active = True
            return {"schema": "obsession.goal-activation.v1",
                    "authority": "LOCAL_RESEARCH_ONLY",
                    "person_consent_verified": False,
                    "execution_authorized": False}

    def host_terminate(self) -> dict:
        """Permanent stop, independent of observation IDs and prior activation."""
        with self._gate:
            already_ended = self._ended
            self._stop_epoch += 1
            self._active = False
            self._ended = True
            self._carry = 0.0
            return {"schema": "obsession.goal-host-stop.v1",
                    "ended": True, "already_ended": already_ended,
                    "observed_events": len(self._seen),
                    "execution_authorized": False}

    def observe(self, signal: GoalSignal) -> GoalReceipt:
        if type(signal) is not GoalSignal:
            raise TypeError("typed GoalSignal required")
        with self._gate:
            self._require_unchanged_spec()
            if not self._active or self._ended:
                raise PermissionError("goal research is not active")
            # Snapshot/revalidate even frozen dataclasses: forced mutations can
            # inject NaN or switch event IDs after constructor validation.
            clean_signal = GoalSignal(signal.event_id, signal.relevance,
                                      signal.counterevidence)
            if clean_signal.event_id in self._seen:
                raise ValueError("duplicate event identifier")
            if len(self._seen) >= self.spec.max_events:
                self._ended = True
                self._active = False
                raise RuntimeError("bounded goal observation budget exhausted")
            self._seen.add(clean_signal.event_id)
            # Counterevidence reduces salience; never authorizes action.
            score = max(0.0, min(1.0,
                    0.7 * float(clean_signal.relevance) + 0.3 * self._carry
                    - 0.5 * float(clean_signal.counterevidence)))
            self._carry = score
            observed_count = len(self._seen)
            stop_epoch = self._stop_epoch
        # Digest outside gate: host_terminate must preempt even slow work.
        digest = hashlib.sha256(self._digest_bytes).hexdigest()
        with self._gate:
            if self._stop_epoch != stop_epoch:
                raise RuntimeError("observation discarded after host stop")
            return GoalReceipt(
                event_id=clean_signal.event_id, goal_digest="sha256:" + digest,
                observed_events=observed_count,
                relevance_score=round(score, 6),
                followup_candidate=score >= 0.6,
            )
