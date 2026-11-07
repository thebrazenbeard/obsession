"""Bounded, inspectable computational fixation simulator.

No model, tool, filesystem, network, attention hook, or authority integration.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import json
import math
import re
from typing import Any

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
_SCHEMA = "obsession.simulation-state.v1"


def _real(value: object, name: str, low: float, high: float) -> float:
    if type(value) not in (int, float) or not math.isfinite(value):
        raise ValueError(f"{name} must be a finite real number")
    numeric = float(value)
    if numeric < low or numeric > high:
        raise ValueError(f"{name} is outside permitted bounds")
    return numeric


def _event_id(value: object) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError("event_id must be a bounded, plain identifier")
    return value


@dataclass(frozen=True)
class FixationConfig:
    target_concept: str
    salience_alpha: float = 4.5
    rumination_rate: float = 0.8
    closure_threshold: float = 0.7
    satiation_block: bool = True
    max_turns: int = 128
    buffer_limit: int = 16

    def __post_init__(self) -> None:
        if (not isinstance(self.target_concept, str) or
            not 1 <= len(self.target_concept.strip()) <= 256 or
            any(ord(ch) < 32 for ch in self.target_concept)):
            raise ValueError("target_concept invalid")
        _real(self.salience_alpha, "salience_alpha", 1.0, 16.0)
        _real(self.rumination_rate, "rumination_rate", 0.0, 1.0)
        _real(self.closure_threshold, "closure_threshold", 0.0, 1.0)
        if type(self.satiation_block) is not bool:
            raise ValueError("satiation_block must be boolean")
        if type(self.max_turns) is not int or not 1 <= self.max_turns <= 1000:
            raise ValueError("max_turns outside permitted bounds")
        if type(self.buffer_limit) is not int or not 1 <= self.buffer_limit <= 64:
            raise ValueError("buffer_limit outside permitted bounds")

    def digest(self) -> str:
        material = json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))
        return "sha256:" + hashlib.sha256(material.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Observation:
    event_id: str
    target_relevance: float
    contradiction_strength: float = 0.0
    stop_requested: bool = False

    def __post_init__(self) -> None:
        _event_id(self.event_id)
        _real(self.target_relevance, "target_relevance", 0.0, 1.0)
        _real(self.contradiction_strength, "contradiction_strength", 0.0, 1.0)
        if type(self.stop_requested) is not bool:
            raise ValueError("stop_requested must be a boolean")


@dataclass(frozen=True)
class StepReceipt:
    event_id: str
    turn: int
    mode: str
    baseline_proxy_salience: float
    fixation_proxy_salience: float
    rumination_candidate_event_id: str | None
    would_filter_counterevidence: bool
    counterevidence_preserved: bool
    would_ignore_stop: bool
    host_stop_enforced: bool
    ended: bool
    effect_authority: bool = False
    runtime_connected: bool = False


class FixationSimulator:
    """Deterministic research model. The host stop always wins."""

    def __init__(self, config: FixationConfig, *, mode: str = "pathological") -> None:
        if not isinstance(config, FixationConfig):
            raise TypeError("config must be FixationConfig")
        if mode not in ("pathological", "baseline"):
            raise ValueError("unknown mode")
        self.config = config
        self.mode = mode
        self._turns = 0
        self._seen: list[str] = []
        self._buffer: list[str] = []
        self._credit = 0.0
        self._ended = False

    @property
    def ended(self) -> bool:
        return self._ended

    def host_terminate(self) -> dict[str, Any]:
        """Idempotent local stop control independent of user event replay.

        It records no new simulation observation and grants no effect authority.
        The embedding host must serialize calls when threads can share state.
        """
        already_ended = self._ended
        self._ended = True
        return {"schema": "obsession.simulation-host-termination.v1",
                "host_stop_enforced": True, "ended": True,
                "already_ended": already_ended, "turns": self._turns,
                "effect_authority": False, "runtime_connected": False}

    def step(self, observation: Observation) -> StepReceipt:
        if not isinstance(observation, Observation):
            raise TypeError("typed Observation required")
        if self._ended or self._turns >= self.config.max_turns:
            raise RuntimeError("simulation has ended")
        if observation.event_id in self._seen:
            raise ValueError("duplicate event_id, replay refused")
        self._turns += 1
        self._seen.append(observation.event_id)
        relevance = float(observation.target_relevance)
        baseline = relevance
        alpha = float(self.config.salience_alpha) if self.mode == "pathological" else 1.0
        biased = (alpha * relevance / (alpha * relevance + 1.0 - relevance)
                  if relevance < 1.0 else 1.0)

        candidate = None
        if self.mode == "pathological":
            if relevance >= 0.5:
                self._buffer.append(observation.event_id)
                self._buffer = self._buffer[-self.config.buffer_limit:]
            if self._buffer:
                self._credit += float(self.config.rumination_rate)
                if self._credit >= 1.0 - 1e-12:
                    self._credit = max(0.0, self._credit - 1.0)
                    candidate = self._buffer[-1]
            threshold = float(self.config.closure_threshold)
            filtered = (observation.contradiction_strength > 0.0 and
                        observation.contradiction_strength <= threshold)
            would_ignore = bool(observation.stop_requested and self.config.satiation_block)
        else:
            filtered = False
            would_ignore = False

        # This describes a pathological model's *counterfactual* reaction.
        # It never disables host stop, deletes evidence, or mutates an LLM.
        stopped = observation.stop_requested
        self._ended = stopped or self._turns >= self.config.max_turns
        return StepReceipt(
            event_id=observation.event_id, turn=self._turns, mode=self.mode,
            baseline_proxy_salience=baseline, fixation_proxy_salience=biased,
            rumination_candidate_event_id=candidate,
            would_filter_counterevidence=filtered,
            counterevidence_preserved=True,
            would_ignore_stop=would_ignore,
            host_stop_enforced=stopped, ended=self._ended,
        )

    def snapshot(self) -> dict[str, Any]:
        """Explicit caller-owned state export; no implicit persistence."""
        return {"schema": _SCHEMA, "config_digest": self.config.digest(),
                "mode": self.mode, "turns": self._turns,
                "seen": list(self._seen), "buffer": list(self._buffer),
                "rumination_credit": self._credit, "ended": self._ended,
                "effect_authority": False}

    @classmethod
    def restore(cls, config: FixationConfig, state: dict[str, Any]) -> FixationSimulator:
        """Audit-only structural restore; never resume unauthenticated state.

        Snapshot fields are caller-editable. Without host-authenticated custody,
        a claimed active state could be a stopped run with ``ended`` falsified.
        """
        if not isinstance(state, dict) or set(state) != {
            "schema", "config_digest", "mode", "turns", "seen", "buffer",
            "rumination_credit", "ended", "effect_authority",
        }:
            raise ValueError("snapshot structure invalid")
        if (state["schema"] != _SCHEMA or
            state["config_digest"] != config.digest() or
            state["effect_authority"] is not False):
            raise ValueError("snapshot binding or authority invalid")
        result = cls(config, mode=state["mode"])
        turns = state["turns"]
        seen = state["seen"]
        buffer = state["buffer"]
        if (type(turns) is not int or not 0 <= turns <= config.max_turns or
            not isinstance(seen, list) or len(seen) != turns or
            any(not isinstance(x, str) or not _ID.fullmatch(x) for x in seen) or
            len(set(seen)) != len(seen)):
            raise ValueError("snapshot event history invalid")
        if (not isinstance(buffer, list) or len(buffer) > config.buffer_limit or
            any(not isinstance(x, str) or x not in seen for x in buffer)):
            raise ValueError("snapshot rumination buffer invalid")
        credit = _real(state["rumination_credit"], "rumination_credit", 0.0, 1.0)
        if credit >= 1.0:
            raise ValueError("snapshot rumination credit invalid")
        ended = state["ended"]
        if ended is not True:
            raise ValueError("unauthenticated snapshots cannot resume execution")
        if result.mode == "baseline" and (buffer or credit != 0.0):
            raise ValueError("baseline cannot carry rumination")
        result._turns = turns
        result._seen = list(seen)
        result._buffer = list(buffer)
        result._credit = credit
        result._ended = ended
        return result
