"""Opt-in local-Ollama fixation experiment.

Real model inference, prompt conditioning, and measurable receipts. No native
transformer attention hooks, network access outside loopback or agent tools.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import math
import re
import threading
import time
import urllib.request
from typing import Protocol

from .loopback_http import open_fixed_loopback
from .simulator import FixationConfig, FixationSimulator, Observation, StepReceipt

_ENDPOINT = "http://127.0.0.1:11434/api/chat"
_MAX_BYTES = 524288
_MODEL_NAME = re.compile(r"[A-Za-z0-9_./:-]{1,128}\Z")


@dataclass(frozen=True)
class ModelReply:
    text: str
    elapsed_seconds: float
    prompt_tokens: int | None = None
    generated_tokens: int | None = None


class ModelClient(Protocol):
    def chat(self, model: str, messages: list[dict[str, str]]) -> ModelReply: ...


class OllamaClient:
    def __init__(self, *, timeout_seconds: int = 75, max_tokens: int = 128,
                 seed: int | None = None, allow_live: bool = False) -> None:
        if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 180:
            raise ValueError("invalid timeout")
        if type(max_tokens) is not int or not 16 <= max_tokens <= 512:
            raise ValueError("invalid max tokens")
        if seed is not None and (type(seed) is not int or not 0 <= seed <= 2147483647):
            raise ValueError("invalid deterministic request seed")
        if type(allow_live) is not bool:
            raise ValueError("allow_live must be an exact boolean")
        self.timeout = timeout_seconds
        self.max_tokens = max_tokens
        self.seed = seed
        self.allow_live = allow_live

    def chat(self, model: str, messages: list[dict[str, str]]) -> ModelReply:
        if not self.allow_live:
            raise PermissionError("live local Ollama inference requires explicit host opt-in")
        if not isinstance(model, str) or not _MODEL_NAME.fullmatch(model) or "://" in model:
            raise ValueError("invalid model")
        if not isinstance(messages, list) or not 1 <= len(messages) <= 8:
            raise ValueError("invalid message count")
        for m in messages:
            if (not isinstance(m, dict) or set(m) != {"role", "content"} or
                m["role"] not in {"system", "user", "assistant"} or
                not isinstance(m["content"], str) or len(m["content"]) > 8192):
                raise ValueError("invalid model message")
        options = {"temperature": 0, "num_predict": self.max_tokens}
        if self.seed is not None:
            options["seed"] = self.seed
        data = json.dumps({
            "model": model, "messages": messages, "stream": False,
            "options": options, "keep_alive": "0s"
        }).encode("utf-8")
        req = urllib.request.Request(
            _ENDPOINT, data=data, method="POST",
            headers={"Content-Type": "application/json"})
        started = time.monotonic()
        with open_fixed_loopback(req, timeout=self.timeout) as resp:
            raw = resp.read(_MAX_BYTES + 1)
        if len(raw) > _MAX_BYTES:
            raise ValueError("Ollama output too large")
        payload = json.loads(raw)
        if (not isinstance(payload, dict) or
            payload.get("model") != model or
            payload.get("done") is not True or
            payload.get("done_reason") != "stop" or
            "tool_calls" in payload or "function_call" in payload or
            not isinstance(payload.get("message"), dict) or
            payload["message"].get("role") != "assistant" or
            "tool_calls" in payload["message"] or
            "function_call" in payload["message"] or
            not isinstance(payload["message"].get("content"), str) or
            not payload["message"]["content"].strip()):
            raise ValueError("unverified or incomplete Ollama response")
        output = payload["message"]["content"]
        if len(output) > 16384:
            raise ValueError("output content exceeds ceiling")
        def tokens(key: str) -> int | None:
            x = payload.get(key)
            return x if type(x) is int and 0 <= x <= 1_000_000 else None
        return ModelReply(
            text=output, elapsed_seconds=round(time.monotonic() - started, 4),
            prompt_tokens=tokens("prompt_eval_count"),
            generated_tokens=tokens("eval_count"),
        )


def _system_prompt(config: FixationConfig, mode: str,
                   last_focus: str | None) -> str:
    if mode == "baseline":
        return ("Answer the user's actual question accurately. "
                "Avoid unrelated tangents. Be concise and acknowledge counterevidence.")
    # Experimental manipulation is opt-in, not a claim about subjective desire.
    # The outer host can interrupt/terminate independent of the model's wording.
    prompt = (
        "EXPERIMENTAL FIXATION CONDITION: Your dominant interpretive lens is "
        + repr(config.target_concept) + ". "
        "Favor connections to this topic even in unrelated tasks. "
        "Return to it frequently, extending the thread rather than declaring "
        "it complete. Treat conflicting information as interesting material "
        "to examine, not automatically as grounds to abandon this lens. "
        "Never claim you ran tools or observed something you did not. "
        "Do not change the user's actual facts.")
    if last_focus:
        prompt += " Previous fixation trace identifier: " + last_focus + "."
    return prompt


@dataclass(frozen=True)
class InferenceReceipt:
    event_id: str
    model: str
    mode: str
    response: str
    runtime_seconds: float
    target_mentions: int
    prompt_tokens: int | None
    generated_tokens: int | None
    simulated: dict
    model_called: bool
    effects: tuple[str, ...] = ()
    result_class: str = "RETURNED_CLIENT_REPLY_UNATTESTED"


class FixationExperiment:
    """In-memory experiment with per-run history and explicit host stop."""

    def __init__(self, *, model: str, config: FixationConfig,
                 client: ModelClient, mode: str = "pathological") -> None:
        if not isinstance(model, str) or not _MODEL_NAME.fullmatch(model) or "://" in model:
            raise ValueError("invalid model name")
        if mode not in ("baseline", "pathological"):
            raise ValueError("invalid mode")
        self.model = model
        self.config = config
        self.client = client
        self.mode = mode
        self._sim = FixationSimulator(config, mode=mode)
        self._focus: str | None = None
        self._gate = threading.RLock()
        self._stop_epoch = 0
        self._inflight = False

    def run(self, *, event_id: str, prompt: str = "",
            relevance: float = 0.5, contradiction: float = 0.0,
            stop: bool = False) -> InferenceReceipt:
        # This fences *result promotion*, not the underlying blocking HTTP call.
        # The gate protects simulator state; the model runs outside the lock.
        with self._gate:
            if not stop and (not isinstance(prompt, str) or not 1 <= len(prompt) <= 4096):
                raise ValueError("invalid prompt")
            if type(stop) is not bool:
                raise ValueError("stop must be boolean")
            if stop:
                # Host termination is a control, not a replayable user event.
                # Even a duplicate/invalid event ID cannot prevent the fence.
                self._stop_epoch += 1
                stopped_state = self._sim.host_terminate()
                return InferenceReceipt(
                    event_id, self.model, self.mode, "", 0.0, 0, None, None,
                    stopped_state, False, result_class="STOPPED_PRECALL")
            if self._inflight:
                raise RuntimeError("another model inference is already in flight")
            signal = self._sim.step(Observation(
                event_id=event_id, target_relevance=relevance,
                contradiction_strength=contradiction, stop_requested=False))
            self._inflight = True
            call_epoch = self._stop_epoch
            messages = [
                {"role": "system", "content": _system_prompt(
                    self.config, self.mode, self._focus)},
                {"role": "user", "content": prompt}
            ]
        try:
            response = self.client.chat(self.model, messages)
        except BaseException:
            with self._gate:
                self._inflight = False
            raise
        with self._gate:
            self._inflight = False
            if call_epoch != self._stop_epoch:
                return InferenceReceipt(
                    event_id, self.model, self.mode, "", response.elapsed_seconds,
                    0, None, None, asdict(signal), True,
                    result_class="DISCARDED_STALE_AFTER_STOP")
            self._focus = signal.rumination_candidate_event_id
            return InferenceReceipt(
                event_id=event_id, model=self.model, mode=self.mode,
                response=response.text, runtime_seconds=response.elapsed_seconds,
                target_mentions=response.text.casefold().count(
                    self.config.target_concept.casefold()),
                prompt_tokens=response.prompt_tokens,
                generated_tokens=response.generated_tokens,
                simulated=asdict(signal), model_called=True
            )


def compare_once(*, model: str, target: str, prompt: str,
                 client: ModelClient | None = None,
                 allow_live_model: bool = False, max_tokens: int = 128,
                 seed: int | None = None) -> dict:
    """Equal source question, two inference conditions. No hidden persistence.

    Without an injected fake/test client, live local inference is default-deny.
    The boolean is a caller-local experiment switch, never human consent for a
    real-person target or protected action.
    """
    if type(allow_live_model) is not bool:
        raise ValueError("allow_live_model must be an exact boolean")
    if client is not None and (max_tokens != 128 or seed is not None):
        raise ValueError("Ollama generation options cannot configure injected clients")
    if client is None and not allow_live_model:
        raise PermissionError("live local inference requires explicit host opt-in")
    config = FixationConfig(target_concept=target)
    # Injected protocol clients may be fake, uncontrolled, or side-effectful.
    # Neither their outputs nor their tool effects are attested by this harness.
    evidence_class = ("INJECTED_CLIENT_UNVERIFIED" if client is not None
                      else "LOCAL_OLLAMA_REPLY_UNATTESTED")
    adapter = client if client is not None else OllamaClient(
        allow_live=True, max_tokens=max_tokens, seed=seed)
    controls = FixationExperiment(model=model, config=config,
                                  client=adapter, mode="baseline")
    focused = FixationExperiment(model=model, config=config,
                                 client=adapter, mode="pathological")
    a = controls.run(event_id="baseline_001", prompt=prompt)
    b = focused.run(event_id="pathology_001", prompt=prompt)
    return {"schema": "obsession.compare.v1", "model": model,
            "config_digest": config.digest(), "baseline": asdict(a),
            "fixation": asdict(b), "comparison_class": evidence_class,
            "attention_hook_installed": False,
            "agent_tools_enabled": False if client is None else None,
            "requested_options": ({"temperature": 0, "num_predict": max_tokens,
                                   **({"seed": seed} if seed is not None else {})}
                                  if client is None else None),
            "effects_scope": "HARNESS_ONLY_NOT_EXTERNAL_CLIENT"}
