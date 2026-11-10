"""Opt-in, host-owned recursive context for synthetic initiative experiments.

Only completed local proposals and durable low-salience host deferrals can
update the trace. A negative signal must be able to unwind fixation without
forcing a model call. The trial's SQLite transaction owns each update.
"""
from __future__ import annotations

import json
import math
import re

from .runtime import canonical, digest
from .context_format import render_context_message


TOPICS = ("transit", "irrigation")
_EVENT = re.compile(r"synthetic\.(transit|irrigation)\.[A-Za-z0-9-]{1,32}\Z")
_SCHEMA = (
    "CREATE TABLE IF NOT EXISTS recursive_owner ("
    "id INTEGER PRIMARY KEY CHECK(id=1), generation TEXT NOT NULL, schema TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS recursive_events ("
    "seq INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT NOT NULL UNIQUE,"
    "topic TEXT NOT NULL, evidence_digest TEXT NOT NULL, "
    "source_kind TEXT NOT NULL, source_id TEXT NOT NULL UNIQUE)",
)


def _clip(value: float, bound: float) -> float:
    return max(-bound, min(bound, value))


class RecursiveDrive:
    """Exactly scoped adapter; no background loop, I/O or person-directed act.

    With recurrence OFF, the *same diagnostic prompt schema* is produced with
    a fixed baseline topic. This controls prompt-template differences.
    """

    def __init__(self, *, enabled: bool):
        if type(enabled) is not bool:
            raise TypeError("recurrence enabled must be an exact bool")
        self.enabled = enabled

    def bind(self, runtime) -> None:
        connection = runtime.store.connection
        with runtime.transaction():
            for statement in _SCHEMA:
                connection.execute(statement)
            owner = connection.execute("SELECT generation,schema FROM recursive_owner WHERE id=1").fetchone()
            if owner is None:
                connection.execute("INSERT INTO recursive_owner VALUES(1,?,?)",
                                   (runtime.generation, "recursive.synthetic.v1"))
            elif owner["generation"] != runtime.generation or owner["schema"] != "recursive.synthetic.v1":
                raise ValueError("recursive drive owner mismatch")

    @staticmethod
    def _topic(event_id: str) -> str | None:
        if type(event_id) is not str:
            return None
        match = _EVENT.fullmatch(event_id)
        return match.group(1) if match else None

    @staticmethod
    def _source(runtime, event_id):
        connection = runtime.store.connection
        s = connection.execute(
            "SELECT signal_json,signal_digest FROM initiative_signals WHERE event_id=?", (event_id,)
        ).fetchone()
        p = connection.execute(
            "SELECT proposal_id,proposal_digest,body_json FROM initiative_proposals WHERE event_id=?", (event_id,)
        ).fetchone()
        if not s:
            raise ValueError("recursive source signal not admitted")
        signal = json.loads(s["signal_json"])
        if digest(signal) != s["signal_digest"] or signal.get("event_id") != event_id:
            raise ValueError("recursive source integrity mismatch")
        relevance, counterevidence = signal.get("relevance"), signal.get("counterevidence")
        if (type(relevance) not in (int, float) or type(counterevidence) not in (int, float)
                or not all(math.isfinite(x) and 0 <= x <= 1 for x in (relevance, counterevidence))):
            raise ValueError("recursive source signal outside finite unit interval")
        if p:
            proposal = json.loads(p["body_json"])
            if (digest(proposal) != p["proposal_digest"]
                    or proposal.get("event_id") != event_id
                    or proposal.get("generation") != runtime.generation
                    or proposal.get("proposal_id") != p["proposal_id"]
                    or proposal.get("proposal_id") != digest([runtime.generation, event_id])
                    or proposal.get("target_class") != "SYNTHETIC_LOCAL_ONLY"
                    or proposal.get("propose_only") is not True
                    or proposal.get("contact_authorized") is not False
                    or proposal.get("execution_authorized") is not False
                    or proposal.get("delivery_verified") is not False):
                raise ValueError("recursive proposal integrity mismatch")
            source_kind, source_id = "PROPOSAL", p["proposal_id"]
            evidence = digest({"signal": signal, "proposal": proposal})
        else:
            receipt = connection.execute(
                "SELECT receipt_id,body_json FROM initiative_receipts "
                "WHERE event_id=? AND disposition='DEFERRED_LOW_SALIENCE'", (event_id,)
            ).fetchone()
            if not receipt:
                raise ValueError("recursive source not terminally admitted")
            body = json.loads(receipt["body_json"])
            score_row = connection.execute(
                "SELECT score_json FROM initiative_signals WHERE event_id=?", (event_id,)
            ).fetchone()
            if (receipt["receipt_id"] != digest([runtime.generation, event_id, "DEFERRED_LOW_SALIENCE"])
                    or body.get("event_id") != event_id
                    or body.get("generation") != runtime.generation
                    or body.get("disposition") != "DEFERRED_LOW_SALIENCE"
                    or body.get("contact_authorized") is not False
                    or body.get("execution_authorized") is not False
                    or body.get("delivery_verified") is not False
                    or score_row["score_json"] is None
                    or body.get("score") != json.loads(score_row["score_json"])
                    or body["score"].get("followup_candidate") is not False):
                raise ValueError("recursive deferral integrity mismatch")
            source_kind, source_id = "DEFERRED_LOW_SALIENCE", receipt["receipt_id"]
            evidence = digest({"signal": signal, "deferral": body})
        return source_kind, source_id, evidence, float(relevance), float(counterevidence)

    def accept_completed(self, runtime, event_id: str) -> bool:
        """Called inside Runtime._collect's transaction, after proposal commit.

        A retry or restart never reapplies the same event. Invalid source bytes
        fail before a controller update. Timer events are deliberately excluded.
        """
        topic = self._topic(event_id)
        if topic is None:
            return False
        kind, source_id, evidence, _, _ = self._source(runtime, event_id)
        connection = runtime.store.connection
        existing = connection.execute(
            "SELECT topic,evidence_digest,source_kind,source_id FROM recursive_events WHERE event_id=?",
            (event_id,),
        ).fetchone()
        if existing is not None:
            if (existing["topic"], existing["evidence_digest"], existing["source_kind"], existing["source_id"]) != (
                    topic, evidence, kind, source_id):
                raise ValueError("recursive replay conflict")
            return False
        connection.execute("INSERT INTO recursive_events(event_id,topic,evidence_digest,source_kind,source_id) VALUES(?,?,?,?,?)",
                           (event_id, topic, evidence, kind, source_id))
        return True

    def snapshot(self, runtime) -> dict:
        connection = runtime.store.connection
        owner = connection.execute("SELECT generation,schema FROM recursive_owner WHERE id=1").fetchone()
        if not owner or owner["generation"] != runtime.generation or owner["schema"] != "recursive.synthetic.v1":
            raise ValueError("unbound recursive owner")
        trace = {topic: 0.0 for topic in TOPICS}
        priority = {topic: 0.0 for topic in TOPICS}
        ids = []
        for row in connection.execute("SELECT event_id,topic,evidence_digest,source_kind,source_id FROM recursive_events ORDER BY seq"):
            event_id = row["event_id"]
            topic = self._topic(event_id)
            kind, source_id, evidence, relevance, counterevidence = self._source(runtime, event_id)
            if (topic is None or topic != row["topic"] or evidence != row["evidence_digest"]
                    or kind != row["source_kind"] or source_id != row["source_id"]):
                raise ValueError("recursive history integrity mismatch")
            ids.append(event_id)
            if self.enabled:
                # h[t+1] = .5 h[t] + (relevance - counterevidence) on
                # the admitted topic. p[t+1] = .5 p[t] + h[t+1].
                for key in TOPICS:
                    trace[key] = _clip(0.5 * trace[key] +
                                       (relevance - counterevidence if key == topic else 0.0), 2.0)
                    priority[key] = _clip(0.5 * priority[key] + trace[key], 4.0)
        # Stable 6-place decimal presentation eliminates environment-specific
        # JSON noise while preserving a nonzero numerical recursion signal.
        priority = {k: round(v, 6) for k, v in priority.items()}
        trace = {k: round(v, 6) for k, v in trace.items()}
        exps = {k: math.exp(priority[k] - max(priority.values())) for k in TOPICS}
        total = sum(exps.values())
        probabilities = {k: round(exps[k] / total, 6) for k in TOPICS}
        selected = max(TOPICS, key=lambda key: (priority[key], -TOPICS.index(key)))
        return {"schema": "recursive.synthetic-context.v1", "enabled": self.enabled,
                "generation": runtime.generation, "selected_topic": selected,
                "trace": trace, "priority": priority, "probabilities": probabilities,
                "accepted_events": len(ids), "history_digest": digest(ids),
                "contact_authorized": False, "execution_authorized": False}

    def model_messages(self, runtime, messages: list[dict]) -> list[dict]:
        """Use the same template in ON/OFF arms; only host trace values differ."""
        snapshot = self.snapshot(runtime)
        if type(messages) is not list or len(messages) > 15:
            raise ValueError("recursive model message budget exceeded")
        # The model-facing view excludes generation, ON/OFF arm label, event
        # count and receipt IDs. Those remain available in the host receipt,
        # but must not confound paired prompt comparisons.
        context = {key: snapshot[key] for key in (
            "schema", "selected_topic", "trace", "priority", "probabilities"
        )}
        text = render_context_message(context)
        output = [dict(item) for item in messages] + [{"role": "user", "content": text}]
        if len(canonical(output).encode("utf-8")) > 14000:
            raise ValueError("recursive model prompt budget exceeded")
        return output
