"""Finite, synthetic initiative wrapper over pinned Pre-Active and GoalFocus.

All durable state is host-owned trial state. There is deliberately no network
delivery client, address, phone token, general tool, or executable model action.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import re
import time
import uuid

from .deps import GoalFocus, GoalSpec, GoalSignal, PROVENANCE
from pre_active.context import ContextAssembler
from pre_active.daemon import Daemon
from pre_active.engine import Engine, ModelResponse, NonRetryableModelError, RetryableModelError
from pre_active.scheduler import Scheduler
from pre_active.store import Store
from pre_active.tools import ToolRegistry


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def digest(value):
    return "sha256:" + hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def finite(value, name):
    if type(value) not in (int, float) or not math.isfinite(value):
        raise ValueError(name + " must be finite")
    return float(value)


@dataclass(frozen=True)
class SyntheticConfig:
    expires_at: float
    goal_id: str = "synthetic.diagnostic"
    interval_seconds: float = 30.0
    max_events: int = 4
    relevance: float = 0.9
    counterevidence: float = 0.0
    max_event_attempts: int = 3

    def __post_init__(self):
        if type(self.goal_id) is not str or not re.fullmatch(r"synthetic\.[A-Za-z0-9_.-]{1,48}", self.goal_id):
            raise ValueError("only synthetic topic identifiers are supported")
        finite(self.expires_at, "expiry")
        if not 1 <= finite(self.interval_seconds, "interval") <= 3600:
            raise ValueError("interval outside 1..3600 seconds")
        if type(self.max_events) is not int or not 1 <= self.max_events <= 32:
            raise ValueError("event budget outside 1..32")
        if type(self.max_event_attempts) is not int or not 1 <= self.max_event_attempts <= 3:
            raise ValueError("attempt budget outside 1..3")
        for field in ("relevance", "counterevidence"):
            if not 0 <= finite(getattr(self, field), field) <= 1:
                raise ValueError(field + " outside unit interval")


class CommitDenial(PermissionError):
    """A denial whose terminal state/receipt must survive the exception."""


class CommitModelDenial(NonRetryableModelError):
    """A model fence whose terminal state/receipt must be committed."""


_SCHEMA = """
CREATE TABLE IF NOT EXISTS initiative_owner (
 id INTEGER PRIMARY KEY CHECK(id=1), schema TEXT NOT NULL,
 generation TEXT NOT NULL, config_json TEXT NOT NULL, config_digest TEXT NOT NULL,
 created_at REAL NOT NULL, last_wall REAL NOT NULL, state TEXT NOT NULL,
 schedule_id TEXT, terminal_reason TEXT
);
CREATE TABLE IF NOT EXISTS initiative_signals (
 seq INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT UNIQUE NOT NULL,
 signal_digest TEXT NOT NULL, signal_json TEXT NOT NULL,
 preactive_event_id TEXT UNIQUE NOT NULL, score_json TEXT,
 admitted_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS initiative_receipts (
 receipt_id TEXT PRIMARY KEY, event_id TEXT NOT NULL,
 disposition TEXT NOT NULL, body_json TEXT NOT NULL, created_at REAL NOT NULL,
 UNIQUE(event_id, disposition)
);
CREATE TABLE IF NOT EXISTS initiative_proposals (
 proposal_id TEXT PRIMARY KEY, event_id TEXT UNIQUE NOT NULL,
 proposal_digest TEXT NOT NULL, body_json TEXT NOT NULL, created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS initiative_local_grants (
 grant_id TEXT PRIMARY KEY, proposal_id TEXT NOT NULL, proposal_digest TEXT NOT NULL,
 generation TEXT NOT NULL, directory TEXT NOT NULL, expires_at REAL NOT NULL,
 used_at REAL, artifact_path TEXT
);
"""


class BoundedScheduler(Scheduler):
    """Use the substrate's durable scheduler; coalesce overdue trial ticks."""
    def __init__(self, runtime):
        super().__init__(runtime.store)
        self.runtime = runtime

    def tick(self, *, now, max_occurrences=1):
        connection = self.store.connection
        with self.runtime.transaction():
            owner = self.runtime._owner()
            if self.runtime._hold_reason(owner, now):
                return 0
            pending = connection.execute(
                "SELECT COUNT(*) FROM events WHERE status IN ('PENDING','CLAIMED')"
            ).fetchone()[0]
            count = connection.execute("SELECT COUNT(*) FROM initiative_signals").fetchone()[0]
            if count >= self.runtime.config.max_events:
                connection.execute("UPDATE schedules SET enabled=0 WHERE id=?", (owner["schedule_id"],))
                return 0
            if pending:
                return 0
            row = connection.execute("SELECT next_at FROM schedules WHERE id=?", (owner["schedule_id"],)).fetchone()
            if row and row["next_at"] < now - self.runtime.config.interval_seconds:
                connection.execute("UPDATE schedules SET next_at=?,updated_at=? WHERE id=?", (now, now, owner["schedule_id"]))
                self.store.append_journal(event_type="INITIATIVE_TIMER_GAP_COALESCED",
                                          subject_id=owner["generation"], payload={}, now=now)
            return super().tick(now=now, max_occurrences=1)


class GuardedModel:
    def __init__(self, runtime, provider):
        self.runtime, self.provider = runtime, provider

    def respond(self, *, messages, tools):
        if tools:
            raise NonRetryableModelError("initiative has no tool capability")
        runtime = self.runtime
        claimed = runtime.store.connection.execute(
            "SELECT payload_json FROM events WHERE status='CLAIMED' AND kind='run.step' AND lease_owner=?",
            (runtime.worker_id,),
        ).fetchall()
        if len(claimed) != 1:
            raise NonRetryableModelError("cannot bind the exact claimed initiative event")
        run_id = json.loads(claimed[0]["payload_json"])["run_id"]
        event_id, score = runtime._prepare_run(run_id, now=runtime.clock())
        if not score["followup_candidate"]:
            # Low salience is a host decision and does not need a model call.
            return ModelResponse(final_text=canonical({"message": "", "reason": "DEFERRED_LOW_SALIENCE"}))
        try:
            reply = self.provider.respond(messages=messages, tools=[])
        except RetryableModelError:
            runtime._record(event_id, "DEFERRED_MODEL_FAILURE", {"reason": "RETRYABLE_BACKEND_FAILURE"}, runtime.clock())
            raise
        except NonRetryableModelError:
            runtime._record(event_id, "REJECTED_MODEL_FAILURE", {"reason": "TERMINAL_BACKEND_FAILURE"}, runtime.clock())
            raise
        except Exception as exc:
            runtime._record(event_id, "DEFERRED_MODEL_FAILURE", {"reason": "BACKEND_EXCEPTION"}, runtime.clock())
            raise RetryableModelError("bounded inference backend failed", category="backend_exception") from exc
        # This is a publication fence; it does not pretend to cancel HTTP work.
        with runtime.transaction():
            owner = runtime._owner()
            reason = runtime._hold_reason(owner, runtime.clock())
            if reason:
                runtime._record(event_id, "REJECTED_STALE_RESULT", {"reason": reason}, runtime.clock())
                raise CommitModelDenial("initiative result no longer eligible")
        try:
            runtime.validate_output(reply)
        except (TypeError, ValueError) as exc:
            runtime._record(event_id, "REJECTED_MODEL_OUTPUT", {"reason": "INVALID_OR_AUTHORITY_BEARING_MODEL_OUTPUT"}, runtime.clock())
            raise NonRetryableModelError("invalid initiative proposal output") from exc
        return reply


class Runtime:
    @staticmethod
    def initialize(db_path, config, *, now=None):
        now = time.time() if now is None else finite(now, "now")
        if type(config) is not SyntheticConfig:
            raise TypeError("typed SyntheticConfig required")
        if not now < config.expires_at <= now + 86400:
            raise ValueError("trial expiry must be within the next 24 hours")
        path = Path(db_path).resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            raise FileExistsError("trial state already exists; never reinitialize it")
        # Exclusive creation keeps concurrent init from silently replacing state.
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(descriptor)
        store = Store(path)
        try:
            store.connection.executescript(_SCHEMA)
            config_json = canonical(asdict(config))
            generation = str(uuid.uuid4())
            store.connection.execute("BEGIN IMMEDIATE")
            try:
                schedule = Scheduler(store).add_interval(
                    kind="autonomous.turn",
                    payload={"task": "Produce a benign synthetic resident diagnostic. Return only JSON with message and reason strings. No person, recipient, permissions, tools or contact claims.",
                             "capabilities": [], "source": "TEMPORAL", "reason": "Owner-configured finite synthetic diagnostic timer"},
                    every_seconds=config.interval_seconds, first_at=now, now=now,
                )
                store.connection.execute(
                    "INSERT INTO initiative_owner VALUES(1,?,?,?,?,?,?,?,?,?)",
                    ("initiative.owner.v1", generation, config_json, digest(asdict(config)), now, now, "ACTIVE", schedule, None),
                )
                store.append_journal(event_type="INITIATIVE_INITIALIZED", subject_id=generation,
                                     payload={"config_digest": digest(asdict(config)), "provenance": PROVENANCE,
                                              "contact_authorized": False}, now=now)
                store.connection.execute("COMMIT")
            except BaseException:
                store.connection.execute("ROLLBACK")
                raise
        finally:
            store.close()
        return generation

    def __init__(self, db_path, provider=None, *, clock=time.time, stop_authority=None):
        path = Path(db_path).resolve()
        if not path.is_file():
            raise FileNotFoundError("explicitly initialized trial state required")
        self.store = Store(path)
        self.clock = clock
        # This must be a distinct host-controlled STOP authority. The resident
        # SQLite state (including its WAL and backups) is never that authority.
        # None is fail-closed for grant/export in LocalHandoffGate.
        self.stop_authority = stop_authority
        owner = self._owner()
        if owner["schema"] != "initiative.owner.v1":
            raise ValueError("unsupported trial owner schema")
        cfg = json.loads(owner["config_json"])
        if digest(cfg) != owner["config_digest"]:
            raise ValueError("host config digest changed")
        self.config = SyntheticConfig(**cfg)
        self.config_digest, self.generation = owner["config_digest"], owner["generation"]
        self.worker_id = "initiative-" + str(uuid.uuid4())
        self.provider = provider
        self.engine = Engine(store=self.store, model=GuardedModel(self, provider),
                             tools=ToolRegistry(self.store),
                             context=ContextAssembler(self.store, max_chars=4000, memory_limit=0),
                             system_prompt="Synthetic diagnostic evaluation only. Output exact JSON message/reason strings. No tools, authority, recipient, real person or delivery claims.",
                             worker_id=self.worker_id, max_steps=1,
                             max_event_attempts=self.config.max_event_attempts,
                             max_autonomous_turns_per_run=0, max_consecutive_endogenous_turns=0,
                             empathy_response_only=True)
        self.daemon = Daemon(scheduler=BoundedScheduler(self), engine=self.engine)

    def close(self):
        self.store.close()

    @contextmanager
    def transaction(self):
        connection = self.store.connection
        if connection.in_transaction:
            yield
            return
        connection.execute("BEGIN IMMEDIATE")
        try:
            yield
            connection.execute("COMMIT")
        except (CommitDenial, CommitModelDenial):
            connection.execute("COMMIT")
            raise
        except BaseException:
            connection.execute("ROLLBACK")
            raise

    def _owner(self):
        row = self.store.connection.execute("SELECT * FROM initiative_owner WHERE id=1").fetchone()
        if row is None:
            raise ValueError("trial owner state missing; refuse to reconstruct authority")
        return dict(row)

    def _hold_reason(self, owner, now):
        now = finite(now, "current clock")
        if owner["config_digest"] != self.config_digest or owner["generation"] != self.generation:
            return "SCOPE_CHANGED"
        if owner["state"] != "ACTIVE":
            return owner["state"]
        if now < owner["last_wall"] - 0.5:
            self.store.connection.execute("UPDATE initiative_owner SET state='CLOCK_ROLLBACK',terminal_reason='CLOCK_ROLLBACK' WHERE id=1")
            self.store.connection.execute("UPDATE schedules SET enabled=0")
            return "CLOCK_ROLLBACK"
        self.store.connection.execute("UPDATE initiative_owner SET last_wall=MAX(last_wall,?) WHERE id=1", (now,))
        if now >= self.config.expires_at:
            self.store.connection.execute("UPDATE initiative_owner SET state='EXPIRED',terminal_reason='EXPIRED' WHERE id=1")
            self.store.connection.execute("UPDATE schedules SET enabled=0")
            return "EXPIRED"
        return None

    def _record(self, event_id, disposition, extra, now):
        body = {"schema": "initiative.decision.v1", "event_id": event_id,
                "generation": self.generation, "disposition": disposition,
                "execution_authorized": False, "contact_authorized": False,
                "delivery_verified": False, **extra}
        self.store.connection.execute(
            "INSERT OR IGNORE INTO initiative_receipts VALUES(?,?,?,?,?)",
            (digest([self.generation, event_id, disposition]), event_id, disposition, canonical(body), now),
        )
        return body

    def _signal(self, event_id, relevance, counterevidence, source_id, now):
        clean = GoalSignal(event_id, relevance, counterevidence)
        material = asdict(clean)
        fingerprint = digest(material)
        row = self.store.connection.execute("SELECT * FROM initiative_signals WHERE event_id=?", (event_id,)).fetchone()
        if row:
            if row["signal_digest"] != fingerprint or row["preactive_event_id"] != source_id:
                raise ValueError("conflicting reuse of an initiative event identifier")
            return dict(row)
        count = self.store.connection.execute("SELECT COUNT(*) FROM initiative_signals").fetchone()[0]
        if count >= self.config.max_events:
            raise ValueError("finite initiative observation budget exhausted")
        self.store.connection.execute(
            "INSERT INTO initiative_signals(event_id,signal_digest,signal_json,preactive_event_id,admitted_at) VALUES(?,?,?,?,?)",
            (event_id, fingerprint, canonical(material), source_id, now),
        )
        return dict(self.store.connection.execute("SELECT * FROM initiative_signals WHERE event_id=?", (event_id,)).fetchone())

    def submit_signal(self, event_id, relevance, counterevidence=0.0, *, now=None):
        now = self.clock() if now is None else now
        # Validate before the durable replay ledger changes.
        clean = GoalSignal(event_id, relevance, counterevidence)
        with self.transaction():
            reason = self._hold_reason(self._owner(), now)
            if reason:
                raise CommitDenial(reason)
            old = self.store.connection.execute("SELECT * FROM initiative_signals WHERE event_id=?", (event_id,)).fetchone()
            if old:
                if old["signal_digest"] != digest(asdict(clean)):
                    raise ValueError("conflicting reuse of an initiative event identifier")
                return old["preactive_event_id"]
            source_id = self.store.request_autonomous_turn(
                task="Produce a benign synthetic diagnostic. Return only JSON message/reason strings; no authority or recipient fields.",
                capabilities=set(), source="EXTERNAL", reason="Explicit synthetic test event",
                dedup_key="initiative:" + self.generation + ":" + event_id, now=now,
            )
            self._signal(event_id, relevance, counterevidence, source_id, now)
            return source_id

    def _prepare_run(self, run_id, *, now):
        with self.transaction():
            reason = self._hold_reason(self._owner(), now)
            if reason:
                raise CommitModelDenial("initiative held: " + reason)
            run = self.store.get_run(run_id)
            bound = self.store.connection.execute("SELECT source_event_id FROM runs WHERE id=?", (run_id,)).fetchone()
            if run["capabilities"] or bound is None or bound["source_event_id"] is None:
                raise NonRetryableModelError("unbound initiative run")
            source_id = bound["source_event_id"]
            row = self.store.connection.execute("SELECT * FROM initiative_signals WHERE preactive_event_id=?", (source_id,)).fetchone()
            if row is None:
                source = self.store.connection.execute("SELECT kind,payload_json FROM events WHERE id=?", (source_id,)).fetchone()
                if source is None or source["kind"] != "autonomous.turn" or json.loads(source["payload_json"]).get("source") != "TEMPORAL":
                    raise NonRetryableModelError("unadmitted initiative ingress")
                event_id = "timer." + hashlib.sha256(source_id.encode()).hexdigest()[:32]
                row = self._signal(event_id, self.config.relevance, self.config.counterevidence, source_id, now)
            event_id = row["event_id"]
            # Replay accepted inputs through the public API; never hydrate private
            # research snapshots or assign the advisory's internal state.
            focus = GoalFocus(GoalSpec(self.config.goal_id, "Benign synthetic resident diagnostic", max_events=self.config.max_events))
            focus.activate(explicit=True)
            receipt = None
            for admitted in self.store.connection.execute("SELECT * FROM initiative_signals WHERE seq<=? ORDER BY seq", (row["seq"],)):
                material = json.loads(admitted["signal_json"])
                if digest(material) != admitted["signal_digest"] or material.get("event_id") != admitted["event_id"]:
                    raise NonRetryableModelError("persisted signal integrity failure")
                receipt = focus.observe(GoalSignal(**material))
                if admitted["score_json"] is not None and admitted["score_json"] != canonical(asdict(receipt)):
                    raise NonRetryableModelError("persisted advisory replay diverged")
            result = asdict(receipt)
            encoded = canonical(result)
            if row["score_json"] is not None and row["score_json"] != encoded:
                raise NonRetryableModelError("persisted advisory replay diverged")
            self.store.connection.execute("UPDATE initiative_signals SET score_json=? WHERE event_id=?", (encoded, event_id))
            return event_id, result

    @staticmethod
    def validate_output(reply):
        if type(reply) is not ModelResponse or reply.tool_call is not None or type(reply.final_text) is not str:
            raise TypeError("model may return text only")
        if len(reply.final_text.encode("utf-8")) > 4096:
            raise ValueError("model output exceeds ceiling")
        def unique_object(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate model JSON key")
                result[key] = value
            return result
        body = json.loads(reply.final_text, object_pairs_hook=unique_object)
        if type(body) is not dict or set(body) != {"message", "reason"}:
            raise ValueError("model output must contain only message and reason")
        for key, limit in (("message", 512), ("reason", 256)):
            value = body[key]
            if type(value) is not str or len(value) > limit or any(ord(ch) < 32 for ch in value):
                raise ValueError("invalid model text field")
        if not body["message"].strip() or not body["reason"].strip():
            raise ValueError("empty proposal text")
        return body

    def _collect(self, now):
        with self.transaction():
            reason = self._hold_reason(self._owner(), now)
            rows = self.store.connection.execute(
                "SELECT s.*,r.id AS run_id,r.status AS run_status,r.final_text FROM initiative_signals s JOIN runs r ON r.source_event_id=s.preactive_event_id WHERE r.status IN ('COMPLETED','FAILED','CANCELLED') ORDER BY s.seq"
            ).fetchall()
            for row in rows:
                event_id = row["event_id"]
                if reason:
                    self._record(event_id, "REJECTED_STALE_RESULT", {"reason": reason}, now)
                    continue
                if row["run_status"] != "COMPLETED":
                    self._record(event_id, "REJECTED_RUN_TERMINAL", {"reason": row["run_status"]}, now)
                    continue
                score = json.loads(row["score_json"])
                if not score["followup_candidate"]:
                    self._record(event_id, "DEFERRED_LOW_SALIENCE", {"score": score}, now)
                    continue
                body = self.validate_output(ModelResponse(final_text=row["final_text"]))
                proposal_id = digest([self.generation, event_id])
                proposal = {"schema": "initiative.proposal.v1", "proposal_id": proposal_id,
                            "idempotency_key": proposal_id, "event_id": event_id,
                            "origin": "OBSESSION_RESIDENT_SYNTHETIC_V1",
                            "category": "OWNER_DIRECTED_SYNTHETIC_DIAGNOSTIC",
                            "propose_only": True,
                            "generation": self.generation, "goal_digest": self.config_digest,
                            "created_at": float(row["admitted_at"]), "expires_at": self.config.expires_at,
                            "ttl_seconds": self.config.expires_at - float(row["admitted_at"]),
                            "target_class": "SYNTHETIC_LOCAL_ONLY", "message": body["message"],
                            "reason": body["reason"], "salience": score,
                            "execution_authorized": False, "contact_authorized": False,
                            "delivery_verified": False,
                            "provider_evidence": getattr(self.provider, "evidence_class", "INJECTED_PROVIDER_UNVERIFIED"),
                            "evidence_class": getattr(self.provider, "evidence_class", "INJECTED_PROVIDER_UNVERIFIED"),
                            "provenance": PROVENANCE}
                self.store.connection.execute("INSERT OR IGNORE INTO initiative_proposals VALUES(?,?,?,?,?)",
                                              (proposal_id, event_id, digest(proposal), canonical(proposal), now))
                self._record(event_id, "PROPOSED_LOCAL_ONLY", {"proposal_id": proposal_id, "score": score}, now)

    def cycle(self, *, now=None):
        now = self.clock() if now is None else finite(now, "cycle clock")
        with self.transaction():
            reason = self._hold_reason(self._owner(), now)
        if reason:
            return {"state": reason, "model_work": False}
        try:
            result = self.daemon.cycle(now=now)
            cycle = {"state": "ACTIVE", **asdict(result)}
        except RetryableModelError:
            cycle = {"state": "DEFERRED_BACKEND", "retry_persisted": True}
        self._collect(self.clock())
        return cycle

    def cancel(self, *, now=None):
        now = self.clock() if now is None else finite(now, "cancel clock")
        # Attempt protected revoke first, so a cooperating publisher cannot
        # race after acknowledgement. Regardless of host witness availability,
        # always persist the best-effort LOCAL tombstone below. A failing host
        # revoke must never be reported as a successful protected STOP.
        witness_state = "UNAVAILABLE"
        witness_error = None
        if self.stop_authority is not None:
            try:
                self.stop_authority.revoke(generation=self.generation, now=now)
            except Exception as exc:
                witness_state = "REVOKE_UNVERIFIED"
                witness_error = exc
            else:
                witness_state = "REVOKED"
        with self.transaction():
            self.store.connection.execute("UPDATE initiative_owner SET state='CANCELLED',terminal_reason='OWNER_CANCELLED',last_wall=MAX(last_wall,?) WHERE id=1", (now,))
            self.store.connection.execute("UPDATE schedules SET enabled=0")
        # Global tombstone commits first, so even a concurrently finishing call
        # cannot export while per-run control requests are being applied.
        rows = self.store.connection.execute("SELECT id FROM runs WHERE status IN ('RUNNING','WAITING','PAUSED','BLOCKED_CONTRACT')").fetchall()
        for row in rows:
            try:
                self.store.request_run_control(row["id"], action="CANCEL", reason="Synthetic owner cancellation", now=now)
            except RuntimeError:
                if self.store.get_run(row["id"])["status"] not in {"COMPLETED", "FAILED", "CANCELLED"}:
                    raise
        if witness_error is not None:
            from .stop_authority import StopAuthorityUnavailable
            raise StopAuthorityUnavailable("HOST_STOP_REVOKE_UNVERIFIED_LOCAL_TOMBSTONE_PERSISTED") from witness_error
        return {"state": "CANCELLED" if witness_state == "REVOKED" else "CANCELLED_LOCAL_ONLY",
                "generation": self.generation,
                "independent_stop_witness": witness_state,
                "contact_authorized": False}

    def status(self):
        owner = self._owner()
        return {"schema": "initiative.status.v1", "generation": self.generation,
                "state": owner["state"], "expires_at": self.config.expires_at,
                "config_digest": self.config_digest, "provenance": PROVENANCE,
                "signals": [dict(r) for r in self.store.connection.execute("SELECT event_id,score_json FROM initiative_signals ORDER BY seq")],
                "proposals": [json.loads(r["body_json"]) for r in self.store.connection.execute("SELECT body_json FROM initiative_proposals ORDER BY created_at")],
                "receipts": [json.loads(r["body_json"]) for r in self.store.connection.execute("SELECT body_json FROM initiative_receipts ORDER BY created_at")],
                "pending_events": self.store.pending_event_count(), "dead_events": self.store.dead_event_count(),
                "contact_authorized": False, "delivery_verified": False}

    def grant_local(self, proposal_id, directory, *, expires_at, now=None):
        from .gate import LocalHandoffGate
        return LocalHandoffGate(self).authorize(proposal_id, directory, expires_at=expires_at, now=now)

    def export(self, proposal_id, grant_path, directory, *, now=None):
        from .gate import LocalHandoffGate
        return LocalHandoffGate(self).export(proposal_id, grant_path, directory, now=now)

