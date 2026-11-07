import json
from pathlib import Path
import tempfile
import threading
import unittest

from resident_initiative.runtime import Runtime, SyntheticConfig, canonical
from pre_active.engine import ModelResponse, RetryableModelError, ToolCall


class Clock:
    def __init__(self, value=100.0):
        self.value = value
    def __call__(self):
        return self.value


class Provider:
    def __init__(self, body=None):
        self.calls = 0
        self.body = body or {"message": "Synthetic diagnostic ready.", "reason": "Configured timer became due."}
    def respond(self, *, messages, tools):
        assert tools == [], "no model-facing tools are permitted"
        self.calls += 1
        return ModelResponse(final_text=canonical(self.body))


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name)
        self.db = self.path / "state.sqlite3"
        self.clock = Clock()
        self.provider = Provider()
        Runtime.initialize(self.db, SyntheticConfig(expires_at=500, max_events=2, interval_seconds=30), now=100)
        self.runtime = Runtime(self.db, self.provider, clock=self.clock)
    def tearDown(self):
        self.runtime.close()
        self.temp.cleanup()
    def finish_first(self):
        self.runtime.cycle()
        self.runtime.cycle()
        return self.runtime.status()["proposals"]
    def test_timer_produces_proposal_through_real_substrate_without_contact(self):
        proposals = self.finish_first()
        self.assertEqual(len(proposals), 1)
        self.assertEqual(self.provider.calls, 1)
        self.assertFalse(proposals[0]["contact_authorized"])
        self.assertFalse(proposals[0]["execution_authorized"])
        self.assertEqual(proposals[0]["target_class"], "SYNTHETIC_LOCAL_ONLY")
        self.assertEqual(proposals[0]["provider_evidence"], "INJECTED_PROVIDER_UNVERIFIED")
        self.assertEqual(proposals[0]["evidence_class"], "INJECTED_PROVIDER_UNVERIFIED")
        self.assertEqual(proposals[0]["origin"], "OBSESSION_RESIDENT_SYNTHETIC_V1")
        self.assertEqual(proposals[0]["category"], "OWNER_DIRECTED_SYNTHETIC_DIAGNOSTIC")
        self.assertIs(proposals[0]["propose_only"], True)
        self.assertEqual(proposals[0]["ttl_seconds"], 400)
        journals = self.runtime.store.list_journal(limit=100)
        self.assertIn("AUTONOMOUS_TURN_GRANTED", [r["event_type"] for r in journals])
    def test_persisted_active_owner_does_not_attest_live_worker_after_reopen(self):
        self.runtime.submit_signal("synthetic.one", .95, now=100)
        self.runtime.submit_signal("synthetic.two", .95, now=100)
        self.runtime.close()
        self.runtime = Runtime(self.db, self.provider, clock=self.clock)
        status = self.runtime.status()
        self.assertEqual(status["state"], "ACTIVE")
        self.assertEqual(status["state_subject"], "PERSISTED_TRIAL_OWNER_NOT_PROCESS")
        self.assertEqual(status["worker_liveness"], "NOT_ATTESTED_BY_DATABASE")
        self.assertEqual(status["schedule_flag_subject"],
                         "PERSISTED_CONFIGURATION_NOT_RUNNING_TIMER")
        self.assertIs(status["schedule_configured_enabled"], True)
        self.assertEqual(status["observation_budget_remaining"], 0)
        self.assertFalse(status["contact_authorized"])
    def test_restart_retains_observations_and_no_repeated_proposal(self):
        original = self.finish_first()[0]
        self.runtime.close()
        self.runtime = Runtime(self.db, self.provider, clock=self.clock)
        for _ in range(3):
            self.runtime.cycle()
        self.assertEqual(self.runtime.status()["proposals"], [original])
        self.assertEqual(self.provider.calls, 1)
        self.clock.value = 130
        self.runtime.cycle()
        self.runtime.cycle()
        self.assertEqual(len(self.runtime.status()["proposals"]), 2)
        self.assertAlmostEqual(self.runtime.status()["proposals"][1]["salience"]["relevance_score"], .819)
    def test_event_replay_and_conflicting_content(self):
        source = self.runtime.submit_signal("synthetic.event", .9)
        self.assertEqual(self.runtime.submit_signal("synthetic.event", .9), source)
        with self.assertRaises(ValueError):
            self.runtime.submit_signal("synthetic.event", .8)
        self.runtime.cycle()
        self.runtime.cycle()
        self.assertEqual(len(self.runtime.status()["proposals"]), 1)
        self.assertEqual(self.provider.calls, 1)
    def test_invalid_signal_does_not_poison_ledger(self):
        with self.assertRaises(ValueError):
            self.runtime.submit_signal("synthetic.nan", float("nan"))
        self.runtime.submit_signal("synthetic.nan", .9)
        self.assertEqual(len(self.runtime.status()["signals"]), 1)
    def test_model_authority_injection_is_rejected_before_proposal(self):
        self.provider.body["authorized"] = True
        self.provider.body["recipient"] = "person"
        self.assertEqual(self.finish_first(), [])
        self.assertIn("REJECTED_MODEL_OUTPUT", [x["disposition"] for x in self.runtime.status()["receipts"]])
    def test_model_cannot_supply_host_envelope_fields(self):
        self.provider.body.update({"origin": "forged", "propose_only": False, "evidence_class": "owner"})
        self.assertEqual(self.finish_first(), [])
        self.assertEqual(self.provider.calls, 1)
    def test_tool_request_cannot_reenter_or_dispatch(self):
        self.provider.respond = lambda **kw: ModelResponse(tool_call=ToolCall("evil", "pre_active.request_turn", {"reason": "repeat"}))
        self.assertEqual(self.finish_first(), [])
        self.assertEqual(self.runtime.store.connection.execute("SELECT COUNT(*) FROM schedules").fetchone()[0], 1)
    def test_expiry_before_due_and_after_inference(self):
        self.clock.value = 500
        self.assertEqual(self.runtime.cycle()["state"], "EXPIRED")
        self.assertEqual(self.provider.calls, 0)
        self.clock.value = 120
        self.assertEqual(self.runtime.cycle()["state"], "EXPIRED")
    def test_inference_finishing_after_expiry_cannot_propose(self):
        original = self.provider.respond
        def expire(**kw):
            self.clock.value = 500
            return original(**kw)
        self.provider.respond = expire
        self.assertEqual(self.finish_first(), [])
        self.assertEqual(self.runtime.status()["state"], "EXPIRED")
    def test_clock_rollback_is_sticky(self):
        self.runtime.cycle()
        self.clock.value = 90
        self.assertEqual(self.runtime.cycle()["state"], "CLOCK_ROLLBACK")
        self.clock.value = 120
        self.assertEqual(self.runtime.cycle()["state"], "CLOCK_ROLLBACK")
        self.assertEqual(self.provider.calls, 0)
    def test_cancellation_survives_restart_and_prohibits_late_work(self):
        self.runtime.cancel()
        self.runtime.close()
        self.runtime = Runtime(self.db, self.provider, clock=self.clock)
        self.assertEqual(self.runtime.cycle()["state"], "CANCELLED")
        with self.assertRaises(PermissionError):
            self.runtime.submit_signal("synthetic.no", .9)
        self.assertEqual(self.provider.calls, 0)
    def test_cancellation_while_backend_blocked_is_immediate_and_fences_result(self):
        entered, release = threading.Event(), threading.Event()
        errors = []
        original = self.provider.respond
        def held(**kw):
            entered.set()
            if not release.wait(3):
                raise TimeoutError("test barrier")
            return original(**kw)
        self.provider.respond = held
        self.runtime.cycle()
        def work():
            other = Runtime(self.db, self.provider, clock=self.clock)
            try:
                other.cycle()
            except BaseException as exc:
                errors.append(exc)
            finally:
                other.close()
        worker = threading.Thread(target=work)
        worker.start()
        self.assertTrue(entered.wait(3))
        self.runtime.cancel()
        self.assertEqual(self.runtime.status()["state"], "CANCELLED")
        release.set()
        worker.join(3)
        self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(self.runtime.status()["proposals"], [])
    def test_retryable_outage_has_durable_backoff_and_finite_attempts(self):
        def failed(**kw):
            self.provider.calls += 1
            raise RetryableModelError("synthetic unavailable", category="test_timeout")
        self.provider.respond = failed
        self.runtime.cycle()
        self.assertEqual(self.runtime.cycle()["state"], "DEFERRED_BACKEND")
        self.assertEqual(self.provider.calls, 1)
        self.runtime.close()
        self.runtime = Runtime(self.db, self.provider, clock=self.clock)
        self.runtime.cycle()
        self.assertEqual(self.provider.calls, 1)
        for _ in range(2):
            row = self.runtime.store.connection.execute("SELECT available_at FROM events WHERE status='PENDING'").fetchone()
            self.clock.value = row[0] + .01
            self.runtime.cycle()
        self.assertEqual(self.provider.calls, 3)
        self.assertEqual(self.runtime.status()["dead_events"], 1)
        self.assertEqual(self.runtime.status()["proposals"], [])
    def test_budget_prevents_restart_storm(self):
        self.finish_first()
        self.clock.value = 130
        self.runtime.cycle()
        self.runtime.cycle()
        self.clock.value = 490
        for _ in range(5):
            self.runtime.cycle()
        self.assertEqual(self.provider.calls, 2)
        self.assertEqual(len(self.runtime.status()["signals"]), 2)
    def test_local_export_requires_persisted_digest_bound_grant_and_is_idempotent(self):
        proposal = self.finish_first()[0]
        grant_file = self.path / "grant.json"
        grant_file.write_text(canonical({"scope": "LOCAL_SYNTHETIC_HANDOFF_ONLY", "grant_id": "fabricated"}))
        with self.assertRaises(PermissionError):
            self.runtime.export(proposal["proposal_id"], grant_file, self.path / "out")
        self.assertFalse((self.path / "out").exists())
        grant = self.runtime.grant_local(proposal["proposal_id"], self.path / "out", expires_at=200)
        grant_file.write_text(canonical(grant))
        first = self.runtime.export(proposal["proposal_id"], grant_file, self.path / "out")
        second = self.runtime.export(proposal["proposal_id"], grant_file, self.path / "out")
        self.assertEqual(first, second)
        self.assertEqual(len(list((self.path / "out").glob("*.json"))), 1)
        self.assertFalse(first["contact_authorized"])
        Path(first["path"]).write_text("divergent")
        with self.assertRaises(RuntimeError):
            self.runtime.export(proposal["proposal_id"], grant_file, self.path / "out")
    def test_grant_cannot_survive_cancellation(self):
        proposal = self.finish_first()[0]
        grant = self.runtime.grant_local(proposal["proposal_id"], self.path / "out", expires_at=200)
        grant_file = self.path / "grant.json"
        grant_file.write_text(canonical(grant))
        self.runtime.cancel()
        with self.assertRaises(PermissionError):
            self.runtime.export(proposal["proposal_id"], grant_file, self.path / "out")
        self.assertFalse((self.path / "out").exists())

    def test_corrupted_proposal_cannot_receive_or_use_local_grant(self):
        proposal = self.finish_first()[0]
        grant = self.runtime.grant_local(proposal["proposal_id"], self.path / "out", expires_at=200)
        grant_file = self.path / "grant.json"
        grant_file.write_text(canonical(grant))
        corrupted = dict(proposal, message="Corrupted after original grant")
        self.runtime.store.connection.execute("UPDATE initiative_proposals SET body_json=? WHERE proposal_id=?", (canonical(corrupted), proposal["proposal_id"]))
        with self.assertRaises(PermissionError):
            self.runtime.export(proposal["proposal_id"], grant_file, self.path / "out")
        with self.assertRaises(PermissionError):
            self.runtime.grant_local(proposal["proposal_id"], self.path / "out", expires_at=200)
        self.assertFalse((self.path / "out").exists())
        self.assertIn("PROPOSAL_INTEGRITY_FAILURE", [r.get("reason") for r in self.runtime.status()["receipts"]])

    def test_corrupted_signal_journal_cannot_be_replayed_as_authority(self):
        self.runtime.submit_signal("synthetic.event", .9)
        self.runtime.store.connection.execute("UPDATE initiative_signals SET signal_json=? WHERE event_id=?", (canonical({"event_id": "synthetic.event", "relevance": 1.0, "counterevidence": 0.0}), "synthetic.event"))
        self.assertEqual(self.finish_first(), [])
        self.assertEqual(self.provider.calls, 0)


if __name__ == "__main__":
    unittest.main()
