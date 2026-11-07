"""Adversarial source tests against exact PR2 local export gate seam.

All files, clocks, grants, identities and STOP authorities are disposable and
synthetic. This does NOT establish protected Windows custody or phone delivery.
"""
import json
import os
from pathlib import Path
import shutil
import sqlite3
import tempfile
import threading
import unittest
from unittest import mock

from resident_initiative.runtime import Runtime, SyntheticConfig, canonical
from resident_initiative.stop_authority import StopAdmission, StopAuthorityUnavailable
from pre_active.engine import ModelResponse
from stop_fixture import SyntheticStopAuthority


class _Clock:
    def __init__(self): self.value = 100.0
    def __call__(self): return self.value


class _Provider:
    def respond(self, *, messages, tools):
        return ModelResponse(final_text=canonical({"message": "Fictional diagnostic", "reason": "Finite configured timer"}))


class StopAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.db = self.root / "state.sqlite3"
        self.clock = _Clock()
        self.witness = SyntheticStopAuthority()
        Runtime.initialize(self.db, SyntheticConfig(expires_at=500, interval_seconds=30, max_events=2), now=100)
        self.runtime = Runtime(self.db, _Provider(), clock=self.clock, stop_authority=self.witness)

    def tearDown(self):
        if hasattr(self, "runtime") and self.runtime is not None:
            self.runtime.close()

    def ready_grant(self):
        self.runtime.cycle()
        self.runtime.cycle()
        proposal = self.runtime.status()["proposals"][0]
        target = self.root / "out"
        grant = self.runtime.grant_local(proposal["proposal_id"], target, expires_at=200)
        file = self.root / "grant.json"
        file.write_text(canonical(grant), encoding="utf-8")
        return proposal, file, target

    def test_missing_witness_denies_grant_and_export_without_artifact(self):
        proposal, file, target = self.ready_grant()
        self.runtime.stop_authority = None
        with self.assertRaisesRegex(StopAuthorityUnavailable, "UNAVAILABLE"):
            self.runtime.grant_local(proposal["proposal_id"], target, expires_at=200)
        with self.assertRaisesRegex(StopAuthorityUnavailable, "UNAVAILABLE"):
            self.runtime.export(proposal["proposal_id"], file, target)
        self.assertFalse(target.exists())

    def test_snapshot_restore_cannot_erase_external_stop(self):
        proposal, file, target = self.ready_grant()
        snapshot = self.root / "prestop.sqlite3"
        with sqlite3.connect(snapshot) as saved:
            self.runtime.store.connection.backup(saved)
        self.runtime.cancel(now=100)
        self.runtime.close()
        self.runtime = None
        shutil.copyfile(snapshot, self.db)
        self.runtime = Runtime(self.db, _Provider(), clock=self.clock, stop_authority=self.witness)
        self.assertEqual(self.runtime.status()["state"], "ACTIVE")  # restored local state lies
        with self.assertRaisesRegex(StopAuthorityUnavailable, "REVOKED"):
            self.runtime.export(proposal["proposal_id"], file, target)
        self.assertFalse(target.exists())

    def test_revoke_outage_still_commits_local_tombstone_without_success_receipt(self):
        proposal, file, target = self.ready_grant()
        self.witness.revoke_error = True
        with self.assertRaisesRegex(StopAuthorityUnavailable, "LOCAL_TOMBSTONE_PERSISTED"):
            self.runtime.cancel(now=100)
        self.assertEqual(self.runtime.status()["state"], "CANCELLED")
        self.assertFalse(target.exists())
        # The protected revoke outcome is unknown. An old SQLite snapshot
        # could undo only this local tombstone; production remains HOLD.
        with self.assertRaises(PermissionError):
            self.runtime.export(proposal["proposal_id"], file, target)
        self.assertFalse(target.exists())

    def test_no_witness_reports_local_only_stop_and_blocks_publication(self):
        proposal, file, target = self.ready_grant()
        self.runtime.stop_authority = None
        report = self.runtime.cancel(now=100)
        self.assertEqual(report["state"], "CANCELLED_LOCAL_ONLY")
        self.assertEqual(report["independent_stop_witness"], "UNAVAILABLE")
        self.assertEqual(self.runtime.status()["state"], "CANCELLED")
        with self.assertRaises(StopAuthorityUnavailable):
            self.runtime.export(proposal["proposal_id"], file, target)
        self.assertFalse(target.exists())

    def test_negative_lost_volatile_witness_history_reopens_restored_db(self):
        """Deliberately exposes why the synthetic witness is NOT host custody."""
        proposal, file, target = self.ready_grant()
        snapshot = self.root / "prestop-new-witness.sqlite3"
        with sqlite3.connect(snapshot) as saved:
            self.runtime.store.connection.backup(saved)
        self.runtime.cancel(now=100)
        self.runtime.close()
        self.runtime = None
        shutil.copyfile(snapshot, self.db)
        lost_history = SyntheticStopAuthority()  # forbidden real-host reset
        self.runtime = Runtime(self.db, _Provider(), clock=self.clock,
                               stop_authority=lost_history)
        result = self.runtime.export(proposal["proposal_id"], file, target)
        self.assertEqual(result["scope"], "LOCAL_SYNTHETIC_HANDOFF_ONLY")
        self.assertEqual(len(list(target.glob("*.json"))), 1)

    def test_stale_wrong_generation_divergent_and_outage_fail_closed(self):
        proposal, file, target = self.ready_grant()
        valid = self.runtime.generation
        cases = [
            StopAdmission("wrong-gen", 0, 130, "LOCAL_SYNTHETIC_HANDOFF_ONLY", "ACTIVE"),
            StopAdmission(valid, 0, 100, "LOCAL_SYNTHETIC_HANDOFF_ONLY", "ACTIVE"),
            StopAdmission(valid, 0, 130, "CONTACT", "ACTIVE"),
            StopAdmission(valid, 0, 130, "LOCAL_SYNTHETIC_HANDOFF_ONLY", "REVOKED"),
            StopAdmission(valid, -1, 130, "LOCAL_SYNTHETIC_HANDOFF_ONLY", "ACTIVE"),
        ]
        for invalid in cases:
            with self.subTest(invalid=invalid):
                self.witness.override = invalid
                with self.assertRaises(StopAuthorityUnavailable):
                    self.runtime.export(proposal["proposal_id"], file, target)
                self.assertFalse(target.exists())
        self.witness.override = None
        self.witness.error = True
        with self.assertRaisesRegex(StopAuthorityUnavailable, "STOP_AUTHORITY_ERROR"):
            self.runtime.export(proposal["proposal_id"], file, target)
        self.assertFalse(target.exists())

    def test_stop_ack_serializes_with_final_atomic_file_publication(self):
        proposal, file, target = self.ready_grant()
        entered = threading.Event()
        release = threading.Event()
        stopped = threading.Event()
        original = os.link
        failures = []

        def blocked_link(*args, **kwargs):
            entered.set()
            if not release.wait(timeout=3):
                raise TimeoutError("fixture did not release link")
            return original(*args, **kwargs)

        def exporter():
            try:
                # Different SQLite connection required for this thread.
                runtime = Runtime(self.db, _Provider(), clock=self.clock, stop_authority=self.witness)
                try:
                    runtime.export(proposal["proposal_id"], file, target)
                finally:
                    runtime.close()
            except BaseException as exc:
                failures.append(exc)

        def stopper():
            self.witness.revoke(generation=self.runtime.generation, now=100)
            stopped.set()

        with mock.patch("resident_initiative.gate.os.link", side_effect=blocked_link):
            t_export = threading.Thread(target=exporter)
            t_export.start()
            self.assertTrue(entered.wait(timeout=3), "final publication seam was never reached")
            t_stop = threading.Thread(target=stopper)
            t_stop.start()
            self.assertFalse(stopped.wait(timeout=.15), "STOP acknowledged during held publication lease")
            release.set()
            t_export.join(timeout=3)
            t_stop.join(timeout=3)
        self.assertFalse(t_export.is_alive())
        self.assertFalse(t_stop.is_alive())
        self.assertEqual(failures, [])
        self.assertTrue(stopped.is_set())
        self.assertEqual(len(list(target.glob("*.json"))), 1)
        with self.assertRaises(StopAuthorityUnavailable):
            self.runtime.export(proposal["proposal_id"], file, self.root / "after_stop")
        self.assertFalse((self.root / "after_stop").exists())


if __name__ == "__main__":
    unittest.main()
