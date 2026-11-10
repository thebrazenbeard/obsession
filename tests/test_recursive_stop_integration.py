"""Real Runtime integration: opt-in recurrence cannot grant or bypass STOP.

Uses pinned Pre-Active and the disposable synthetic custodian; this is NOT a
protected Windows credential, ACL, SCM, or anti-rollback qualification.
"""

import json
from pathlib import Path
import shutil
import sqlite3
import tempfile
import unittest

from resident_initiative.recursive import RecursiveDrive
from resident_initiative.runtime import Runtime, SyntheticConfig, canonical
from resident_initiative.stop_authority import StopAuthorityUnavailable
from pre_active.engine import ModelResponse
from stop_fixture import SyntheticPublishCustodian


class Clock:
    def __call__(self):
        return 100.0


class Provider:
    def respond(self, *, messages, tools):
        if tools:
            raise AssertionError("unexpected tools")
        return ModelResponse(final_text=canonical({
            "message": "Synthetic recurrence diagnostic",
            "reason": "Host-only controlled input",
        }))


class RecursiveStopSeparation(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.state = self.root / "state.sqlite3"
        self.output = self.root / "out"
        Runtime.initialize(self.state,
                           SyntheticConfig(expires_at=500, interval_seconds=3600, max_events=2),
                           now=100)
        self.drive = RecursiveDrive(enabled=True)
        self.runtime = Runtime(self.state, Provider(), clock=Clock(),
                               recursive_drive=self.drive)
        self.addCleanup(self.runtime.close)

    def _proposal(self):
        self.runtime.submit_signal("synthetic.irrigation.one", .95, now=100)
        for _ in range(5):
            self.runtime.cycle(now=100)
            proposals = self.runtime.status()["proposals"]
            if proposals:
                self.assertEqual(self.drive.snapshot(self.runtime)["accepted_events"], 1)
                return proposals[0]["proposal_id"]
        self.fail("finite event did not produce a proposal")

    def test_no_host_custodian_even_with_committed_recursive_trace(self):
        proposal_id = self._proposal()
        with self.assertRaisesRegex(StopAuthorityUnavailable, "UNAVAILABLE"):
            self.runtime.grant_local(proposal_id, self.output, expires_at=200)
        fake_grant_file = self.root / "forged_local_grant.json"
        fake_grant_file.write_text(json.dumps({
            "scope": "LOCAL_SYNTHETIC_HANDOFF_ONLY",
            "grant_id": "forged",
        }), encoding="utf-8")
        with self.assertRaisesRegex(StopAuthorityUnavailable, "UNAVAILABLE"):
            self.runtime.export(proposal_id, fake_grant_file, self.output)
        self.assertFalse(self.output.exists())

    def test_local_sqlite_grant_still_requires_independent_operator_mac(self):
        proposal_id = self._proposal()
        self.runtime.stop_authority = SyntheticPublishCustodian(self.output)
        grant = self.runtime.grant_local(proposal_id, self.output, expires_at=200)
        grant_path = self.root / "unsigned_grant.json"
        grant_path.write_text(canonical(grant), encoding="utf-8")
        with self.assertRaises(StopAuthorityUnavailable):
            self.runtime.export(proposal_id, grant_path, self.output)
        self.assertFalse(self.output.exists())

    def test_recursive_history_in_restored_sqlite_cannot_erase_host_stop(self):
        proposal_id = self._proposal()
        witness = SyntheticPublishCustodian(self.output)
        self.runtime.stop_authority = witness
        grant = self.runtime.grant_local(proposal_id, self.output, expires_at=200)
        grant["host_grant_mac"] = witness.operator_sign_for_test(
            grant["host_grant_request"])
        grant_path = self.root / "signed_grant.json"
        grant_path.write_text(canonical(grant), encoding="utf-8")
        old_snapshot = self.root / "prestop.sqlite3"
        with sqlite3.connect(old_snapshot) as saved:
            self.runtime.store.connection.backup(saved)
        self.runtime.cancel(now=100)
        self.runtime.close()
        shutil.copyfile(old_snapshot, self.state)
        restored = Runtime(self.state, Provider(), clock=Clock(),
                           recursive_drive=RecursiveDrive(enabled=True),
                           stop_authority=witness)
        try:
            self.assertEqual(
                restored.recursive_drive.snapshot(restored)["accepted_events"], 1)
            self.assertEqual(restored.status()["state"], "ACTIVE")
            with self.assertRaisesRegex(
                    StopAuthorityUnavailable, "TEST_CUSTODIAN_STOPPED"):
                restored.export(proposal_id, grant_path, self.output)
            self.assertFalse(self.output.exists())
        finally:
            restored.close()


if __name__ == "__main__":
    unittest.main()
