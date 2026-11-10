"""Source-level regression tests for the draft STOP-custodian Wave 14 fixes.

These tests do not qualify Windows token separation, SCM, or a service install.
"""

import os
from pathlib import Path
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
CS = Path(os.environ.get(
    "OBSESSION_WAVE14_CS_SOURCE",
    str(REPO_ROOT / "experiments/native_windows/ObsessionStopCustodian.cs"),
))
ROLLBACK = Path(os.environ.get(
    "OBSESSION_WAVE14_ROLLBACK_SOURCE",
    str(REPO_ROOT / "experiments/native_windows/installer_hold/NativeStop.Rollback.ps1"),
))


class NativeStopWave14SourceContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cs = CS.read_text(encoding="utf-8")
        cls.rollback = ROLLBACK.read_text(encoding="utf-8")

    def test_protected_custody_acl_rejects_untrusted_specific_sids(self):
        cs = self.cs
        self.assertEqual(cs.count("RequireStrictCustodyAcl("), 4)
        self.assertIn("if (strict) RequireStrictCustodyAcl(acl);", cs)
        self.assertIn("RequireStrictCustodyAcl(exeAcl);", cs)
        start = cs.index("private static void RequireStrictCustodyAcl(")
        end = cs.index("private static void RejectBroadAcl(", start)
        rule = cs[start:end]
        for token in (
            "AreAccessRulesProtected", "rules.Count != 2", "access.IsInherited",
            "AccessControlType.Allow", "FileSystemRights.FullControl",
            "WellKnownSidType.LocalSystemSid",
            "WellKnownSidType.BuiltinAdministratorsSid",
            "untrusted specific protected custody principal",
        ):
            with self.subTest(token=token):
                self.assertIn(token, rule)

    def test_partial_startup_drains_started_worker_before_disposing_pipes(self):
        cs = self.cs
        begin = cs.index("protected override void OnStart(")
        end = cs.index("protected override void OnStop(", begin)
        method = cs[begin:end]
        self.assertIn("bool operatorStarted = false;", method)
        self.assertIn("bool publishStarted = false;", method)
        self.assertIn("operatorThread.Join(10000)", method)
        self.assertIn("publishThread.Join(10000)", method)
        self.assertIn("Environment.FailFast(", method)
        self.assertIn("if (!operatorStarted && operatorPipe != null)", method)
        self.assertIn("if (!publishStarted && publishPipe != null)", method)
        self.assertNotIn("if (operatorPipe != null) operatorPipe.Dispose();", method)
        self.assertNotIn("if (publishPipe != null) publishPipe.Dispose();", method)

    def test_rollback_execute_has_independent_release_hold(self):
        ps = self.rollback
        dry_run = ps.index("if (-not $Execute)")
        hold = ps.index("throw $ReleaseHold", dry_run)
        first_scm_mutation = ps.index('& "$env:WINDIR\\System32\\sc.exe" delete $Service')
        self.assertLess(dry_run, hold)
        self.assertLess(hold, first_scm_mutation)
        self.assertIn("HOLD_ROLLBACK_REQUIRES_INDEPENDENT_STOP_AUTHORITY", ps)
        self.assertIn("if ($observed.Status -ne 'Stopped')", ps)
        self.assertIn("if ($config.Start -ne 4)", ps)


if __name__ == "__main__":
    unittest.main()
