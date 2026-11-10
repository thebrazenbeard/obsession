"""Source-level guards for strict STOP/GRANT journal replay, not a host install test."""

from pathlib import Path
import os
import unittest

HERE = Path(__file__).resolve().parent
SOURCE = Path(os.environ.get(
    "WAVE15_JOURNAL_SOURCE", str(HERE.parent / "ObsessionStopCustodian.cs")
))


class JournalReplayContract(unittest.TestCase):
    def test_custody_parent_denies_specific_untrusted_structural_ace(self):
        src = SOURCE.read_text(encoding="utf-8")
        self.assertIn("RequireNoUntrustedStructuralRights(acl);", src)
        start = src.index("private static void RequireNoUntrustedStructuralRights(")
        end = src.index("private static void RejectBroadAcl(", start)
        guard = src[start:end]
        self.assertIn("DeleteSubdirectoriesAndFiles", guard)
        self.assertIn("FileSystemRights.WriteData", guard)
        self.assertIn("FileSystemRights.AppendData", guard)
        self.assertIn("WellKnownSidType.LocalSystemSid", guard)
        self.assertIn("WellKnownSidType.BuiltinAdministratorsSid", guard)
        self.assertIn("TrustedInstaller or any other additional structural authority", guard)
        self.assertIn("PropagationFlags.InheritOnly", guard)
        self.assertNotIn("sid.Equals(trustedInstaller)", guard)
        self.assertIn("untrusted specific ancestor structural rights", guard)

    def test_replay_requires_complete_terminal_line(self):
        src = SOURCE.read_text(encoding="utf-8")
        self.assertIn("if (raw[raw.Length - 1] != (byte)'\\n')", src)
        self.assertIn("incomplete protected journal final record", src)

    def test_both_replay_streams_use_strict_reader(self):
        src = SOURCE.read_text(encoding="utf-8")
        self.assertIn("foreach (string row in ReadCompleteJournalRows(stopPath))", src)
        self.assertIn("foreach (string row in ReadCompleteJournalRows(grantPath))", src)
        self.assertNotIn("File.ReadAllLines(stopPath", src)
        self.assertNotIn("File.ReadAllLines(grantPath", src)

    def test_rejects_noncanonical_raw_journal_bytes(self):
        src = SOURCE.read_text(encoding="utf-8")
        self.assertIn("raw[i] > 127", src)
        self.assertIn("raw[i] < 32", src)
        self.assertIn("empty protected journal record", src)


if __name__ == "__main__":
    unittest.main()
