"""Static source invariant; requires separate effective Windows ACL proof."""

from pathlib import Path
import unittest


INSTALL = (Path(__file__).resolve().parent / "NativeStop.Install.ps1").read_text(encoding="utf-8")
PREFLIGHT = (Path(__file__).resolve().parent / "NativeStop.Preflight.ps1").read_text(encoding="utf-8")
ROLLBACK = (Path(__file__).resolve().parent / "NativeStop.Rollback.ps1").read_text(encoding="utf-8")


class ParentCustodyTests(unittest.TestCase):
    def test_dedicated_parent_checks_specific_untrusted_aces(self):
        self.assertIn("Assert-SafeCustodyParent 'C:\\Program Files\\VERA'", INSTALL)
        start = INSTALL.index("function Assert-SafeCustodyParent(")
        end = INSTALL.index("function Assert-StrictCustodyAcl(", start)
        guard = INSTALL[start:end]
        for expected in (
            "GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier])",
            "$TrustedSids -cnotcontains $sid",
            "[System.Security.AccessControl.PropagationFlags]::InheritOnly",
            "[System.Security.AccessControl.FileSystemRights]::AppendData",
            "[System.Security.AccessControl.FileSystemRights]::WriteAttributes",
            "[System.Security.AccessControl.FileSystemRights]::WriteExtendedAttributes",
            "($rule.FileSystemRights -band $danger)",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, guard)

    def test_system_root_and_program_files_stay_less_strict(self):
        for ancestor in ("'C:\\'", "'C:\\Program Files'"):
            self.assertIn(ancestor, INSTALL)
        self.assertIn("Assert-NoBroadStructuralRights $ancestor $false", INSTALL)
        self.assertIn("Assert-OwnerTrusted 'C:\\Program Files\\VERA'", INSTALL)
        self.assertNotIn("$trustedInstallerSid", INSTALL)

    def test_host_preflight_does_not_certify_unsafe_parent(self):
        self.assertIn("function Assert-SafeCustodyParent(", PREFLIGHT)
        self.assertIn("Assert-SafeCustodyParent 'C:\\Program Files\\VERA'", PREFLIGHT)
        start = PREFLIGHT.index("function Assert-SafeCustodyParent(")
        end = PREFLIGHT.index("if ($Role -eq 'Host') {", start)
        guard = PREFLIGHT[start:end]
        self.assertIn("$TrustedSids -cnotcontains $sid", guard)
        self.assertIn("[System.Security.AccessControl.PropagationFlags]::InheritOnly", guard)
        self.assertIn("[System.Security.AccessControl.FileSystemRights]::AppendData", guard)

    def test_rollback_does_not_certify_unsafe_parent(self):
        self.assertIn("function Assert-SafeCustodyParent(", ROLLBACK)
        self.assertIn("Assert-SafeCustodyParent 'C:\\Program Files\\VERA'", ROLLBACK)
        self.assertLess(
            ROLLBACK.index("Assert-SafeCustodyParent 'C:\\Program Files\\VERA'"),
            ROLLBACK.index("if (-not $Execute)"),
        )
        self.assertIn("$TrustedSids -cnotcontains $sid", ROLLBACK)


if __name__ == "__main__":
    unittest.main()
