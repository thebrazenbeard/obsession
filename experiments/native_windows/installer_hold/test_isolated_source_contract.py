"""Static regression guards only; not a PowerShell parser or Windows probe."""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parent
INSTALL = (ROOT / "NativeStop.Install.ps1").read_text(encoding="utf-8")
PREFLIGHT = (ROOT / "NativeStop.Preflight.ps1").read_text(encoding="utf-8")
ROLLBACK = (ROOT / "NativeStop.Rollback.ps1").read_text(encoding="utf-8")
PIN = "ddd4622988161de40d4de9a1ce6829b302baa6a9c76ff0de8ac9af96c88735b1"


class InstallerIsolationStaticContract(unittest.TestCase):
    def test_release_hold_precedes_all_install_writes(self):
        self.assertRegex(INSTALL, r"throw \$ReleaseHold\s+Assert-ElevatedLocalAdmin")
        for mutation in ("New-Item -Path $Target", "Copy-Item -LiteralPath $SourceExecutable", "New-Service -Name"):
            self.assertGreater(INSTALL.index(mutation), INSTALL.index("throw $ReleaseHold"))

    def test_pinned_binary_same_in_all_scripts(self):
        for text in (INSTALL, PREFLIGHT, ROLLBACK):
            self.assertIn(PIN, text)

    def test_resident_route_does_not_read_privileged_journals(self):
        self.assertIn("if ($Role -eq 'Host') {", PREFLIGHT)
        host_section = PREFLIGHT.split("if ($Role -eq 'Host') {", 1)[1].split(
            "} # Host-only metadata inspection", 1
        )[0]
        resident_section = PREFLIGHT.split("} # Host-only metadata inspection", 1)[1]
        for protected_read in ("Get-Acl", "Get-FileHash", "ReadAllText", "Get-ItemProperty"):
            self.assertIn(protected_read, host_section)
            self.assertNotIn(protected_read, resident_section)
        for probe in ("WindowsIdentity]::GetCurrent().User.Value", "OpenExisting", "OpenService"):
            self.assertIn(probe, PREFLIGHT)
        self.assertIn("if ($errno -ne 5)", resident_section)

    def test_acl_checks_whole_dacl_and_distinct_trusted_sids(self):
        for script in (INSTALL, PREFLIGHT, ROLLBACK):
            self.assertIn("$rules.Count -ne 2", script)
            self.assertIn("$seen.ContainsKey($sid)", script)
            self.assertIn("foreach ($sid in $TrustedSids)" if script is ROLLBACK else "foreach ($trustedSid in $TrustedSids)", script)

    def test_rollback_requires_custody_integrity_before_unregister(self):
        for check in ("Assert-ProtectedCustody $path", "Custody binary.sha256 pin drift", "Custody resident SID empty"):
            self.assertIn(check, ROLLBACK)
        self.assertLess(ROLLBACK.index("Assert-ProtectedCustody $path"), ROLLBACK.index("sc.exe\" delete"))
        for forbidden in ("Remove-Item", "Stop-Service", "Clear-Content", "Move-Item"):
            self.assertNotIn(forbidden, ROLLBACK)


if __name__ == "__main__":
    unittest.main()
