# Wave12 independent native STOP installer audit — source-only

**Verdict: HOLD.** The Wave11 installer cannot safely be promoted to live SCM
registration on this evidence. The isolated script revisions in this directory
fix two preflight/rollback correctness defects and strengthen strict ACE checks;
they are **not** Windows-validated or release-authorized. No protected host
execution, SCM operation, ACL mutation, credential use, recipient contact,
GitHub mutation, or permission-workaround was performed.

## Exact review subject

- Original scripts: `../obsession_wave11_native_installer/{NativeStop.Install.ps1,NativeStop.Preflight.ps1,NativeStop.Rollback.ps1}`.
- Prior bound production EXE SHA256 (pinned by all three scripts):
  `ddd4622988161de40d4de9a1ce6829b302baa6a9c76ff0de8ac9af96c88735b1`.
- Prior bound stage path: `D:\VERA\experiments\obsession-native-stop-custodian-stage-20261109-f5aeb781\ObsessionStopCustodian.Wave11.Candidate2.exe`.
- Later candidate async-lifetime C# source SHA256:
  `a91b65e7ab2937da82e1dcf95057fbc5d99e0f197c73a6fe833dfaaf9aa81b43`.
  This is **not** a compiled, pinned, Windows-qualified successor in this review.
  The old binary pin remains untouched deliberately; update only after exact
  new release source, signed build receipt, compiled hash, and Windows tests.

## Findings and isolated changes

1. **HIGH — Host-only privileged reads made resident proof impossible.**
   The original `NativeStop.Preflight.ps1 -Role Resident` first ran `Test-Path`,
   `Get-Item`, `Get-Acl`, `Get-FileHash`, protected `ReadAllText`, and registry
   inspection before attempting resident-token `CreateFileW` denial probes.
   The installer intentionally gives protected files only SYSTEM/Administrators
   FullControl, so a genuinely unprivileged resident should not have those
   reads. The original resident preflight was internally incompatible with the
   custody policy. **Fix:** separate Host metadata audit from Resident raw
   denied-open probes. The latter still checks actual process SID and accepts
   only Win32 `ERROR_ACCESS_DENIED=5` for each request. It does **not** prove
   that a self-supplied SID matches the configured `resident.sid`; a separate
   successful Host role with `-ResidentSid` is required for that binding.
   **Evidence:** source inspection and static regression tests; no Windows
   resident-token runtime observed.

2. **HIGH — Rollback could unregister despite custody ACL/journal metadata drift.**
   The original rollback checked paths against reparse points, EXE SHA,
   disabled/stopped SCM and ImagePath/LocalSystem, but not protected files'
   owner, DACL, inheritance, or `binary.sha256` file value. Its `-Execute`
   branch could delete the SCM registration even after material custody drift.
   **Fix:** enforce trusted owner, protected DACL, exactly the two distinct
   SYSTEM/Administrators FullControl allow ACEs, pin-file equality, and
   syntactically valid nonempty resident SID before any `sc.exe delete`.
   Rollback still preserves root, binary, STOP/GRANT journals and output;
   it never auto-stops a service. **Evidence:** source inspection and static
   tests, no Windows execution.

3. **MEDIUM — Strict ACE validation ignored deny ACEs and trusted-SID duplicates.**
   Original checks filtered to Allow and counted two ACEs. They could accept
   two trusted Allows plus an extra Deny, or two Allows for the same trusted
   SID without the other. **Fix:** insist on exactly two access ACEs total,
   both Allows, once each for SYSTEM and Administrators. Applied in isolated
   installer and host preflight and incorporated into rollback guard.
   **Evidence:** source inspection/static tests, not full Windows DACL tests.

4. **HOLD — stale binary pin and real operator authority.** All scripts still
   bind the prior Wave11 EXE hash `ddd462...`. New async C# source supersedes
   that release candidate, but no new compiled hash is supplied here. The
   install effect branch remains unconditionally unreachable through
   `throw $ReleaseHold` before any protected write or SCM registration.
   Source-file pinning is not an independent anti-rollback STOP witness.

## Other risks, not promoted to findings without live evidence

- `New-Service` is configured `Disabled` and the script checks post-registration
  `ImagePath`, `ObjectName=LocalSystem`, `Start=4`. This is intended behavior;
  it is not an observed SCM service registration. The script does not separately
  inspect service `Type`, runtime pipe readiness, actual operator identity,
  endpoint concurrency, or service security descriptor.
- The source executable is under `D:\VERA\experiments`, not the protected
  custody root. Its SHA pin protects bytes against an accidental substitution
  within the old release but does not establish currentness or trusted build
  provenance. The hardcoded path is an internal path disclosure only; no
  credential or recipient address was found in the three scripts.
- The custodian can be administered by SYSTEM/Administrators, and an elevated
  AI-reachable Admin path would still compromise independent operator STOP.
  Real effective access, token separation, SCM security, journal restoration,
  and monotonic STOP must be independently witnessed. ACL text is insufficient.
- Resident probe uses PowerShell 5.1 `Add-Type`, whose compilation may use
  temporary local files; do not interpret `read-only` as an OS-wide guarantee
  of zero scratch/cache effects. It makes no intended protected-state changes.
- No Windows PowerShell 5.1 parser or Windows host available in this worker;
  actual syntax, ACL owner translations, Win32 errno behavior, and service
  semantics remain unverified.

## Checks

Executed:

```text
python -m unittest discover -s obsession_wave12_installer_review -p 'test_*.py' -v
Ran 5 tests in 0.000s — OK
```

These are **STATIC TEST** evidence only; not Windows syntax/runtime, resident
token, SCM, ACL, or independent formal verification. No release PASS asserted.

## Return package

- `NativeStop.Install.ps1`: tightened exact DACL checker; original hard HOLD
  before all effectful operations retained.
- `NativeStop.Preflight.ps1`: Host-only metadata verification, Resident-only
  effective denial requests, exact ACE checker, unbound-SID warning.
- `NativeStop.Rollback.ps1`: guard on custody ACL/owner, pin file, SID; preserve
  all journals/output; no stop action.
- `test_isolated_source_contract.py`: five source-contract checks.

**Next dependency:** build/qualify the async-lifetime C# candidate, then
regenerate a new exact three-script pin and stage path in an independently
reviewed successor package while retaining the release hold. Do not run the
installer through a blocked SCM/ACL connector or use alternative commands to
work around its restrictions.
