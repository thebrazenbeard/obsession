# Native Windows STOP custodian — source patch, not installed

**Disposition:** `SOURCE_BUILD_PASS / STAGING_SEMANTIC_TEST_PASS / HOST_CUSTODY_HOLD / CONTACT_DISABLED`.

Patrick explicitly authorized `C:\Program Files\VERA\ObsessionStopCustodian`
as the protected installation target on 2026-11-09. The project workspace
remains `D:\VERA`; `C:\VERA` is obsolete. No recipient or network transport
is provided by this candidate.

## Evidence boundary

- The **previous PR #9 source** was compiled on Lappy with a Microsoft-signed
  .NET Framework compiler and `/warnaserror+`; an isolated in-process staging
  test exercised GRANT → PUBLISH → STOP → denied publication after reload.
- **This patched source** corrects typed resident proposal digests, validates
  the nested synthetic proposal fields, enforces a whole-frame pipe deadline,
  and distinguishes harmless ancestor `AppendData` from rights that replace
  or modify protected children. Fresh staging builds on Lappy completed with
  `/warnaserror+`, exit 0. The isolated in-process staging semantic test exited
  0 with GRANTED/PUBLISHED/STOPPED/HOLD-after-STOP/HOLD-after-reload and
  malformed/nested payload denials. This is **not** live IPC, ACL or SCM
  qualification.
- Native Python adapter tests in a separate work area: **14/14 pass**,
  including a fixture based on the actual resident handoff method. They are
  simulated transport tests, not a Windows named-pipe execution.

## Protected release contract

An authorized installer must provision a new SYSTEM/Administrators-owned,
restricted executable/state directory, output directory, `binary.sha256`,
`resident.sid`, `stops.log`, and `grants.log`. The resident must run under a
genuinely nonadministrator dedicated SID, with no write/delete/owner-retake
authority over the protected path or access to the operator pipe. The service
name is `VeraObsessionStopCustodian`, SCM identity `LocalSystem`, and image path
is the exact protected executable. Do **not** transplant synthetic staging
journals or SIDs into production custody.

The compiler command for a separately staged, noninstalled build is:

```powershell
& 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe' /nologo /warnaserror+ /target:exe /out:ObsessionStopCustodian.exe /reference:System.ServiceProcess.dll /reference:System.Core.dll /reference:System.Web.Extensions.dll ObsessionStopCustodian.cs
```

Verified patched staging build receipts, dated 2026-11-09:

- Source SHA-256: `f5aeb7819a24441d63449c7c49dc3fbad91e10a3530a096fcf4997f9d7b0d58d`.
- Production candidate EXE SHA-256: `1840b154f84561f4da89ef8a6f6254a6e4a2015f819e6275e4481f172b3a877a`.
- `STAGING_SELFTEST` EXE SHA-256: `9e6bc959f473dff8378278a14ac400736677ec356c5ac3e1434acf0de35891b7`.
- Isolated staging directory:
  `D:\VERA\experiments\obsession-native-stop-custodian-stage-20261109-f5aeb781`.

The staging test also returned `HOLD|NOT_SYNTHETIC_HANDOFF` for raw
proposal-digest, unsafe nested proposal, duplicate top-level or nested JSON
keys, and escaped object-key variants. The underlying .NET JSON deserializer
was observed collapsing duplicate keys in the absence of the strict scanner;
the new scanner is therefore a material safety boundary.

These hashes identify an **uninstalled staging build** and must be independently
read back before any authorized protected installation. Old PR #9 build hashes
must not be reused for this patch.

## Outstanding release blockers

1. Neither WorkBridge Commander nor Executor Lappy Dedicated currently allows
   service-registration commands (`sc`, `reg`, `net`, `runas`, `takeown` are in
   their blocked-command configurations). Do not circumvent those restrictions
   with equivalent PowerShell, WMI, or .NET service-management APIs; use a
   separately sanctioned host-management route.
2. The observed AI-accessible WorkBridge session is elevated administrator,
   while the prototype operator pipe admits Administrators. Without a narrower
   execution boundary, the AI route can undermine independent owner STOP.
3. Real distinct-token Windows named-pipe, ACL, direct-write denial,
   STOP/PUBLISH race, and service restart tests have not been completed.
4. A protected local journal cannot detect replacement by an older valid
   snapshot performed by a privileged administrator or offline actor without
   an independent monotonic witness. This remains an explicit residual risk.
5. A native SCM installer with guarded registration/start and conservative
   rollback has not been qualified. The earlier Python Scheduled Task installer
   is **not** a valid replacement.

See `HOST_TEST_PLAN.md`, `HOST_ADVERSARIAL_QUALIFICATION.md`, and
`PROTOCOL.md` for the host qualification contract. The companion
`host_tests/Test-StopCustodianHost.ps1` is **not executed or authorized to
perform effects merely by being in this repository**; its default preflight
is read-only, and its effect modes require separate explicit test identities
and opt-in.

No production installation, service activation, merge, or recipient contact
has occurred for this patched candidate.
