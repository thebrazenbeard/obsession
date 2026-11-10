# Obsession STOP custodian — Wave 15 security, recovery, and transport

Initial review subject: [Obsession Draft PR #9](https://github.com/thebrazenbeard/obsession/pull/9)
head `c42c8afc39a1a98bc4b4f3b4e5889475764d8ccd`, base PR #8
`a195d6ea204c728e759c487210926408233ec20f`.
This document is not a release, installation, permission change, real provider
activation, or contact authority. The authoritative development root is
`D:\VERA`. The approved *candidate* Windows service path remains
`C:\Program Files\VERA\ObsessionStopCustodian`.

## Reproduced source defects

1. **Incomplete journal replay.** `File.ReadAllLines` previously accepted
   a final syntactically valid `GRANT` or `STOP` record without its LF.
   After a crash, an incompletely appended record could be admitted at
   restart. The C# loader now requires complete LF-terminated ASCII records
   and refuses CRLF, control bytes, blank extra rows, and unterminated tails.
   Both STOP and GRANT replay paths use the same reader.
2. **Custody parent structural ACE bypass.** C# and installer/preflight/
   rollback scripts inspected broad identities but missed an arbitrary
   *specific* untrusted SID with effective `DELETE_CHILD` or other structural
   rights on `C:\Program Files\VERA`. New fail-closed immediate-parent
   checks examine every allow ACE; SYSTEM and Administrators remain the
   only trusted effective structural principals, while `InheritOnly` ACEs
   do not confer parent access. Ordinary `C:\` and `C:\Program Files`
   ancestry retains its prior less-strict policy.

These changes preserve the existing unconditional install and rollback
release holds and the protected resident-only PUBLISH / operator STOP split.
No `gate.py` direct-publish route was imported.

## Execution and evidence classes

- **SOURCE_TEST:** Four C# journal/parent source-contract regressions and
  nine installer/rollback source regressions passed independently on the
  current isolated candidates. New source tests reproduced the defects
  before repair. Neither suite proves effective Windows permissions.
- **REAL_WINDOWS_STAGING_TEST, source-only:** Lappy compiled the combined
  production-semantics C# using Framework64 `csc.exe /warnaserror+`,
  exit 0; nonstaging candidate binary SHA-256
  `191db3aa800518e8cd411e348d1cf10023cdf6b1ce599b8337ed23a67344c646`.
  The host source included prior staging-only pipe diagnostics; staged
  source SHA-256
  `a7787024e3722fa7c6a81cf2ce16c53dbda2166f19acc5b4aa8fe791d0e5ecba`.
  Isolated pipe suite returned
  `STAGING_PIPE_RESULT=POSITIVE_PASS_COLLISION_FAIL_CLOSED_PASS`:
  100 abrupt disconnect/recovery attempts, 40 idle start/stop cycles,
  1st-instance collision `WIN32_231`, synthetic GRANT→PUBLISH→STOP and
  post-STOP denial, timeout and malformed-frame rejection.
  Receipt: `C:\Users\patri\AppData\Local\Temp\VeraObsessionPipeStage-76ea5dc7987740e78bedf52218a4e49f\receipt.txt`.
- **REAL_WINDOWS_IN_MEMORY_TEST:** Temporary .NET library reflection
  confirmed empty/terminated synthetic STOP+GRANT records allowed,
  incomplete/blank/CRLF/non-ASCII records denied; trusted parent and
  read-only untrusted ACE allowed, specific DELETE_CHILD and effective
  TrustedInstaller FullControl denied, InheritOnly ACE allowed.
  Exact marker:
  `WAVE15_STAGE_RESULT=PASS;SYNTHETIC_ONLY=true;REAL_TOKEN_EFFECTIVE_ACL=UNVERIFIED`;
  process exit 0. The harness was fixed to unwrap PowerShell reflection
  arguments before this pass.
- **REAL_WINDOWS_IN_MEMORY_TEST:** The source-only installer parent checker,
  evaluated against synthetic DirectorySecurity objects and a mocked
  `Get-Acl`, returned
  `PARENT_ACL_STAGE=PASS;IN_MEMORY_ONLY=true;REAL_PARENT_EFFECTIVE_ACL=HOLD`,
  process exit 0. Specific FullControl/CreateDirectories and effective
  TrustedInstaller FullControl were rejected; Users read and CREATOR OWNER
  inheritance-only were allowed.
- **REAL_WINDOWS_SYNTHETIC_CLIENT_TEST:** Exact unchanged PR #9 Python
  transport (`dfc2ca3145d408e21fc94862aa6a2c8588fb816c808f419e4263180be40662a1`)
  ran with Python 3.14.5 on Lappy. Ten random local byte-pipe pending reads
  timed out around 208 ms and cancelled with no hang:
  `WIN32_CANCEL_CASES=10;FAILURES=0`, process exit 0. SCM attestation
  was mocked *only for transport exercise*. Separate real read-only SCM
  attestation refused the synthetic peer (Windows error 1060, STOP service
  absent), exit 0. This is not a cross-token service identity test.
- **POWERSHELL_PARSE:** Updated rollback script parsed with zero errors
  on Lappy. Concurrent parse probes for install/preflight encountered
  host `spawn EPERM`, so those two parsers remain unverified; no
  permission escalation or alternate privileged route was attempted.

## Exact live-host read-only qualification boundary

`C:\Program Files\VERA\ObsessionStopCustodian` **does not exist**.
`C:\Program Files\VERA` exists with Administrators ownership, inherited
ACLs, and **effective** TrustedInstaller FullControl on the parent. A separate
TrustedInstaller ACE and CREATOR OWNER ACE are inheritance-only. The stricter
parent guard will intentionally **HOLD** this current host layout: treating
TrustedInstaller as a third accepted structural principal would be a
material trust-policy change not authorized by these source patches.
No ACL or Windows service state was changed.

## Hostile review

> A protected child DACL cannot alone defend its directory name when its
> immediate parent allows `FILE_DELETE_CHILD` to another principal.
> Source checks now close the obvious allowance, but actual Win32
> rename/delete denial by separate accounts is still unverified.

> Exact SCM process-PID matching is not binary/token trust. A synthetic
> local pipe rejection when the service is absent does not establish
> authenticated service identity when it is installed and running. The
> external monotonic anti-rollback witness and crash/power-loss recovery
> remain unqualified.

> PR #3–6's recursive gate uses direct `os.link/os.rename` publication
> and must not replace PR #9's protected custodian gate. Existing unrelated
> PR #9 line-ending and asset changes must not be silently removed.

**Disposition:** `WINDOWS_STAGING_PASS / IN_MEMORY_NEGATIVE_TESTS_PASS /
REAL_WINDOWS_SYNTHETIC_CANCEL_PASS / REAL_TOKEN_HOLD /
PROTECTED_INSTALL_HOLD / TRUSTEDINSTALLER_POLICY_HOLD /
CONTACT_DISABLED`.
