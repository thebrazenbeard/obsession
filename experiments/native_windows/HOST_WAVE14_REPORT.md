# Obsession STOP custodian — Wave 14 source fixes and isolated evidence

Review subject at start: draft PR #9, head `9b8c4e32688c185ce08061034ec26f2bf989658c`;
base PR #8 `a195d6ea204c728e759c487210926408233ec20f`.
This report does not assert a release, installation, credential, recipient-contact, or
real protected-output event. `D:\VERA` is the authoritative development root.
`C:\Program Files\VERA\ObsessionStopCustodian` is an approved *candidate target*,
not authority to install there.

## Defects reproduced and corrected in source

1. **Strict protected ACLs.** The C# custody check previously rejected only broad
   principals and allowed an explicit FullControl ACE for an arbitrary specific
   user despite a trusted owner. The new guard requires a protected DACL of exactly
   SYSTEM and Builtin Administrators FullControl, no inherited/deny/extra ACEs,
   on protected custody paths, executable, and durable journals. Source-level
   regression tests pass; cross-token effective ACLs remain unverified.
2. **Partially started worker.** If the second native pipe worker fails to start,
   the first worker's pending APM operation must settle before its pipe handle
   is disposed. The C# startup catch now joins started workers and fails fast
   if they do not drain; it only directly disposes never-started handles.
3. **Rollback independent authority.** The source-only rollback script formerly
   allowed `-Execute` to reach an SCM deletion after local administrator checks.
   It now unconditionally raises `HOLD_ROLLBACK_REQUIRES_INDEPENDENT_STOP_AUTHORITY`
   before any deletion, even if its preflight otherwise passes.
4. **Python overlapped cancellation.** An unsignaled CancelIoEx completion
   formerly caused unbounded GetOverlappedResult(True) blocking. The client now
   caps the cancellation-settle wait at 1000 ms; uncertain I/O retains its
   handle and OVERLAPPED buffer in process-owned quarantine and poisons later
   publication attempts. Only a settled event is nonblocking-drained.
5. **Python attestation deadline.** The native client's deadline previously
   began only *after* named-pipe connection and SCM attestation. It now starts
   before connection, with post-attestation expiry denial.

## Evidence distinct from implementation

- **REAL_WINDOWS_STAGING_TEST (Lappy; process-local synthetic only):** The
  combined strict-ACL/startup code compiled using 64-bit .NET Framework
  `csc.exe /warnaserror+` into a nonstaging candidate. Binary SHA-256
  `dfc988f196c7b8f3a2050b9348a3ccabeed4673c856e0d28b1418c14649bb8e2`
  (source *includes extra stage-only diagnostics*; production behavior matched
  the clean source changes). The isolated byte-pipe test returned
  `STAGING_PIPE_RESULT=POSITIVE_PASS_COLLISION_FAIL_CLOSED_PASS`,
  including 100 abrupt disconnect/recovery attempts, 40 idle restarts,
  synthetic GRANT→PUBLISH→STOP denial, first-instance collision
  `WIN32_231`, and exact required marker checks. Isolated receipt:
  `C:\Users\patri\AppData\Local\Temp\VeraObsessionPipeStage-68e5573e3ec44befaf2311dcbce7b0f6\receipt.txt`.
- **REAL_WINDOWS_STAGING_TEST (fault injection):** A stage-only conditional
  forced failure after the operator worker started and before the publisher
  worker started, and confirmed no live operator thread plus reacquisition of
  both reserved pipe names. Marker
  `PIPE_TEST startup_failure_drain=PASS;PENDING_CONNECT_END_REQUIRED=true;STAGING_ONLY=true`,
  exit 0. Stage-only source SHA-256
  `e4c6ba97ea74b7b1629668dca3ec3602fd7c47841547ac560211322c0ea6f925`;
  test binary SHA-256
  `aefb3b798482682016a2baf2ddeaff7c624b66a3d3dbf346c5e2d1f5d282346d`.
- **WINDOWS_POWERSHELL_PARSE:** Rollback script staged at
  `D:\VERA\experiments\obsession-native-stop-custodian-stage-20261109-f5aeb781\wave14-review-scripts\NativeStop.Rollback.Wave14.HOLD.ps1`;
  parsed with zero errors. No `-Execute` invocation or SCM change.
- **PYTHON_MOCK_TEST:** Patched native client **25/25 PASS**; existing
  Wave 12 runtime/source suite **28/28 PASS** separately; new combined
  C#/rollback source-contract **3/3 PASS**. Mock counts are not independent
  real Windows cross-token qualifications.
- **SOURCE_REVIEW:** Changes were compared with the exact PR #9 head source,
  not a remembered earlier branch. The C# integrated clean source SHA-256
  `aa4804720a58cac5d56dc2b9258a6045f96bcdd2e12872d14b9141e3ca870c5a`.
  Python client SHA-256
  `dfc2ca3145d408e21fc94862aa6a2c8588fb816c808f419e4263180be40662a1`;
  rollback source SHA-256
  `d4d0030fc57cf8dbd00997a37e92245b8cc1edbaefa8fc588abbce8355dd5c92`.

## Hostile unresolved challenges

> A trusted owner plus source DACL checks cannot independently demonstrate
> effective Windows cross-token denial, hardlink/reparse behavior under
> privileged paths, or durable monotonic anti-rollback witnesses. The strict
> two-ACE contract may also reject an existing deployment's different ACL;
> this must be qualified without weakening the trust policy.

> Python SCM PID equality is not independently attested binary/token identity.
> CancelIoEx behavior has only mock regression, and synchronous SCM attestation
> calls can overrun the deadline before returning. Actual Windows service
> installation, two principal probes, and crash/power-loss recovery remain on HOLD.

> Draft PR #9 head `9b8c4e3` includes unrelated project assets and wide
> line-ending changes relative to its stack base. Do not equate its cumulative
> file list with the five source fixes or silently rewrite unrelated work.
> PR #3–6's recursive gate can publish directly and must not be wholesale
> cherry-picked over PR #9's protected STOP gate.

The normal Blotter tail via Lappy returned HTTP **401 Unauthorized**. No
credentials were extracted and no writer bypass/update was made. The source PR
conversation is the authorized durable coordination location until a valid
Blotter lane is available.

**Disposition:** `WINDOWS_STAGE_PASS / SOURCE_BUILD_PASS /
PYTHON_MOCK_PASS / STRICT_ACL_REAL_TOKEN_HOLD / SERVICE_INSTALL_HOLD /
INDEPENDENT_ROLLBACK_HOLD / CONTACT_DISABLED`.
