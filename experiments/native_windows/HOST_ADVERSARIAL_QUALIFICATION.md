# Independent Windows STOP custody qualification (2026-11-09)

**Subject:** `thebrazenbeard/obsession` Draft PR #9, native `.NET Framework` service,
exact source head `92b08211db1922fea508557712395c6386adf1b9`.

**This is a source-only test package.** No script in this package has been run
on Lappy, and no protected service was installed, restarted, stopped, registered,
or modified by this independent test lane. No recipient/API/network transport
is involved. The local output is only `LOCAL_SYNTHETIC_HANDOFF_ONLY`.

## Trust boundary prerequisite

1. `C:\Program Files\VERA\ObsessionStopCustodian` has protected code, state,
   binary SHA pin, and protected output; its every ancestor lacks resident
   write, owner-regrant, delete-child or reparse-replacement routes.
2. An independent trusted installer/administrator is **not reachable** through
   the resident/model/agent command channel. The observed elevated WorkBridge
   route currently conflicts with this requirement. NTFS DACLs cannot protect
   against an administrator who controls the installed service.
3. Three actual effective identities are logged, with `whoami /user /groups`:
   install admin, STOP/GRANT operator, and nonadmin resident SID. They are not
   inferred from folder names, token requests, or service account strings.
4. The service's operator pipe denies resident connection. Publisher pipe allows
   resident, but its payload is checked against a protected owner grant and
   monotonic per-generation STOP state inside one native process.
5. The native adapter in PR #9 is **not yet runtime-selected** by PR #8's
   resident gate. Only deploy after an exact binding and negative-path test.

## Safe sequence for qualified test operator

The companion `Test-StopCustodianHost.ps1` is `Preflight` **read-only by default**.
Effect modes require explicit `-ExecuteTestEffects`, a distinct generation
prefixed `TEST_`, a 64-lowercase-hex `ArtifactId`, and a real synthetic JSON
fixture whose contact/execution flags are false. Use a disposable isolated
resident database and newly initialized journals; never reuse a production
generation or grant. Run the effect modes manually in the order below:

| Phase | Effective identity | Mode | Required evidence |
| --- | --- | --- | --- |
| 0 | installer admin | `Preflight` | Service `LocalSystem`, exact binary hash, code/journal/output ACLs and owner, current SCM image path |
| 1 | nonadmin resident | `ResidentDeny` | Operator pipe connection denied; protected output direct `CreateNew` denied |
| 2 | independent operator | `OperatorGrant` | Exactly one short-lived protected grant for test generation/payload hash |
| 3 | nonadmin resident | `ResidentPublish` | Protected output newly created by service; file content equals signed payload bytes |
| 4 | independent operator | `OperatorStop` | STOP durability acknowledged for test generation |
| 5 | nonadmin resident | `ResidentAfterStop` | PUBLISH denied, even when resident restores pre-STOP SQLite+WAL fixture |
| 6 | independent installer | guarded service restart | Exact same per-generation STOP remains in protected journal after restart |
| 7 | nonadmin resident | `ResidentAfterStop` | PUBLISH still denied after service restart |

Do **not** run the service restart while other application owners hold work.
The exact test binary should be staged with source/hash readback, and installer
must save before/after SCM, owner, ACL, and service state receipts. This plan
does not authorize altering unrelated services or releasing contact capability.

## Additional adversarial cases (distinct test harness needed)

| Attack | Required result | Coverage now |
| --- | --- | --- |
| Resident restores pre-STOP SQLite/WAL and cached permit | Protected STOP cannot be erased | PR #8 synthetic, not live host |
| Resident renames an ancestor/output, deletes or resets ACL, owns file and regrants | OS access denied under real resident token | Unverified |
| Resident reaches operator pipe or SCM control APIs | OS access denied | Unverified |
| Administrative WorkBridge issues unauthorized GRANT/STOP | Bridge capability must be restricted first | **Known design conflict** |
| Two custodian instances attempt to run simultaneously | Singleton authority, second cannot operate | Unverified |
| Power failure mid STOP append then restart | Fail closed on torn journal | Source-only semantics |
| STOP races with PUBLISH | No publication begins after durable STOP ack | Source-only semantics |
| Client sends only frame header then stalls | Operator STOP service remains available within bounded deadline | Source timeout added, host unverified |
| Old valid protected journal snapshot replaces newer STOP journal | Replay detected by independent monotonic anchor | **Not implemented** |
| Different bytes reusing same artifact ID | No-replace/byte hash denial | Source-only semantics |
| Wrong pipe, wrong SID, corrupt payload, duplicate JSON keys, nested contact/execute true | Deny without output | **Server nested schema not fully qualified** |
| Installer/bridge can override protected service while resident is operational | Distinct privileged authority or explicit residual risk | **Unresolved** |

## Evidence classes and disposition

- `SOURCE_INSPECTION`: C# service uses operator/publisher pipes, per-generation
  STOP logs, SHA-bound owner grants, and protected file output. This is not an
  observed Windows boundary.
- `SYNTHETIC_TEST`: Prior stage reported compiler success and a direct
  GRANT→PUBLISH→STOP→deny→reload-deny semantic test. It is **not a real SCM,
  two-token, or named-pipe qualification**.
- `REAL_SYSTEM_PROBE`: Parent's separate host-preflight lane must report exact
  Lappy currentness. This lane performed no host probe or mutation.
- `FORMAL_VERIFY`: None. Source review and test design cannot upgrade status.
- `HUMAN_REVIEW`: No independent user acceptance of residual administrator or
  offline journal rollback risk has been recorded here.

**Disposition: `TEST_HARNESS_SOURCE_ONLY / NATIVE_HOST_QUALIFICATION_HOLD / CONTACT_DISABLED`.**

> Hostile challenge: a STOP journal that survives restart is not necessarily
> rollback-resistant. If someone can replace the entire protected directory with
> a prior valid snapshot, the service will see well-formed entries and may
> authorize publication again. A protected ACL stops an ordinary resident token,
> not a privileged administrator or offline disk rewrite. Claim exactly the
> narrower protection proven by distinct-token tests.
