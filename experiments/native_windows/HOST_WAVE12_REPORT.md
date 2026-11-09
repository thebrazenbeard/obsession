# Wave 12 native STOP-custodian qualification (source-only)

Evidence classes are deliberately separate. The staged application exercises
synthetic, local-only handoffs; it cannot authorize or contact a recipient.

## Verified on Lappy (Windows 10.0.26300, PowerShell 5.1)

- The staging source was SHA-256 checked after transferring to
  `D:\VERA\experiments\obsession-native-stop-custodian-stage-20261109-f5aeb781`.
- Microsoft Framework64 `csc.exe` compiled `/warnaserror+` with
  `STAGING_SELFTEST,STAGING_PIPE_TEST` and ran the unprivileged named-pipe stage.
- The final staging run exited `0`: synthetic GRANT/PUBLISH/STOP and replay,
  malformed frames, whole-frame timeout and subsequent recovery, 100 abruptly
  disconnected clients and subsequent recovery, startup collision denial
  (`WIN32_231`), and 40 idle start/stop cycles.
- Receipt: `STAGING_PIPE_RESULT=POSITIVE_PASS_COLLISION_FAIL_CLOSED_PASS`,
  `REQUIRED_POSITIVE_MARKERS_VERIFIED=true`, `POSITIVE_EXIT=0`,
  `COLLISION_EXIT=0`, `IDLE_STOP_EXIT=0`.
- The tested staging source included additional `STAGING_PIPE_TEST` diagnostics;
  the source-of-record candidate omits those diagnostics but retains the same
  production paths and corrected native pipe state transitions. Its production
  semantics are not claimed independently qualified merely by this equivalence.
- A non-staging, source-only production candidate compiled `/warnaserror+` to
  binary SHA-256 `4196d5402210fe007ce47e4e12841cdf655bc79f698e52bfbb3b2a6e725dd623`.
  It was **not installed or started as a service**.

## Root cause and repair

The previous implementation kept the first pipe instance open to prevent a
name-squatting gap, but only called `Disconnect()` if `IsConnected` was true.
An abruptly disconnected client leaves `.NET`'s pipe state `Broken` with
`IsConnected=false`. The next `BeginWaitForConnection` then raises
`IOException: Pipe is broken`, observed in the Windows stage. The repaired
server calls `Disconnect()` after each completed connection even in `Broken`
state; a failed transition is fatal and does not restore publication authority.

Additional source corrections: preserve pending APM I/O lifetime through
CancelIoEx/End, drain pending BeginWaitForConnection on stop, and use a
bounded response-digest ACK before server disconnect so a successful effect
does not immediately lose its receipt.

## Python/source evidence

The integrated resident PUBLISH client and mocks passed 28/28 Python tests
and `compileall`. These verify fail-closed provider selection, strict synthetic
payloads, forged receipt rejection, exact 36-byte Win32 SCM status layout,
cancel-and-drain behavior, and response-bound ACK framing. They do not
establish live Windows SCM/ACL/pipe identity qualification.

## Explicit release HOLD

- Do not install/register the protected Windows service or alter SCM ACLs.
- Do not enable a resident, sender, recipient, phone, contact, or network path.
- Do not infer resident/operator account separation from a same-user staging
  test. Actual independent-token ACL, SCM PID attestation, authoritative
  custody journal/anti-rollback witness, and crash/restart qualification remain.
- Installer sources are review candidates only and retain the unconditional
  release hold. No service/admin-capability bypass is permitted.
- The open draft PR is not merge, install, deploy, or contact authority.

## Blotter

The normal latest-20 endpoint on Lappy returned HTTP `401 Unauthorized`.
No credential extraction, alternate privileged route, or unauthorized write
was attempted. Blotter readback/update remains blocked.
