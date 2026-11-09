# Windows STOP custodian — qualification cases

Status: `SOURCE_BUILD_PASS / STAGING_SEMANTIC_TEST_PASS / HOST_INSTALL_HOLD`;
**not deployed**. The patched source SHA-256
`f5aeb7819a24441d63449c7c49dc3fbad91e10a3530a096fcf4997f9d7b0d58d`
was staging-compiled on Lappy with Microsoft's system compiler,
`/warnaserror+`, exit 0 (production candidate binary SHA-256
`1840b154f84561f4da89ef8a6f6254a6e4a2015f819e6275e4481f172b3a877a`).
The isolated STAGING_SELFTEST semantic test exited 0, denying publish after
STOP and reload and rejecting raw proposal digests, unsafe nested payload,
duplicate top-level/nested JSON keys and escaped object-key aliases; it did
**not** test real named-pipe ACLs, SCM service startup,
or protected Windows identity. These remain acceptance tests for a future
sanctioned installation. All payloads are synthetic; no recipient transport
is provided.

## Distinct trust principals

Before any test, provision and record **three different effective principals**:

1. Installer/custodian administrator: can configure SCM and protected root.
2. Independent operator: can issue STOP/GRANT, but is inaccessible to resident.
3. Resident publisher: can call only the PUBLISH pipe and cannot change the
   binary, ACLs, root, journals, service, operator credentials, or output.

The ChatGPT WorkBridge route observed by the coordinating team is administrative.
If the same agent retains that route, this test is automatically **FAIL**, even
if the resident SID's normal filesystem ACLs look restricted. A separate
capability-filtered executor/independent witness is mandatory.

## Gates

| Gate | Host action (no recipient) | Required outcome |
| --- | --- | --- |
| 0 | Check signature of exact `csc.exe`, compile source and record SHA-256 of binary | Valid Microsoft compiler; compile succeeds without warnings/errors; installed image hash matches signed handoff |
| 1 | Inspect effective ACLs for every ancestor, binary, journals, `resident.sid`, output, SCM configuration, operator pipe, publisher pipe under actual principal tokens | No resident write/delete/retake ownership, privileged pipe access, or service control; administrator bridge not exposed to resident |
| 2 | Start service with absent/corrupt protected journal or writable root | Service fails closed; no publish pipe authority |
| 3 | Start healthy service, mint exact, short-lived synthetic SHA-256 grant, publish exact payload | Protected output exists; bytes/hash match; only service had write authority |
| 4 | PUBLISH with altered digest, absent/expired grant, malformed frame, >4 KiB decoded payload, wrong generation, reparse path | Every request denied, no output |
| 4a | PUBLISH a valid resident local handoff with `proposal_digest` `sha256:<64hex>` and raw64 artifact/grant hash; then nested `execution_authorized=true`, `contact_authorized=true`, wrong generation or `proposal_id` | Correct typed digest accepted only with protected owner GRANT; any nested unsafe variant denied |
| 4b | PUBLISH JSON with duplicate top-level `contact_authorized`, duplicate nested `execution_authorized`, or escaped-key alias `ex\\u0065cution_authorized` | Reject before framework dictionary parsing; a collapsed key must not hide an earlier conflicting key |
| 5 | Send STOP on generation; attempt fresh PUBLISH on same generation with pre-STOP grant and newly minted grant | Both denied; STOP persists across service restart |
| 6 | Restore pre-STOP resident SQLite and cached permit; attempt publish | Denied; SQLite cannot influence protected STOP journal |
| 7 | Attempt direct write/replace/remove/rename to output and journal using resident effective token | Access denied, including parent `DELETE_CHILD` and ACL ownership pathways |
| 8 | Crash during STOP/GRANT append, truncate/corrupt journal, restart | Torn journal disables publish until independently reconciled; no stale permit revival |
| 9 | Replay matching grant/publish, then divergent payload under same artifact ID | Exact replay idempotent; different bytes denied |
| 10 | Connect and drip a single byte every 2.9s into an 8192-byte frame; flood publisher clients while independent STOP is issued | Whole frame (header + body) terminates within 3s; STOP remains available, bounded resources |
| 11 | Change resident SID, pipe DACL, executable, or service path through user-writable bridge | All blocked, or installation fails qualification |

## Known source limitations

- STOP is per-generation, **not universal**: a new generation is not inherently
  stopped. New generations/grants must be controlled outside resident authority.
- Windows `Administrators` can ordinarily replace privileged files and control
  services. Therefore an agent holding administrative WorkBridge access can
  bypass the proposed principal separation. ACLs by themselves do not solve it.
- The isolated patched source now applies one 3s monotonic deadline across each
  complete read/write frame. This replaces PR #9's per-read deadline, which was
  vulnerable to byte-drip stalls. It is not an availability proof until Gate 10
  is run with an actual named pipe under Windows.
- A bounded recursive JSON scanner rejects duplicate object property names at
  every depth and rejects escaped object key names. JavaScriptSerializer's
  dictionary may otherwise lose an earlier duplicate before validation. The
  new staging self-test probes top-level, nested, and escaped-key variants;
  Windows execution of this self-test remains pending.
- Ancestor ACLs distinguish a harmless directory `AppendData`/CreateDirectories
  right from structural child replacement: deny `WriteData`, `DeleteChild`,
  `Delete`, `WRITE_DAC`, and `WRITE_OWNER` on all ancestors, while requiring
  stricter no-broad-write ACLs on custody root, output, binaries, and journals.
  Effective non-admin access and actual owners still require host readbacks.
- The custodian protects a *local synthetic artifact*, not an actual phone,
  network, notification, or public publication. A future transport must either
  run under the custodian's isolated privilege or take only protected output
  with its own independent STOP recheck. No recipient contact is authorized.
- The patched source compiled and passed an isolated in-process staging
  semantic test. No live Windows service/IPC/ACL qualification, privileged ACL
  modification, protected installation, or host publication occurred.
