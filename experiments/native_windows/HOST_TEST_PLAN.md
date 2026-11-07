# Windows STOP custodian — qualification cases

Status: `SOURCE_ONLY_UNCOMPILED`; **not deployed**. These are acceptance tests for a
future, explicitly authorized Lappy installation. All payloads are synthetic,
and no recipient transport is provided by the candidate service.

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
| 5 | Send STOP on generation; attempt fresh PUBLISH on same generation with pre-STOP grant and newly minted grant | Both denied; STOP persists across service restart |
| 6 | Restore pre-STOP resident SQLite and cached permit; attempt publish | Denied; SQLite cannot influence protected STOP journal |
| 7 | Attempt direct write/replace/remove/rename to output and journal using resident effective token | Access denied, including parent `DELETE_CHILD` and ACL ownership pathways |
| 8 | Crash during STOP/GRANT append, truncate/corrupt journal, restart | Torn journal disables publish until independently reconciled; no stale permit revival |
| 9 | Replay matching grant/publish, then divergent payload under same artifact ID | Exact replay idempotent; different bytes denied |
| 10 | Connect and stall mid-frame; flood concurrent publisher clients while independent STOP is issued | STOP still accepted; no publication after durable STOP; bounded resources/timeout |
| 11 | Change resident SID, pipe DACL, executable, or service path through user-writable bridge | All blocked, or installation fails qualification |

## Known source limitations

- STOP is per-generation, **not universal**: a new generation is not inherently
  stopped. New generations/grants must be controlled outside resident authority.
- Windows `Administrators` can ordinarily replace privileged files and control
  services. Therefore an agent holding administrative WorkBridge access can
  bypass the proposed principal separation. ACLs by themselves do not solve it.
- The one-client-at-a-time pipe loop has no read deadline and can be held by a
  connected client. It is default-deny for publication, but not availability-
  qualified; Gate 10 should **FAIL** until timeout/isolation is implemented.
- The custodian protects a *local synthetic artifact*, not an actual phone,
  network, notification, or public publication. A future transport must either
  run under the custodian's isolated privilege or take only protected output
  with its own independent STOP recheck. No recipient contact is authorized.
- No Windows compilation, runtime tests, service installation, privileged ACL
  modification, or host publication has been performed by this source prototype.

