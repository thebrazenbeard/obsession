# Wave 7 source-only STOP custodian — 2026-11-07

## Verdict

`SOURCE_PROTO_PASS / AF_PIPE_UNTESTED / OS_CUSTODY_HOLD / CONTACT_HOLD`.
This packet is **not** a production service or an installed control.
No Lappy service, ACL, credential, GitHub branch/PR, or recipient was modified.

## Source and integration contract

- `stop_custodian.py`: a separate process intended to run as a host-owned
  Windows AF_PIPE JSON custodian. Resident holds only the transport authkey;
  operator HMAC authorizes REGISTER, GRANT and REVOKE. Operator nonces are
  fsync-journaled, including GRANT, and cannot be replayed across restart.
- PUBLISH verifies an operator-signed grant bound to generation, artifact ID,
  exact SHA256 of **the complete final local-handoff payload**, local-only
  scope and server-clock expiration. Publication happens in custodian-owned
  `outbox`, serialized with STOP's durable journal append. STOP closes future
  publications; an already completed publication is not retrospectively
  removed.
- The resident adapter must use `source_digest = SHA256(final payload bytes)`;
  the nested `proposal_digest` names a different source claim. The resident
  cannot issue REGISTER, GRANT or REVOKE with only its transport key.
- Windows endpoint must match the resident's exact
  `\\.\pipe\VERA_Obsession_Stop_V1`.

## Executed tests

Command, from scratch workspace root:

```bash
env PYTHONPATH=obsession_wave7_custodian_service python3 -B \
  -m unittest discover -s obsession_wave7_custodian_service/tests -q
```

Observed `Ran 20 tests ... OK (skipped=1)`, exit 0. Covered strict JSON and
HMAC rejection, repeated GRANT rejection after restart, full-artifact digest
integrity, malformed/contact-enabled payload denial, idempotent protected
local output, STOP/PUBLISH ordering, durable revocation after restart,
tampered journal fail-closed and one separate-process raw-bytes protocol test.

The one skipped test is a **real AF_UNIX socket listener test** requiring
`OBSESSION_ALLOW_REAL_IPC_TEST=1`; hosted scratch denied socket bind with
`PermissionError: [Errno 1] Operation not permitted`. Windows AF_PIPE runtime,
authentication handshake, service startup and actual ACL enforcement have
**not** been exercised.

## Unresolved mandatory holds

1. `D:\VERA` and ancestors were observed with broad inherited Modify rights;
   protecting a child directory alone does not prove non-replaceable custody.
   Need an independently audited protected parent, child, journal, service
   executable, pipe and final output root. Parent DELETE_CHILD, symlink,
   junction/reparse and handle semantics require host qualification.
2. Observed Lappy Python 3.12 interpreter is user-profile-writable and unsafe
   for LocalSystem elevation. Service code, interpreter, runtime libraries,
   config and credential ownership must all be trusted. Consider a separately
   audited native service instead of elevating user-controlled Python.
3. Source assumes **exactly one** privileged server and no untrusted writes
   to its executable, journal or output. It does not supply an OS singleton,
   protected operator CLI, pipe DACL attestation or Windows installer.
4. A SHA256 journal hash chain detects local corruption/tampering but cannot
   detect a *complete privileged journal rollback* without an external trusted
   monotonic anchor. The supplied prototype is not such an anchor.
5. No external recipient, phone, real delivery, publication transport or
   automatic contact operation exists. STOP cannot be declared production
   protected until resident final-write bypass, full integration, Windows
   security and STOP race tests pass on the intended host.

## Exact source hashes

```text
9ebd1479ba61b8609d3a0d79bf6c9be042cf4999a04ee43b1ecc422f061cca61  stop_custodian.py
e326be62d449cc9834c204994c7803330c09453ac5dcb443ae48a9441cbb6fe5  tests/test_stop_custodian.py
202d1b5a08763716ea3ac4d1ce5a7383f46fdfac4031f932844f4416a49390e1  README.md
```

These hashes name the source-only files at the above verified test run, not a
deployed or independently trusted Windows binary.
