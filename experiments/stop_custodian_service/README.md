# Obsession protected STOP custodian — source-only candidate

**Not installed or production-qualified. No contact transport.** This is an
experimental `LocalSystem`-intended IPC service candidate for the synthetic
local handoff path in Obsession PR #7. It replaces unsafe resident-owned final
`os.link` publication with a *custodian-owned* atomic file write in a separately
protected output directory.

## Runtime and files

- Single Python 3.12 stdlib script: `stop_custodian.py`.
- Windows IPC: `multiprocessing.connection.Listener` `AF_PIPE`, exact resident
  endpoint `\\.\pipe\VERA_Obsession_Stop_V1`; Linux test variant `AF_UNIX`.
- Wire: `send_bytes` / `recv_bytes` with bounded 16 KiB UTF-8 JSON objects and
  duplicate-key/nonfinite rejection. **Never use pickle `recv()` or `send()`.**
- Transport-level authkey: independent 32-byte secret used by both resident and
  service; it is a *consumer* credential, not an operator credential.
- Operator-only HMAC key: **different** 32-byte secret, accessible only to
  host-authorized principal, never to resident/model. Used for REGISTER,
  GRANT, REVOKE. Each request HMACs its exact canonical JSON fields excluding
  `mac`. Grant signatures use domain `OBSESSION_LOCAL_PUBLISH_GRANT_V1\0`.
- Service config contains exactly `root,address,family,transport_key_hex,
  operator_key_hex`; both keys are 64 lowercase hex chars. Keep service config
  SYSTEM-only and provide a *separate* client config without operator key.
- Protected root must preexist and pass independent ACL/ancestor integrity
  qualification. `initialize --root ROOT` only creates child `outbox`,
  `private`, and first journal; refuses an existing journal. `serve --config
  SYSTEM_ONLY_CONFIG` refuses a missing/corrupt journal.
- Durable `private/stop-journal.jsonl`: fsync'd append-only REGISTER/GRANT/REVOKE
  history with monotonic sequence, unique operator nonce, hash chain and strict
  transition validation. A resident SQLite rollback cannot erase this *if*
  host custody actually separates the files. Loss/corruption denies startup.
- `outbox/<artifact_id>.json`: immutable no-replace local synthetic handoff,
  written by custodian while serializing against REVOKE.

## Strict requests

All requests are a single JSON object per authenticated local connection.
`REGISTER {op,generation,nonce,mac}` (operator only) establishes one fresh
generation. A revoked generation is never re-registered. `REVOKE
{op,generation,nonce,mac}` (operator only) fsyncs tombstone before acknowledgement.

`GRANT {op,generation,artifact_id,source_digest,expires_at,nonce,mac}` is
operator-only. It issues a signed grant containing exact generation,
artifact_id (64 lowercase hex chars), source_digest (SHA-256 **of entire final
payload bytes**, not the nested proposal digest), local-only scope and an
expiry no more than one hour ahead of **server clock**.

`PUBLISH {op,generation,artifact_id,source_digest,payload_b64,now,grant,
grant_mac}` is consumer-facing and cannot change STOP. The protected server
checks the grant signature, generation, source digest, decoded payload length
of 1–4096 bytes, synthetic-only schema and nested `contact_authorized:false`,
`delivery_verified:false`, `execution_authorized:false`, then performs atomic
no-replace publication under the same process lock used by REVOKE. It replies
`{state:PUBLISHED|ALREADY_IDENTICAL,path,sha256,epoch,generation}`. No arbitrary
path, contact, phone number, network destination, or messaging operation exists.

## Test evidence

```bash
PYTHONPATH=obsession_wave7_custodian_service \
  python3 -B -m unittest discover \
  -s obsession_wave7_custodian_service/tests -v
```

Source core/security tests and an actual **separate-process raw bytes** test
run in scratch. AF_UNIX listener cannot bind in this hosted scratch sandbox
(`PermissionError: [Errno 1] Operation not permitted`); that explicit test is
opt-in only with `OBSESSION_ALLOW_REAL_IPC_TEST=1` on a socket-permitted host.
Windows AF_PIPE handshake and service installation have not run.

## Mandatory holds

1. Lappy `D:\VERA` and its `D:` ancestor currently have broad inherited
   write/Modify rights. A protected child ACL may still be bypassed via a
   writable parent. **No protected claim until effective DELETE_CHILD and
   replacement/reparse behavior are qualified**; alternate protected root may
   require Patrick's separate authorization.
2. The observed Python 3.12 interpreter on Lappy resides in a user-writable
   profile and is unsuitable for a privileged SYSTEM service without binary
   provenance and ACL verification. Do not elevate that interpreter.
3. Default Python AF_PIPE DACL and task/service principal need live hostile
   tests. Transport authkey and operator key must remain separate. Client-side
   `hold_active` from PR #7 alone is insufficient; the service must own the
   final write and the resident must not be able to write its protected outbox.
4. Hash chains are not external anti-rollback anchors. A host administrator
   able to replace the entire journal can defeat this source-only protection.
5. No host registration, production grant, real recipient contact, owner
   messaging, merge, or any model/prod activation occurred.

Disposition: `SOURCE_PROTO_PASS / IPC_HOST_TEST_PENDING / WINDOWS_CUSTODY_HOLD /
CONTACT_HOLD`.
