# Native STOP custodian / existing resident gate adapter contract

Status: source-only; native production service not installed. Current service
source is **not** wire-compatible with the existing Python JSON custodian.
The adapter must deliberately target this versioned native protocol and must
not silently switch on transport failure.

## Local named pipes

| Pipe | Allowed principal | Commands |
| --- | --- | --- |
| `\\.\pipe\VeraObsessionStopOperatorV1` | LocalSystem + Administrators only (requires independent restricted bridge) | `STOP`, `GRANT` |
| `\\.\pipe\VeraObsessionStopPublishV1` | LocalSystem + Administrators + exact `resident.sid` | `PUBLISH` |

Each request/response is **one** UTF-8 string preceded by an unsigned 4-byte
big-endian length; 1..8192 bytes. No newline terminator on the pipe frame.
Service responds the same way. At most one active client per pipe in current
candidate; idle/partial clients are intended to time out in 3 seconds. 

### Operator

- `STOP|<generation>|V1` -> `STOPPED|<generation>`; persistent STOP applies
  only to that generation, including across service restart. STOP cannot be
  issued via resident publish pipe.
- `GRANT|<generation>|<artifact_id>|<sha256>|<expires_utc_ticks>|V1`
  -> `GRANTED|<artifact_id>` or `GRANT_EXISTS`. Owner must derive authorization
  independently; never grant merely because resident SQLite says permit.
- Generation ASCII pattern `[A-Za-z0-9_-]{8,96}`; artifact and SHA-256 are
  exactly 64 lowercase hex digits; expiry is .NET `DateTime.UtcNow.Ticks`
  in 100ns ticks after 0001-01-01 (not Unix seconds), no more than one hour ahead.

### Resident

- `PUBLISH|<generation>|<artifact_id>|<base64payload>|V1`
  -> `PUBLISHED|<artifact_id>` or `ALREADY_PRESENT|<artifact_id>`.
- Native service recomputes SHA-256 over raw decoded payload and compares it
  with the protected owner GRANT; payload must be 1..4096 bytes; STOP is checked
  inside same lock immediately before the protected output write.
- Allowed payload is the current resident gate `_handoff_payload` UTF-8 bytes:

```json
{"schema":"initiative.local-handoff.v1","scope":"LOCAL_SYNTHETIC_HANDOFF_ONLY","proposal_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","proposal":{"label":"synthetic"},"delivery_verified":false,"contact_authorized":false}
```

  Actual bytes include a trailing `\n`. Canonical resident serialization is
  `json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
  + '\n'`. Native code currently validates top-level fields, not full nested
  proposal schema or canonical ordering. The protected grant SHA-256, however,
  is over **exact bytes including newline**. The canonical schema is a
  source-only compatibility assumption until tested against real resident output.
- `artifact_id` is resident `proposal_id` with leading `sha256:` removed.
  Grant digest (`sha256`) is SHA-256 of the entire handoff payload and may be
  *different from* resident `proposal_digest`.
- Any non-success response (including `HOLD|...`) is a **hard refusal**. No
  local-file/SQLite fallback and no direct write to custodian output permitted.

## Persistent files (protected-install target only)

- `C:\Program Files\VERA\ObsessionStopCustodian\resident.sid`
- `...\stops.log`, `...\grants.log`, `...\binary.sha256`
- `...\ObsessionStopCustodian.exe`, `...\output\<artifact_id>.json`

All precreated by an independent installer, bound to an isolated Windows
resident identity and with tested effective ACLs. The service verifies SCM
image path, LocalSystem account, protected binary hash, broad parent ACLs,
and journaling before exposing its pipes. This is not a substitute for
restricting the agent-accessible elevated WorkBridge route.

Current disposition: `STAGING_SEMANTIC_TEST_PASS / SERVICE_NOT_ACTIVATED /
HOST_AUTHORITY_HOLD / CONTACT_DISABLED`.
