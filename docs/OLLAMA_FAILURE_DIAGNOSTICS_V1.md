# Ollama failure diagnostics V1 — source-only candidate

The November 6 Lappy trial of the stacked recursive qualifier reached the
authenticated broker but its first `qwen3.5:0.8b` inference returned HTTP 502.
The captured generic 502 does **not** establish whether Ollama timed out, a
model returned no final content, the response envelope was invalid, or the
model was unavailable. This change does not replay or explain that trial.

## Bounded experiment interface

The existing `INITIATIVE_BACKEND_V1` config remains valid. Only an explicitly
specified new optional boolean enables the Qwen3.5 0.8B Ollama setting:

```json
"qwen35_08b_think_false": true
```

That config is valid only when `model` is **exactly** `qwen3.5:0.8b`.
It adds top-level `"think": false` to the `/api/chat` JSON request. Other
models, including Qwen2.5 and Qwen3.5 4B, are unchanged. Omission means no
thinking override. The model, seed `20261106`, temperature `0`, context
budget, and token cap are otherwise unchanged.

The broker's existing config identity includes this flag. Changing it against
an existing broker-state database fails closed; any authorized later trial
must use a newly isolated bounded broker state and explicitly configured
endpoint, not mutate/restart a production service.

## Failure evidence and privacy

For a post-admission Ollama failure, the broker returns a **signed** HTTP 502
with a strict `OLLAMA_FAILURE_DIAGNOSTIC_V1` object containing only:

| Field | Meaning |
| --- | --- |
| `category` | one of `transport`, `http_status`, `invalid_json`, `invalid_envelope`, `unfinished_or_tools`, `invalid_text` |
| `elapsed_ms` | capped local elapsed time measured via monotonic clock |
| `http_status` | Ollama HTTP status or `null` for transport failures |
| `done_reason` | `stop`, `length`, `other`, or `missing` (never an arbitrary model string) |
| `content_present` | whether nonempty final content existed |
| `thinking_present` | whether nonempty thinking existed |
| `response_bytes` | raw HTTP response length, not response contents |

The authenticated caller checks the nonce-bound HMAC before accepting this
diagnostic, validates exact keys/types/ranges, and reports safe metadata in a
retryable error. Unsigned, malformed, unauthorized, and unknown errors remain
generic. Prompts, generated text, thinking text, credentials, and raw
transport errors must never be placed in diagnostics or logs.

Failed inference still consumes an admission; the patch never retries a
request, increases a budget, sends a phone/Matrix message, trains weights,
or changes the running host. `think:false` is a candidate intervention, not
a verified fix.

## Executed source qualification

The source-level fixture suite exercises explicit/omitted thinking requests,
synthetic thinking-only truncated responses, HTTP error, malformed JSON,
transport failure, signed loopback 502, forged response, and privacy
restrictions. They contain no real Ollama/Qwen inference. A future opt-in host
trial must record exact config/model/hash, signed safe diagnostic, broker
admission count, wall time, and paired A/A and B/B vs A/B controller results
without repurposing or replaying expired admissions. Real-model efficacy and
long-term self-learning remain **UNVERIFIED**.
