# Recursive synthetic drive V2 — stacked research candidate

This adds to `obsession` Draft PR #2 (`66ba5712021d3e83fb0472aa1894ea4ae4d64f15`)
without replacing that foundation. The separate Work/Codex editor's uncommitted
`qualify_recursive.py` was **not accessible/recovered**. This is an independently
reconstructed candidate with separately executed tests.

## Causal runtime seam

`Runtime(..., recursive_drive=RecursiveDrive(enabled=True))` is explicit opt-in.
The normal `Runtime` path stays unchanged by default. After a host-admitted
synthetic event reaches a committed local proposal, or a host-owned durable
`DEFERRED_LOW_SALIENCE` receipt, `Runtime._collect` journals a unique
evidence-digest-bound controller event in its **same SQLite transaction**.
Repeated event collection and restart do not double-apply. Unverified model
text is never interpreted as a topic or capability.

The controller reconstructs state on each read from the admitted journal.
For each of two fixed topics, with topic-specific net signal
`s[t] = relevance[t] - counterevidence[t]`, the bounded recurrence is:

```
trace[t+1]    = clip(0.5 * trace[t] + s[t], -2, 2)
priority[t+1] = clip(0.5 * priority[t] + trace[t+1], -4, 4)
probability   = softmax(priority)
```

`GuardedModel.respond` passes the reconstructed bounded synthetic context to
the actual provider as an additional **user message**, so a prior admitted
signal can influence the *next inference input*. The same prompt template
is used with recurrence ON and OFF. Host diagnostics retain full generation,
history and arm identifiers; model-facing context excludes those confounders.
No instruction forces the model to repeat the selected topic. Model replies
remain ordinary text-only proposals with existing contact/execute denials.

## Verification and falsifiers

`tests/test_recursive.py` uses the actual `Runtime` and `GuardedModel` call
path with a synthetic recorder: cold restart, recurrence ON/OFF, negative
counterevidence flipping topic without an extra inference, no default drive,
idempotent replay and invalid/tampered source rejection.

`qualify_recursive.py --private-root NEW_PRIVATE_DIR` runs four synthetic
arms A1/A2 (ON) and B1/B2 (OFF) through that actual Runtime call path. It
requires identical A/A and B/B *provider-request* digests and an A/B request
difference; the canned synthetic replies are intentionally constant.

With `--backend-config PRIVATE_APPROVED_BROKER_CONFIG`, it instead makes
four finite calls through the **already running authenticated local broker**
and additionally requires stable A/A and B/B *response* hashes and a different
A/B response before reporting **byte-comparison PASS, semantics UNVERIFIED**.
This does not rate topic relevance, factual accuracy, or counterevidence uptake;
punctuation-only differences can satisfy the byte condition. The broker fixes
temperature and seed in its source, but the script does not independently
attest model weights, decoding determinism or hardware. A mere request-digest
PASS is not a semantic response-effect PASS. Real mode must run only in an approved idle
window; no broker, model, phone or messaging service is started here.

## Limits

- Synthetic/runtime source tests are **not real local-model testing**.
- A real reply difference would establish byte-level input-context sensitivity only,
  not autonomous motivation, subjective feeling, model weight changes,
  self-learning or the sought Vera identity.
- `qualify_semantics.py` can create an effectless, counterbalanced plan for
  synthetic held-out cases and selected-topic/trace/priority/probability
  ablations. No independent blind semantic review or model call is implied.
- SQLite hashes detect inconsistent local records but do not establish
  tamper-proof authority against a privileged whole-database rollback.
- Topics (`transit`, `irrigation`) are deliberately synthetic; this research
  must not be pointed at Patrick, other people, a contact list, or phone flows.
- No APK, Matrix, owner-outbox credential, notification, deployment, service,
  contact grant, merge or external effect is included.
