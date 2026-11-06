# Obsession Lab v1 — candidate evidence and boundaries

Status: isolated source/deterministic-test candidate. Not merged, installed, activated, trained, or used by any live Vera runtime.

## Implemented source
- `obsession_lab.simulator`: bounded in-memory baseline/pathological comparison using proxy salience, rumination candidates, counterevidence, and host-stop receipts.
- `obsession_lab.ollama_bridge`: optional fixed loopback Ollama request adapter plus an A/B `compare_once` harness; not a transformer attention hook.
- `obsession_lab.opportunity_bridge`: optional loopback Tattler observation correlation into declared local channel candidates; never sends a message or authenticates a recipient.

## Evidence
- Initial Windows Python 3.12 preservation commit: `py -3.12 -B -m unittest discover -s tests -v` -> 25 tests pass (synthetic/fake-client tests only). Follow-up hardening adds four tests; re-run before claiming a new Windows result.
- No live Ollama inference result was produced by this test suite; `FakeClient` generates the synthetic responses.
- `StepReceipt` and `InferenceReceipt` distinguish simulated behavior from measured model calls and keep `effects` empty.
- The optional runtime client could contact local Ollama at fixed `127.0.0.1:11434` only if a separately authorized caller invokes it.
- The optional Tattler fetcher targets fixed local `127.0.0.1:9147` and does not grant outbound communication.

## Caveats
- The repository's root README describes an aspirational `obsession_engine.ObsessionWrapper` quickstart, not implemented in this candidate.
- No Hugging Face attention-logit modification, persistent cross-session rumination, real model behavior qualification, or psychological/consciousness claim exists here.
- `snapshot`/`restore` are caller-owned structural simulation state, not trusted memory admission or runtime continuity. Restored snapshots are **terminal audit-only** and may not resume execution; no host-authenticated stop witness exists in this source.
- The pathological condition is a controlled research counterfactual; host stop always wins.
- The local Ollama client now rejects mismatched model names, incomplete/truncated responses, non-assistant replies, and tool-call-bearing responses. Its requested model name still does not cryptographically attest loaded weights.
- Host stop is checked before a model call; **mid-request cancellation is not implemented** for the blocking local Ollama HTTP request (bounded by timeout). Do not qualify this as an interruptible runtime.
- Live local Ollama invocation is default-deny and needs an explicit caller-side opt-in; that flag is not permission for person-specific data or a runtime effect.
- No automatic conations, volition, agency, consent, communication, or protected effect authority is transferred.

## Next verification
Run owner-approved, same-prompt baseline/fixation comparisons against a specifically identified local model with measured receipts; record model/runtime, environment, controls, dissent, and observed failures.
Independent initial local QA holds a separate raw-response-validated A/B receipt (SHA-256 `9f9a9f88b469129290a844cb8f2e0c36dcb28f488d71d460f23e4f96e8af3b02`): both models showed 0->0 target mentions; the 1.5B control/fixation outputs were byte-identical, and the 4B fixation reply ended by length. Those observations do **not** validate an increased fixation effect and were made with a separate QA transport, not this unqualified candidate adapter.
Keep source PR as Draft until independent review and truthful README revision. No main merge, deployment, canonical-memory promotion, or communication effects from this candidate.
