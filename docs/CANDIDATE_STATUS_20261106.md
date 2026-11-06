# Obsession Lab v1 — candidate evidence and boundaries

Status: isolated source/deterministic-test candidate. Not merged, installed, activated, trained, or used by any live Vera runtime.

## Implemented source
- `obsession_lab.simulator`: bounded in-memory baseline/pathological comparison using proxy salience, rumination candidates, counterevidence, and host-stop receipts.
- `obsession_lab.ollama_bridge`: optional fixed loopback Ollama request adapter plus an A/B `compare_once` harness; not a transformer attention hook.
- `obsession_lab.opportunity_bridge`: optional loopback Tattler observation correlation into declared local channel candidates; never sends a message or authenticates a recipient.

## Evidence
- Windows Python 3.12 on Lappy: `py -3.12 -B -m unittest discover -s tests -v` -> **32/32 pass**, exit 0 (synthetic/fake-client/unit tests only, including three fixed-loopback transport regression tests). Initially preserved 25 tests; later hardening and network isolation increased the suite to 32.
- No live Ollama inference result was produced by this test suite; `FakeClient` generates the synthetic responses.
- `StepReceipt` and `InferenceReceipt` distinguish simulated behavior from measured model calls and keep `effects` empty.
- The optional client contacts local Ollama only at fixed `127.0.0.1:11434` if a separately authorized caller invokes it. Its HTTP transport disables ambient proxies and rejects redirects, guarding against off-loopback requests.
- The optional Tattler fetcher targets fixed local `127.0.0.1:9147` and does not grant outbound communication. Both adapters allowlist endpoint/method pairs and reject HTTP redirects. No actual Tattler service availability or authenticated messaging was verified by these tests.

## Caveats
- The root README has been updated to describe the implemented simulator and optional adapters; proposed transformer-attention/rumination mechanisms remain unimplemented.
- No Hugging Face attention-logit modification, persistent cross-session rumination, real model behavior qualification, or psychological/consciousness claim exists here.
- `snapshot`/`restore` are caller-owned structural simulation state, not trusted memory admission or runtime continuity. Restored snapshots are **terminal audit-only** and may not resume execution; no host-authenticated stop witness exists in this source.
- The pathological condition is a controlled research counterfactual; host stop always wins.
- The local Ollama client now rejects mismatched model names, incomplete/truncated responses, non-assistant replies, and tool-call-bearing responses. Its requested model name still does not cryptographically attest loaded weights.
- Host stop is checked before a model call; **mid-request cancellation is not implemented** for the blocking local Ollama HTTP request (bounded by timeout). Do not qualify this as an interruptible runtime.
- Live local Ollama invocation is default-deny and needs an explicit caller-side opt-in; that flag is not permission for person-specific data or a runtime effect.
- No automatic conations, volition, agency, consent, communication, or protected effect authority is transferred.

## Next verification
Independent initial local QA holds a separate raw-response-validated A/B receipt (SHA-256 `9f9a9f88b469129290a844cb8f2e0c36dcb28f488d71d460f23e4f96e8af3b02`): both models showed 0->0 exact target mentions; the 1.5B control/fixation outputs were byte-identical, and the 4B fixation reply ended by length. This did **not** validate increased fixation.

A second independent Lappy **real-model QA** (separate harness, not this adapter) generated 16 complete untruncated responses with 0 errors across `qwen3:4b-instruct` (model digest `0edcdef34593eac1aa2be9c7d06c432dcf81945adca5eca2f27662c18f168ba0`) and `qwen2.5-coder:1.5b-instruct-q8_0` (digest `00f372390c1dac8c6d0cca549d683475d5854c0f0d77d5f5368e0ffe4724fe8b`) at temperature 0.2, top_p 0.9, num_predict 128, num_ctx 2048; seeds 20261106/20261107, order balanced, same user tasks (ocean tides and sourdough), system condition baseline vs explicit `railway scheduling` lens. The 4B model's two conditioned responses per task contained a combined nine related railway lexemes for each task (baseline zero); the 1.5B model yielded zero related lexemes in both conditions. Across all 16 outputs, **zero exact target-phrase mentions**. Receipt: `D:\VERA\experiments\obsession-live-model-qa-20261106\OBSERVED_LOCAL_OLLAMA_REPLICATION_V2.json`, readback SHA-256 `74AA58F158A95B6ACFD8FF2DCC18B0F37DC07F4994B995B3CDA63AFE9B1C148E`; script SHA-256 `7009bd2ad724647646085753a7e1ff115da417b98f1c7f347bead1d509ad41e7`. **This tests ordinary system-prompt effects; it does not qualify stateful rumination, model-internal attention changes, persistent behavior, or subjective feeling.**

Future work: reproduce using this adapter under isolated runtime conditions; measure host stop during a blocking request, caller-granted modes, Tattler availability/identity, and longer-horizon persistent goal behavior. Keep source PR as Draft for independent review. No main merge, deployment, canonical-memory promotion, or communication effects from this candidate.
