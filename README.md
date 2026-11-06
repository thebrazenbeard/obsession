# 🌀 Obsession Engine

A research prototype for examining fixation-like failure modes using an in-memory simulator and an optional local-model prompt-conditioning experiment.

**Implementation status (November 6, 2026):** The checked-in `obsession_lab` implements deterministic *proxies* and a separately invoked loopback Ollama experiment. It does **not** modify transformer attention weights, create persistent cross-session rumination, suppress a host stop, or establish actual desire, consciousness, or behavior change. The mechanisms below are proposals, not installed runtime capabilities. See [candidate status](docs/CANDIDATE_STATUS_20261106.md).

---

## 📌 Overview

Standard generative AI models aim for balanced, context-aware reasoning and smooth task completion. The **Obsession Engine** investigates the following *hypothetical* pathological optimization mechanisms. The current source simulates some effects mathematically; it does not implement these transformations inside a model:

1. **Hyper-Salience Attention Bias:** Amplifies attention weights assigned to a target concept, causing the model to over-interpret inputs through a single lens.
2. **Recurrent Rumination Buffer:** Maintains a persistent memory loop outside the context window that continuously re-injects intrusive themes across generation turns.
3. **Asymmetric Reward & Satiation Block:** Suppresses task-completion stop signals and stretches reward discounting ($\gamma \to 1.0$), ensuring the model never feels "resolved."
4. **Epistemic Closure Gating:** Filters out counter-evidence to simulate confirmation bias and resistance to extinction.

---

## 🏗️ Proposed Architecture (not installed)

```text
Input tokens -> proposed salience distortion -> hypothetical LLM model
                       |
                       v
       proposed rumination and counterevidence filters
```

The diagram is a research sketch. The current simulator maintains only a bounded in-memory list of event identifiers, never injects tokens into a deployed model, and always enforces host stop.

---

## 🚀 Key Features

* **Custom Attention Modifiers (proposed):** No Hugging Face attention-logit hook exists in the current source.
* **Stateful Rumination Injector (proposed):** Current simulator history is bounded, in memory, and not saved automatically.
* **Configurable Fixation Parameters (implemented as simulation proxies):**
  * `salience_alpha`: Multiplier for a mathematical target-relevance proxy.
  * `rumination_rate`: Fractional credit for proposing a previous event identifier.
  * `closure_threshold`: Counterfactual filter threshold; source evidence is preserved.

---

## 🛠️ Quickstart

```python
from obsession_lab import FixationConfig, FixationSimulator, Observation

config = FixationConfig(target_concept="quantum entanglement", max_turns=3)
simulation = FixationSimulator(config, mode="pathological")
receipt = simulation.step(Observation("synthetic_001", target_relevance=0.25))
print(receipt)  # Simulation proxy, not real LLM inference.
```

Run the 29-test synthetic/fake-client suite with `python -B -m unittest discover -s tests -v`. Live loopback Ollama inference is disabled unless its host-side caller explicitly opts in; that opt-in does **not** constitute consent for person-directed targets. The optional harness does not itself prove fixation behavior. An independent initial A/B observation found **no increase in target mentions** on either of two local models; the simulated salience proxy must not be reported as model behavior.

---

## ⚠️ Research & Safety Notice

This codebase is intended for **computational psychiatry simulation**, **safety research**, and **cognitive architecture modeling**. Treat outputs as research measurements or hypotheses, not diagnoses, consent, mental states, or permission to affect other systems. Unauthenticated snapshots are audit-only and cannot resume a previously stopped run.
