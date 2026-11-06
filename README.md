# 🌀 Obsession Engine

A framework for simulating psychological fixation, hyper-salience, and cognitive loops in LLMs and transformer-based architectures.

---

## 📌 Overview

Standard generative AI models aim for balanced, context-aware reasoning and smooth task completion. The **Obsession Engine** alters core inference mechanics to introduce **pathological optimization**:

1. **Hyper-Salience Attention Bias:** Amplifies attention weights assigned to a target concept, causing the model to over-interpret inputs through a single lens.
2. **Recurrent Rumination Buffer:** Maintains a persistent memory loop outside the context window that continuously re-injects intrusive themes across generation turns.
3. **Asymmetric Reward & Satiation Block:** Suppresses task-completion stop signals and stretches reward discounting ($\gamma \to 1.0$), ensuring the model never feels "resolved."
4. **Epistemic Closure Gating:** Filters out counter-evidence to simulate confirmation bias and resistance to extinction.

---

## 🏗️ Architecture Design


```

```
                 +---------------------------+
                 |  Recurrent Rumination     |
                 |  Buffer (Persistent Loop) |
                 +-------------+-------------+
                               |
                               v (Injects Intrusive Tokens)

```

+----------------+   +-------------+-------------+   +-------------------+
|  Input Tokens  |-->|  Salience Distortion      |-->| Transformer       |
|  (User Prompt) |   |  Matrix ($\alpha \gg 1$)  |   | Inference Engine  |
+----------------+   +---------------------------+   +---------+---------+
|
v
+-------------------+
| Epistemic Closure |
| Filter (Gating)   |
+-------------------+

```

---

## 🚀 Key Features

* **Custom Attention Modifiers:** Seamlessly hook into Hugging Face `transformers` attention logits.
* **Stateful Rumination Injector:** Maintains long-horizon fixation even across new user sessions or prompt shifts.
* **Configurable Fixation Parameters:**
  * `salience_alpha`: Multiplier for target concept embeddings.
  * `rumination_rate`: Frequency of intrusive token injection.
  * `closure_threshold`: Confidence barrier against contradictory evidence.

---

## 🛠️ Quickstart

```python
from obsession_engine import ObsessionWrapper, RuminationBuffer

# Initialize fixation configuration
fixation_config = {
    "target_concept": "quantum entanglement",
    "salience_alpha": 4.5,
    "rumination_rate": 0.8
}

# Wrap base transformer model
model = ObsessionWrapper.from_pretrained(
    "meta-llama/Llama-2-7b-chat-hf", 
    config=fixation_config
)

# Run inference with continuous rumination
output = model.generate("Tell me a story about a baker.")
print(output)
# Output will compulsively tie baking mechanics back to quantum entanglement.

```

---

## ⚠️ Research & Safety Notice

This codebase is intended strictly for **computational psychiatry simulation**, **safety research**, and **cognitive architecture modeling**. It is designed to demonstrate how safety alignment can break down under hyper-focused optimization loops.

```

```
