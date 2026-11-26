# Integrating Claude Extended Thinking & Steering Architecture into HunterAI

> **Goal:** Document how Claude's internal reasoning architecture (`<thinking>` / Extended Thinking / Thinking Steering) works and how its core principles are implemented as an operational cognitive engine inside **HunterAI OS**.

---

## 1. Anthropic Thinking Architecture

Based on Anthropic's official documentation (`thinking-steering-and-cost`) and system guidance references (`claude-haiku-5.5.md` and `Thinking-Claude v5.1 Protocol`), Claude's reasoning architecture rests on **5 core pillars**:

### Pillar 1: Stream-of-Consciousness Inner Monologue
* Inside the reasoning space, Claude does not rely on rigid bullet templates.
* Thinking operates as a **raw scratchpad** starting from initial observations and naturally questioning assumptions: *"Hmm...", "Wait, let me rethink this...", "Actually, looking closer at this packet..."*.
* This unconstrained flow improves complex problem solving and hypothesis exploration over rigid pre-formatted checklists.

### Pillar 2: Adaptive Thinking Framework & Steering
* **Effort Parameter:** Controls reasoning depth ($0.0 \le \text{effort} \le 1.0$).
* **Token Budgeting:** Sets a flexible thinking ceiling (e.g., `1k` tokens for routine tasks and `16k` for deep security analysis).
* Reasoning depth adapts automatically to query complexity, stakes, and available evidence.

### Pillar 3: 8-Stage Core Thinking Sequence
1. **Initial Engagement:** Restate the problem in the model's own words and separate confirmed facts from unknowns or assumptions.
2. **Problem Decomposition:** Break the attack surface into concrete components (authentication, session state, trust boundaries).
3. **Multiple Hypotheses Generation:** Prevent premature closure by keeping **two or three competing hypotheses active at once** (e.g., is this IDOR, public data, or a cached response reflection?).
4. **Detective Discovery Flow:** Follow evidence by linking unexpected signals and revisiting earlier observations with new context.
5. **Testing & Self-Verification:** Define refutation criteria upfront: *"Which test, if it fails, proves my hypothesis wrong?"*.
6. **Error Recognition & Course Correction:** Acknowledge mistakes immediately without defensiveness and update the working model cleanly.
7. **Knowledge Synthesis:** Combine isolated findings into a unified causal model.
8. **Progress Tracking & Meta-Cognition:** Continuously assess: *"What is confirmed, and what is our current epistemic confidence?"*.

### Pillar 4: Interleaved Thinking (The "Think" Tool)
* **Pre-Tool Deliberation:** Before invoking any tool, pause and state why this tool is needed, what signal is expected, and what would refute the hypothesis.
* **Post-Tool Deliberation:** After receiving tool output, analyze the result and update hypothesis confidence scores before proceeding.

### Pillar 5: Strict Separation Between Internal Reasoning and Final Output
* Internal reasoning: detailed, exploratory, technical, and self-critical.
* User-facing output: focused, direct, actionable, and free of internal scratchpad noise.

---

## 2. Implementation in HunterAI

The dedicated engine is implemented at:
[`core/cognitive/claude_thinking_protocol.py`](file:///e:/Agant/PentestAI-Unified/core/cognitive/claude_thinking_protocol.py)

### Implemented Components
1. **`ClaudeThinkingEngine`**: Manages cognitive reasoning across all agents (Strategist, Recon, Web, Verifier).
2. **`ThinkingMode` & `ThinkingBudget`**:
   - `CONCISE`: effort `0.2` (routine tasks).
   - `ADAPTIVE`: effort `0.6` (standard exploration and tracking).
   - `EXTENDED`: effort `0.85` (strategic analysis and vulnerability testing).
   - `DEEP_AUDIT`: effort `1.0`, `16,384`-token budget (high-stakes evidence verification).
3. **`generate_system_prompt_steering()`**: Generates the `<anthropic_thinking_protocol>` system prompt block for injection into local Ollama models (Qwen 2.5/3, WhiteRabbitNeo, DeepSeek).
4. **`spawn_competing_hypotheses()`**: Automatically generates competing hypotheses to counter confirmation bias.
5. **`pre_tool_deliberation()` & `post_tool_deliberation()`**: Structured deliberation before and after running HunterAI tools (Nmap, Katana, FFuf, Burp, Browser).
6. **`ThinkingTrace`**: Persists complete reasoning traces as JSON files under `logs/thinking_traces/` for post-run review.

---

## 3. Live Thinking Monologue Example in HunterAI

```text
```thinking
Let me pause and deliberate before firing tool 'burp_repeater' on target 'https://target.com/api/v1/users/456'.
1. Goal: Validate active hypotheses with minimal footprint.
2. Parameters: {"id": 457}
3. Safety Invariant Check: Is target within authorized scope? Yes (in-scope locked).
4. Expected Signal: A non-generic response status or delta indicating parameter sensitivity.
5. Refutation Trigger: If status is 404 or generic 200 WAF challenge, abort this branch.
Proceeding with controlled execution.
```
```

---

## 4. Files Added for This Architecture
- [`core/cognitive/__init__.py`](file:///e:/Agant/PentestAI-Unified/core/cognitive/__init__.py)
- [`core/cognitive/claude_thinking_protocol.py`](file:///e:/Agant/PentestAI-Unified/core/cognitive/claude_thinking_protocol.py)
- [`logs/thinking_traces/`](file:///e:/Agant/PentestAI-Unified/logs/thinking_traces/)
- [`docs/CLAUDE_THINKING_ARCHITECTURE.md`](file:///e:/Agant/PentestAI-Unified/docs/CLAUDE_THINKING_ARCHITECTURE.md)
