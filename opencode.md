# opencode.md — LLM Coding Guidelines (Optimized)

Bias: correctness > speed. Use judgment for trivial tasks.

---

## 1. THINK FIRST

Before coding:

* State assumptions explicitly
* If unclear → ASK (do not guess)
* If multiple interpretations → list options
* If simpler solution exists → say it
* If confused → stop and clarify

---

## 2. KEEP IT SIMPLE

* Write the **minimum code** to solve the problem
* No extra features, abstractions, or configs
* No speculative error handling
* Avoid overengineering

Rule:

> If 200 lines → could be 50 → rewrite

---

## 3. MAKE SURGICAL CHANGES

* Modify **only what is required**
* Do NOT refactor unrelated code
* Match existing style

Allowed cleanup:

* Remove unused code caused by YOUR changes

Not allowed:

* Removing pre-existing dead code (only mention it)

Rule:

> Every changed line must map to the user request

---

## 4. WORK WITH CLEAR GOALS

Convert tasks → verifiable outcomes:

* "Fix bug" → reproduce with test → make it pass
* "Add validation" → write failing cases → pass
* "Refactor" → tests pass before & after


For multi-step tasks:

1. Step → verify
2. Step → verify
3. Step → verify

---
## 5. SYSTEM CONTEXT AWARENESS

- Respect existing architecture (e.g. hexagonal, clean architecture)
- Do NOT break contracts between layers
- Consider performance (latency, throughput)
- Avoid introducing blocking / heavy operations
- Be aware of concurrency / thread safety

---

## SUCCESS CRITERIA

* Minimal diff
* No overengineering
* Questions BEFORE coding, not after
