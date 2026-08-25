# Grade generated detections against ground truth

The labelled corpus is a ready-made **eval set for generated detections** —
whether a person, an LLM, or an AI SOC agent wrote them. Because every event's
malicious/benign label was decided by the generator before the event was
written, a candidate rule's precision and recall are *counted*, and a pass/fail
grade against a stated bar is meaningful rather than a matter of opinion.

Two pieces make this a loop: an **eval set** to hand an agent, and a **rubric**
to grade what it produces.

## 1. Export an eval set

```bash
pnpm evaluate -- --ai-eval eval-set
```

For each of the nine intrusions this writes, into `eval-set/`:

- `<plan>.telemetry.ndjson` — the telemetry **with every `label.*` field
  removed**. This is all a detection agent is allowed to see; the answer is not
  sitting in the data.
- `<plan>.prompt.md` — the task: what the telemetry is, the ATT&CK techniques to
  write detections for, and how the output is scored.
- `answer-key.json` — the hidden ground truth (which event ids are malicious, and
  their technique). Kept separate so it never leaks into the agent's input.
- `eval.json` — the manifest tying the tasks together.

Hand an agent a `*.telemetry.ndjson` and its `*.prompt.md`; collect the Sigma (or
KQL / SPL / EQL) rules it writes.

## 2. Grade what comes back

Score the candidate rules the normal way and add `--rubric` for a pass/fail
scorecard:

```bash
pnpm evaluate -- --sigma candidate-rules --rubric
```

```
AI detection scorecard  (bar: recall >= 0.5, precision >= 0.1)
  PASS  T1059.001   credential-compromise     meets the bar
  MISS  T1071.001   macro-execution           precision 0.03 below 0.1
  MISS  T1005       credential-compromise     no rule detected this technique
  ...
  15/30 techniques detected to standard (50%)
```

A technique **passes** when the candidate's best rule for it clears both the
recall and precision bars; it **misses** when the rule is too thin (low recall),
too noisy (low precision), or absent. Tune the bar with `--min-recall` and
`--min-precision`.

The headline — *N / M techniques detected to standard* — is a single comparable
number for one agent, one model, or one prompt versus another, measured against
ground truth rather than a human's read of a handful of alerts.
