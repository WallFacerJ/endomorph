# Detection-as-code: score your rules on every change

Endomorph can gate a detection-rule repository the way tests gate application
code. Because the corpus is labelled by construction, a rule's precision, recall,
and technique coverage are **counted**, so "did this change make our detections
better or worse" has an exact, reproducible answer — in CI, on every pull
request.

No new tooling: this uses the flags the evaluator already ships.

## The loop

```bash
# 1. Score your Sigma rules against the benchmark and record the result.
pnpm evaluate -- --sigma path/to/your/rules --json detection-baseline.json

# 2. On every change, score again and fail if anything regressed.
pnpm evaluate -- --sigma path/to/your/rules --baseline detection-baseline.json
```

The second command exits non-zero when a rule stops firing on a technique it
used to catch, so a pull request that quietly breaks a detection fails the
build. Rules the supported Sigma subset can't express are reported by name with
a reason, never dropped silently — a rule that matches nothing looks exactly
like one that works, and CI is precisely where that must not slip through.

Commit `detection-baseline.json` alongside the rules. When you *intend* to change
what the ruleset catches, regenerate it (step 1) in the same PR — the diff makes
the change reviewable.

## In GitHub Actions

A ready-to-adapt workflow is in
[`.github/workflows/detection-ci.example.yml`](../.github/workflows/detection-ci.example.yml).
Copy it into your detection-rules repository, point `RULES_DIR` at your Sigma
folder, commit a baseline, and every pull request gets scored against the
Endomorph benchmark with a regression gate.

## What "regressed" means

- **Regression (fails the build):** a rule that used to detect its technique now
  detects none of it — coverage lost.
- **Notice (does not fail):** a rule got noisier, or the corpus shape shifted.
  Reported so it's visible, but a rule getting louder is a judgement call, not an
  automatic failure.

The distinction is the point: a rule that got noisier and a rule that broke are
different events, and reporting them in the same word is how a real regression
slips past someone who has learned to skim the output.

## Why this is possible here and not against a captured dataset

A captured corpus has one world and hand-applied labels, so the numbers drift
and can't be reproduced. Endomorph's are generated from a seed with ground truth
known by construction, so the same ruleset scored twice gives the same result,
and a difference is a difference in the rules — which is the only basis on which
a CI gate means anything.
