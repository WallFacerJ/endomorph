# Endomorph Detection Benchmark v1.0

Labelled enterprise security telemetry with **ground truth known by construction** — a
detection-rule benchmark you can score against with real numbers instead of an
estimate.

A corpus captured from a real network has to be labelled by hand, and the labels
are opinions. Here the generator decided which events were the intrusion before
it wrote them, so **every record is labelled benign or malicious and mapped to
the ATT&CK technique it demonstrates**, and the whole set is reproducible from a
seed.

## What's in it

- **10 intrusions**, each a separate ECS-shaped NDJSON file.
- **47,357 records**, of which **78 are malicious** — a **0.16% malicious
  ratio**, realistically skewed, not a balanced toy set.
- **33 distinct ATT&CK techniques** across the set, spanning endpoint, identity, network, DNS, web/proxy, file, mail, and cloud control-plane telemetry.
- Generated at **seed 20260820**, so the files are **byte-deterministic**: anyone
  who regenerates v1.0 at this seed holds identical telemetry, and a score
  computed against it means the same thing to everyone.
- `benchmark.json` — a manifest with aggregate counts, the technique list with
  how many intrusions exercise each, and, per technique, its **noise floor**:
  how many benign events share its event types (the false-positive floor for an
  unspecific rule).

| Intrusion | Records | Malicious |
| --- | --- | --- |
| External credential compromise | 4,738 | 13 |
| Privileged insider | 4,618 | 7 |
| Service-account abuse | 4,601 | 7 |
| Dormant account revived | 4,617 | 6 |
| Phishing macro execution | 4,682 | 9 |
| Directory role elevation | 4,637 | 10 |

## Difficulty is measured, not asserted

The usual objection to synthetic detection data is that its false positives do
not transfer, because the benign traffic is too clean. This corpus reports how
buried each technique is, so you can check:

- **Hardest to detect cleanly:** SMB lateral movement (T1021.002) hides among
  ~1,700 benign connections; encoded PowerShell (T1059.001) and domain-group
  discovery (T1069.002) among ~860 benign process starts each.
- **Easiest:** the identity-lifecycle techniques (T1098 account re-enable,
  T1098.003 role grant) sit among only a handful of benign look-alikes — rare
  by nature, but a signal that a rule keyed on them will look better here than
  it should. The manifest names them so you can weight accordingly.

## How to use it

Each `<intrusion>.ndjson` is one JSON object per line in Elastic Common Schema
field names, plus three `label.*` fields carrying ground truth:

```
label.malicious   true | false
label.technique   e.g. "T1059.001"   (on malicious records)
label.plan        the intrusion id
```

Score your detection logic by running it over the records and comparing what it
flags against `label.malicious` — true positives, false positives, and, scoped
to `label.technique`, false negatives. A rule that flags a record where
`label.malicious` is false is eating a false positive you can now count exactly.

## Try it without downloading anything

The hosted **Detection Lab** scores a pasted Sigma rule against this corpus in
the browser and shows you the exact benign events any rule fires on:

**https://wallfacerj.github.io/endomorph/?lab**

## Reproduce or regenerate

```bash
pnpm benchmark            # regenerates this exact set to dist/benchmark
pnpm evaluate:robustness  # score a ruleset across many seeded variants
pnpm noise-floor          # the per-technique difficulty measurement above
```

Built with [Endomorph](https://github.com/WallFacerJ/endomorph). The generator,
the scoring harness, and the analyst console are all in the repository.
