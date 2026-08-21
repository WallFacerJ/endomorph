# Enterprise Product Requirements

This document converts the enterprise vision into durable acceptance criteria for future product work.

## Experience requirements

### The product must not feel like courseware

- Professional mode does not present obvious answer-card response choices as the primary workflow.
- Active professional runs hide score/correctness/objective completion unless an organization explicitly enables those overlays.
- Investigation begins from incomplete evidence and requires analyst-directed pivots.
- The system supports ambiguity, benign activity, false positives, delayed data, and changing scope.

### Security applications must feel distinct

- SIEM is search/query/time/correlation centric.
- EDR is endpoint/process/file/network/action centric.
- Identity is account/session/access/risk/privilege centric.
- Network is flow/asset/packet/protocol centric.
- Email is message/header/sender/link/attachment centric.
- Cloud is resource/IAM/audit/configuration centric.
- Case is incident command/evidence/hypothesis/task/decision centric.

A generic card-list implementation duplicated across applications does not satisfy this requirement.

### Investigations must support depth

Professional scenarios should be able to include:

- hundreds to millions of telemetry records depending on fidelity;
- normal background activity;
- multiple users/endpoints/servers/services;
- multi-stage attacker behavior;
- raw event/log/artifact views;
- process trees and filesystem evidence;
- identity and access relationships;
- network and cloud pivots;
- acquired evidence and forensic artifacts;
- investigation tasks that cannot be completed by reading one curated timeline.

### Case must be operationally necessary

Case should support:

- evidence and provenance;
- entities/assets;
- indicators;
- hypotheses;
- findings;
- tasks/owners/status;
- decisions and approvals;
- response actions;
- communications;
- incident phase and severity;
- timeline and graph views;
- report generation;
- bidirectional pivots to source tools.

## Range requirements

### Fidelity ladder

Every asset may choose a fidelity level:

- synthetic model;
- interactive deterministic synthetic host;
- ephemeral container;
- microVM/full VM;
- external/customer-stack adapter where appropriate.

Scenario logic must not be tightly coupled to one fidelity level.

### Interactive-system safety

Runtime-backed assets require:

- isolation between users/runs;
- no unrestricted external network access by default;
- resource/time quotas;
- immutable/versioned base images;
- health checking;
- deterministic or checkpointed reset;
- automatic teardown;
- auditable analyst/adversary actions;
- explicit capability policy for executable operations.

### Reliability targets

Before range infrastructure is considered enterprise-ready, define and measure:

- environment startup latency;
- successful startup rate;
- reset latency/success rate;
- terminal/session availability;
- cleanup success;
- resource consumption per run;
- failure recovery behavior.

## Replay requirements

- Run state must remain reproducible from persisted scenario/run inputs wherever the fidelity layer permits.
- Analysts/instructors must eventually be able to inspect past state without restarting the entire exercise.
- Branching from a checkpoint should preserve provenance between the original and alternative runs.
- Tool observations and scoring must be explainable from underlying state/events.

## Enterprise control-plane requirements

A sellable enterprise product must eventually provide:

- multi-tenant organizations;
- users/teams/cohorts/roles;
- SSO and provisioning;
- server-side authorization;
- durable runs and collaboration;
- exercise assignment/scheduling;
- capacity management;
- audit logs;
- retention/data governance;
- readiness analytics;
- ATT&CK/NICE mapping;
- reports and exports;
- APIs/webhooks/integrations;
- private deployment options where buyer requirements justify them.

## Differentiation requirements

A major feature should improve at least one of these differentiators:

1. coherent enterprise causality across tools;
2. deterministic replay/rewind/branch/compare;
3. depth of analyst-directed investigation;
4. low-friction digital-twin/scenario authoring;
5. mixed-fidelity synthetic/container/VM ranges;
6. explainable readiness assessment;
7. human/red/blue/purple/AI actors operating against the same world.

## Anti-goals

Do not optimize for:

- badge count;
- scenario count without depth;
- childish gamification;
- multiple-choice completion rates;
- copying another platform's visual layout;
- infrastructure complexity as a proxy for enterprise readiness.
