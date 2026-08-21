# Polymorph Enterprise Vision

## North star

**Polymorph should become a deterministic cyber-operations digital twin: a platform where people, teams, security controls, and eventually AI agents investigate and respond to realistic incidents inside one coherent synthetic enterprise.**

The current v1 proves the deterministic scenario/runtime model. It is not the final product shape. Post-v1 development should prioritize technical depth, environmental realism, interconnection, enterprise operation, and a distinct professional identity over adding more shallow scenarios or course-like content.

## Product positioning

Polymorph should sit between two existing categories:

- browser-first training platforms that are easy to access but can become guided, shallow, or module-like;
- high-fidelity cyber ranges/digital twins that are technically deep but expensive, high-touch, infrastructure-heavy, and difficult to author.

The intended position is:

> **The depth of a cyber range, the coherence of a digital twin, the reproducibility of an event-sourced simulator, and the authoring/deployment friction of a modern software platform.**

Polymorph should be sellable as an enterprise cyber-readiness and incident-response platform, not merely as a cybersecurity course website.

## Direct tester feedback -> product mandates

Recent first-time feedback is consistent and should be treated as a product reset.

### Feedback: the experience feels juvenile and surface-level

Mandate:
- default scenarios must require genuine investigation, not simply reading an alert and selecting a response;
- incidents need noise, ambiguity, false leads, multiple affected assets, deeper timelines, and non-obvious scope;
- users should be able to investigate for 30-120+ minutes without exhausting the evidence surface;
- advanced scenarios should require hypothesis building, scoping, validation, eradication, recovery, and post-incident analysis.

### Feedback: it feels like a multiple-choice entry-level course

Mandate:
- remove courseware as the dominant interaction metaphor;
- response actions should be contextual operations inside tools/systems, not a row of obvious answer cards;
- explicit objectives should be hidden, optional, or instructor-configurable during professional-mode runs;
- assessment should measure state, evidence quality, investigation coverage, timing, unnecessary/harmful actions, and incident-process outcomes;
- guided learning remains an optional layer for onboarding, not the identity of the product.

### Feedback: it does not feel technical or deep

Mandate:
- add real investigative primitives: queries, filters, pivots, process trees, file metadata/hashes, registry/config state, auth history, cloud audit events, packet/network evidence, threat intel, sandbox output, timeline correlation, and artifact acquisition;
- allow users to enter isolated synthetic/virtualized systems and perform investigation/response work directly;
- professional scenarios must include enough raw data that analysts decide what matters rather than being shown only curated facts.

### Feedback: sections do not feel meaningfully different

Mandate:
- each security application gets its own information architecture and interaction model;
- SIEM should be query/search/correlation-centric;
- EDR should be endpoint/process-tree/telemetry/action-centric;
- Identity should be account/session/risk/access-policy-centric;
- Network should be flow/connection/asset/packet-centric;
- Email should be message/header/sender/link/attachment-centric;
- Cloud should be resource/IAM/audit/configuration-centric;
- Case should be investigation/incident-command-centric;
- visual design should support a coherent Polymorph brand while preserving the feel of distinct operational tools.

### Feedback: the Case section feels unnecessary

Mandate:
- transform Case from note-taking into the operational incident hub;
- connect alerts, entities, evidence, hypotheses, tasks, findings, indicators, decisions, response actions, communications, owners, and status;
- support an evidence graph and incident timeline assembled from analyst work;
- pivots from any tool should be attachable to the case and any case object should pivot back to its source tool;
- incident handling phases (triage, investigation, containment, eradication, recovery, lessons learned) should be represented as real workflow state.

### Feedback: Polymorph lacks a unique identity and feels too small

Mandate:
- identity comes from **coherent depth**, not decorative branding;
- all tools must observe the same synthetic enterprise and react to the same underlying causes;
- deterministic replay/rewind/branch/compare becomes a signature capability;
- enterprise topology and activity should continue outside the active incident so the environment feels alive;
- content should span identity, endpoint, network, email, cloud, SaaS, applications, data, security controls, and business context.

### Feedback: analysts want to enter real/virtual systems and perform red/blue work

Mandate:
- build a Synthetic Infrastructure Fabric capable of attaching interactive runtime instances to synthetic assets;
- start with safe deterministic host/service models, then add server-backed ephemeral containers, and later microVM/full-VM fidelity where required;
- expose terminal/PowerShell-like investigation, filesystem/process/service/configuration state, logs, network connections, and artifact acquisition;
- support controlled attack behavior so red-team activity changes the same world the blue team observes;
- support containment/recovery operations that materially change systems and telemetry;
- isolate environments by default, deny uncontrolled external network access, enforce CPU/memory/time limits, and record all range actions into deterministic run history where possible.

---

# Product architecture: named layers

Working names are intentionally product-oriented so Polymorph develops a recognizable identity.

## Polymorph Fabric - the enterprise digital twin

The shared model of organizations, users, identities, endpoints, servers, applications, SaaS, cloud resources, networks, data stores, mailboxes, controls, vulnerabilities, normal activity, and adversary activity.

Requirements:
- topology and relationship graph;
- normal background behavior and traffic;
- business context and criticality;
- entity history and state at any virtual time;
- deterministic event history;
- configurable fidelity per asset.

## Polymorph Ops - professional security applications

Distinct operational applications over the same Fabric:

- SIEM / search / correlation
- EDR / endpoint investigation
- Identity / IAM / session analysis
- Email security
- Network / NDR
- Cloud security / CSPM-style context / audit
- Threat intelligence
- Malware/sandbox analysis
- Vulnerability and asset context

These are not independent toy datasets. Every observation should derive from the same world/run.

## Polymorph Range - interactive systems

A safe isolated execution layer for assets that need hands-on depth.

Fidelity ladder:

1. **Synthetic host runtime** - deterministic virtual filesystem/process/service/configuration/registry/network model with a controlled command API.
2. **Ephemeral containers** - real Linux/service workloads with network namespaces, resource controls, snapshots, telemetry instrumentation, and no unrestricted internet by default.
3. **MicroVM/full VM** - Windows/Linux or appliance fidelity where containers are insufficient.
4. **Customer-stack adapters** - optional commercial/open-source security tooling and customer-like infrastructure for enterprise deployments.

A scenario should be able to mix fidelity levels. Most assets can remain inexpensive synthetic models while only investigation-critical assets consume heavier runtime resources.

## Polymorph Case - incident command and investigation graph

The incident's operational source of work, not canonical enterprise truth.

Objects:
- alerts
- evidence
- entities/assets
- indicators
- hypotheses
- findings
- tasks
- owners
- decisions
- response actions
- communications
- approvals
- timestamps/SLA state
- incident phase/status

Capabilities:
- graph and timeline views;
- bidirectional pivots into Ops tools;
- tasking and collaboration;
- evidence provenance;
- case report generation;
- after-action reconstruction.

## Polymorph Replay - deterministic time machine

Signature capability enabled by the event-sourced architecture.

Long-term capabilities:
- rewind to any run point;
- inspect the exact state/tool projections at that time;
- branch an alternative response from a checkpoint;
- compare two response paths;
- instructor playback;
- explain why a tool showed a particular observation;
- reproduce scoring and readiness metrics;
- export/share deterministic run bundles.

## Polymorph Forge - scenario and digital-twin authoring

Enterprise content creation should not require rebuilding infrastructure by hand.

Capabilities:
- topology/world builder;
- reusable organization templates;
- asset and security-stack templates;
- ATT&CK technique/adversary plan authoring;
- normal-activity generators;
- attack/incident timeline authoring;
- response policy/objective authoring;
- telemetry source selection;
- per-asset fidelity selection (synthetic/container/VM);
- preview/validate/replay before publishing;
- versioned content and approvals.

## Polymorph Control - enterprise control plane

Capabilities expected for a marketable enterprise product:
- organizations/tenants;
- teams and cohorts;
- users and roles;
- SSO/SAML/OIDC and SCIM;
- assignments/campaigns/exercises;
- run scheduling and capacity controls;
- instructor/facilitator console;
- dashboards and readiness baselines;
- ATT&CK/NICE coverage and skill-gap analysis;
- MTTD/MTTR, investigation quality, containment/recovery, and process metrics;
- audit logs;
- reports/export;
- API/webhooks/integrations;
- retention and data-governance controls;
- cloud and private/on-prem deployment options where justified.

---

# Enterprise experience principles

## Professional mode first

The core UI should resemble work, not school. No score, objective checklist, or "correct answer" language needs to be visible during a professional run unless an organization intentionally enables it.

## Progressive assistance

Beginner support should be layered onto the same deep environment:
- contextual hints;
- optional playbooks;
- instructor nudges;
- tooltips/explanations;
- guided mode.

Do not create a separate shallow product for beginners.

## Ambiguity is a feature

Real incidents include normal traffic, false positives, incomplete evidence, delayed telemetry, benign admin behavior, multiple users, and changing scope. Scenarios should deliberately model this.

## Interconnection over content count

Ten deeply interconnected incidents are more strategically valuable than one hundred isolated card-and-button exercises.

## Reliability is product quality

If interactive systems are introduced, startup latency, health, reset speed, capacity, snapshot integrity, and environment cleanup become first-class SLOs.

## Explainability over opaque scoring

Every score or readiness metric must be explainable from run state, actions, evidence, timing, and authored assessment criteria.

---

# Enterprise-grade incident lifecycle

A serious Polymorph scenario should be able to exercise:

1. detection / alerting;
2. triage and prioritization;
3. investigation and hypothesis formation;
4. scope determination;
5. evidence acquisition and preservation;
6. containment;
7. eradication;
8. recovery;
9. validation/monitoring;
10. communications/escalation;
11. case documentation;
12. post-incident review and lessons learned.

Different roles should be able to participate in the same run: Tier 1/2/3 SOC, incident responder, threat hunter, malware analyst, detection engineer, IAM/cloud/network specialists, red team, SOC manager, and executive/crisis roles where appropriate.

---

# Definition of "special"

Polymorph should eventually be able to demonstrate an experience like this:

> A user receives an ambiguous identity alert. They query a SIEM with real search semantics, pivot to an identity console, inspect the user's session graph, open the associated endpoint in EDR, trace a process tree, acquire a suspicious file, detonate it in a sandbox, query DNS/network history, attach the resulting evidence to an incident graph, open an isolated shell on another affected server, discover lateral movement, coordinate containment tasks with a teammate, and then rewind the completed incident to compare what would have happened if they had isolated the host ten minutes earlier. Every tool view, system state, and score is derived from one replayable synthetic enterprise.

That is a substantially different product from a multiple-choice SOC course and is the standard future work should move toward.
