# Endomorph Product Roadmap, from wedge to sellable product

Updated: 2026-08-25

This is the **commercial** roadmap: the complete path from Endomorph's current
open core to a product a security organization pays for. It is deliberately
broader than `ROADMAP.md` (the near-term working roadmap of what's being executed
now) and `STRATEGY.md` (the wedge decision record). Nine capability pillars,
sequenced across four horizons, with the commercial model, the buyers, the
metrics, and the guardrails.

Horizon key: **H1** Foundation (0-3mo) · **H2** Commercialize (3-9mo) ·
**H3** Enterprise (9-18mo) · **H4** Platform (18mo+).
Priority key: **P0** load-bearing · **P1** important · **P2** valuable.

Today: 12 intrusions · 41 ATT&CK techniques · 8 event domains · 5 rule languages ·
5 vendor-native export schemas · digital twin · AI-eval harness · seeded attack variation.

---

## The thesis, and who pays

**Detection is unmeasured, and Endomorph measures it.** Every SOC ships detections
it cannot score, tunes rules it cannot prove, and reports "coverage" it cannot
defend. Because Endomorph knows ground truth by construction, it turns detection
quality into a **counted number**, precision, recall, ATT&CK coverage, resilience
to attacker evasion, resilience across worlds, with zero infrastructure and zero
real data.

The sellable product is the platform around that number: **continuous detection
validation, coverage reporting, and a citable benchmark**, delivered where security
teams already work (their SIEM, their CI, their ATT&CK matrix), priced open-core so
adoption is bottom-up and monetization is scale, privacy, content, and enterprise
trust.

**Who buys** (beachhead → widening budget):

- **Detection engineers / security engineering**, score and regression-gate their
  own rules. The bottom-up adopter and champion. *Beachhead.*
- **SOC / detection managers & CISOs**, coverage reporting, readiness evidence,
  MTTD proxies, board-ready posture. *Budget owner.*
- **MSSPs & MDR providers**, prove and differentiate detection quality across many
  tenants. Multi-tenant, high-ACV.
- **Detection-content & SIEM/EDR vendors**, validate their own shipped detections
  against a neutral, labelled benchmark.
- **Purple / red teams & threat-informed defense**, emulation-aligned scenarios,
  evasion variation, gap analysis vs adversary profiles.
- **GRC, audit & regulated industries**, evidence of detection coverage mapped to
  NIST CSF / DORA / PCI for auditors.

---

## Commercial model, open core, land bottom-up

Give away the generator, the public benchmark, and the single-user lab to earn
inbound, citations, and trust; monetize what infrastructure and a solo user cannot
cheaply copy, scale, privacy, hosted continuous validation, content cadence, and
enterprise controls.

| Tier | For | Includes | Price |
| --- | --- | --- | --- |
| **Open Source** | adopt & cite | generator + benchmark, CLI + 5 languages, single-user lab, CI recipe, coverage badge | Free (MIT/Apache) |
| **Team** | self-serve SaaS | hosted lab + saved runs, coverage dashboard & history, SIEM push + CI, digital twin, shared workspaces | per-seat + usage (PLG) |
| **Enterprise** | sales-assisted | SSO/SCIM/RBAC/audit, continuous validation + alerts, compliance & exec reporting, private/VPC or self-hosted, premium content + SLA | annual contract |
| **MSSP / OEM** | platform | multi-tenant, white-label reporting, API/SDK volume, vendor detection-testing, revenue-share content | usage / OEM |

**Pricing levers:** seats · generation volume & scale · scheduled validation runs ·
connected SIEMs/repos · premium & fresh content subscriptions · deployment mode
(SaaS → VPC → air-gapped) · support SLA.

**TAM adjacencies (later):** purple-team exercises, vendor detection-testing,
detection-content marketplace, managed detection-quality service, training/cyber-range.

---

## The nine capability pillars

### 1 · Detection data & content
*Done when the corpus is broad, fresh, vendor-native, and citable enough to be an industry standard.*

- **[H1·P0]** Deepen ATT&CK coverage from 41 toward the top ~150-200 techniques by real-world prevalence (Red Canary / CISA / Sigma), across all 14 tactics.
- **[H1·P0]** Vendor-native schema export: ECS, Splunk HEC, Elastic bulk, Sentinel, and OCSF ship today; Chronicle UDM and ASIM next.
- **[H1·P1]** Versioned, citable benchmark releases, SemVer, changelog, permalinks, DOI.
- **[H2·P0]** New domains, AD/LDAP audit, macOS + Linux endpoint, Kubernetes/container, SaaS audit (M365, Google, Okta, Salesforce), NetFlow/PCAP, WAF/CASB.
- **[H2·P1]** Adversary-emulation profiles (named ATT&CK groups, ransomware chains); a full evasion library.
- **[H2·P1]** Scale generation, millions of events, thousands of hosts, streaming replay into a live SIEM.
- **[H3·P0]** Threat-intel-driven fresh content within days of major campaigns/CVEs, a content cadence SLA. The recurring reason to keep paying.
- **[H3·P2]** Benign-realism v2, business-process modelling, seasonality, richer entities.

### 2 · Detection engineering platform
*Done when a team manages the full detection lifecycle inside it.*

- **[H1·P0]** Coverage analytics, ATT&CK heatmap of a ruleset's coverage, gaps, gaps weighted against a threat profile.
- **[H1·P1]** More rule languages, Chronicle YARA-L, Panther (Python), Sentinel scheduled analytics, Splunk ESCU/correlation, Suricata/Snort, Zeek, Falco, Sigma-correlation.
- **[H2·P0]** Detection lifecycle, catalog with versioning, deep GitHub/GitLab PR checks, drift detection, health over time.
- **[H2·P1]** Alert-volume & latency estimation, FP clustering, tuning recommendations.
- **[H2·P2]** Rule translation across languages; AI-assisted authoring from a gap.
- **[H3·P1]** Public detection-quality leaderboard & a "detection quality score" standard.

### 3 · AI & autonomous evaluation
*Done when Endomorph is the neutral benchmark the AI-SOC market is graded against.*

- **[H1·P1]** Package the AI-eval harness as a standard "AI SOC / LLM detection benchmark" with a public leaderboard.
- **[H2·P1]** In-product detection copilot, write, tune, explain; gap → candidate detection.
- **[H2·P2]** Continuous model-regression eval; agent-vs-human & human+agent comparison.
- **[H3·P2]** Synthetic labelled data for ML-detection training; adversarial-ML eval.

### 4 · Enterprise platform & control plane
*Done when a large org can deploy, govern, and audit it inside their own controls.*

- **[H1·P0]** Hosted SaaS, accounts/workspaces, durable run history & saved configs (Postgres + object storage).
- **[H1·P0]** Public REST API + Python SDK + stable versioned CLI + webhooks.
- **[H2·P0]** Multi-tenant orgs/teams; RBAC (admin/engineer/analyst/auditor); API keys & service accounts.
- **[H3·P0]** SSO (SAML/OIDC) + SCIM, the hard gate on every enterprise deal.
- **[H3·P1]** Deployment options, self-hosted (Helm/k8s), private VPC, air-gapped; AWS/Azure/GCP Marketplace.
- **[H3·P2]** Scale & reliability, job queue, multi-region, HA, published SLAs.
- **[H4·P2]** Terraform provider, event streaming, data-lifecycle & retention.

### 5 · Integrations & ecosystem
*Done when Endomorph plugs into the tools a SOC already lives in, both directions.*

- **[H1·P0]** One-click corpus push to Splunk, Sentinel, Elastic; a GitHub Actions app (+ GitLab / Azure DevOps).
- **[H2·P1]** Chronicle, QRadar, Exabeam, Panther, Sumo, Devo; EDR/XDR schemas (CrowdStrike FDR, Defender, SentinelOne).
- **[H2·P1]** ATT&CK Navigator import/export; STIX/TAXII; threat-informed mapping (Tidal / CTID).
- **[H2·P2]** Ticketing & notify, Jira, ServiceNow, Slack, Teams.
- **[H3·P2]** Detection-content repo integrations (Sigma HQ, Splunk ESCU, Elastic rules, Sublime); SOAR playbook validation.
- **[H3·P1]** GRC framework mapping, NIST CSF, CIS, PCI, DORA, HIPAA, coverage as audit evidence.

### 6 · Reporting, analytics & value
*Done when a CISO can show the board detection posture improving, with evidence.*

- **[H1·P0]** Coverage dashboard, ATT&CK heatmap, gaps, trend, plus a one-click exec/board report. Converts a champion into a budget.
- **[H2·P0]** Scheduled continuous validation with regression alerts; readiness scoring; MTTD / alert-volume / analyst-hour proxies.
- **[H2·P1]** Compliance / audit-ready reports mapped to frameworks; evidence export.
- **[H3·P2]** Anonymised peer / industry benchmarking, a data network effect only a multi-user platform can offer.

### 7 · Trust, security & compliance
*Done when security-buying committees clear it without friction.*

- **[H1·P1]** Lead with the privacy story, 100% synthetic, no customer data required or exfiltrated. The strongest differentiator vs any tool that ingests real logs. Trust center + security whitepaper.
- **[H1·P1]** Supply-chain hygiene, SBOM, signed releases, dependency scanning; firm responsible-use guardrails (synthetic & isolated only).
- **[H2·P0]** SOC 2 Type II + pen-test cadence + DPA/GDPR + data-residency, table stakes.
- **[H3·P2]** ISO 27001; FedRAMP / IL4-5 path and air-gapped support for gov/defense.

### 8 · Go-to-market, pricing & community
*Done when adoption is a self-sustaining bottom-up flywheel with an enterprise upsell.*

- **[H1·P0]** The public benchmark + leaderboard as a category standard, the highest-leverage marketing asset. Research, blog, conference talks (BSides, DEF CON, SANS, ATT&CKcon).
- **[H1·P0]** Product-led growth, frictionless self-serve (score a rule in <2 min), packaging & pricing v1, in-product upgrade paths.
- **[H2·P1]** Community, Discord, contributor program, content bounties, and 3-5 design partners.
- **[H2·P1]** Partnerships, SIEM/EDR co-sell + marketplaces, MSSPs, MITRE CTID, universities/training.
- **[H3·P2]** Analyst relations (Gartner/Forrester); certification / education program.

### 9 · Adjacent products & TAM expansion
*Done when the wedge has become a platform other products are built on.*

- **[H2·P2]** Purple-team exercise platform, the investigation console grows into live blue/purple exercises.
- **[H3·P1]** Vendor detection-testing, sell to SIEM/EDR/XDR vendors validating their own detections. High-ACV, distinct budget.
- **[H3·P2]** Managed detection-quality service / detection-content-as-a-service.
- **[H4·P2]** Detection-content marketplace; compliance-evidence product; SOAR/playbook validation; training/cyber-range upsell.

---

## The four horizons, what each delivers

**Horizon 1, Foundation & beachhead (0-3mo).** Hosted lab with saved runs; public
API + SDK; vendor-native schema export; one-click push to Splunk/Sentinel/Elastic; a
GitHub Actions app; the coverage dashboard; deeper ATT&CK coverage; a versioned
citable benchmark + leaderboard; the AI-SOC benchmark; PLG packaging & pricing v1;
the privacy/trust story.
**Exit:** a detection engineer self-serves, scores their rules, pushes a shaped
corpus into their SIEM, shows their manager a coverage heatmap, and there's a paid
tier to convert into.

**Horizon 2, Commercialize (3-9mo).** Multi-tenant workspaces & RBAC; detection
lifecycle; more languages/domains/integrations; adversary-emulation profiles;
scheduled continuous validation with regression alerts; the detection copilot; SOC 2
underway; community + design partners; co-sell partnerships.
**Exit:** a repeatable PLG-to-paid motion, 3-5 reference customers, and a content
cadence that makes the subscription sticky.

**Horizon 3, Enterprise-grade (9-18mo).** SSO/SCIM/audit; deployment options + cloud
marketplaces; SOC 2 Type II done; compliance & framework reporting; threat-intel
content SLA; the leaderboard as a recognised standard; vendor detection-testing;
analyst relations.
**Exit:** procurement-ready. Enterprise and MSSP contracts closing without
security-review or deployment blockers.

**Horizon 4, Platform & ecosystem (18mo+).** Content marketplace; managed service;
peer-benchmarking network effects; purple-team & training products; ML-training data;
the enterprise north star (interactive range, control plane, Forge) if a customer
pulls for it.
**Exit:** Endomorph is the measurement layer the detection industry is graded
against, with an ecosystem building on top.

---

## Metrics that matter

- **Adoption:** OSS stars, benchmark downloads, academic/vendor **citations**, the leading indicator.
- **Activation:** % of signups who score a rule in their first session (aim > 40%).
- **Conversion & expansion:** free → Team → Enterprise; net revenue retention.
- **Product depth:** techniques covered, domains, languages, content-refresh cadence.
- **Distribution:** connected SIEMs / CI repos per account; integrations shipped.
- **Enterprise readiness:** SOC 2, SSO, marketplace listings, design partners → logos.

## Guardrails & risks

- **Don't abandon the wedge.** Every feature must strengthen the ground-truth data moat, not just add surface.
- **Don't become a BAS clone.** Differentiate on ground-truth-by-construction + zero-infra + zero real data, what AttackIQ / SafeBreach / Cymulate structurally can't match.
- **Content freshness is a treadmill**, and the recurring reason to pay. Staff it deliberately.
- **Depth before breadth.** A benchmark trusted for 150 techniques beats a shallow 500.
- **Enterprise gravity.** Don't build SSO/VPC before design partners pull; PLG funds the enterprise build.
- **Safety boundary is absolute.** Synthetic, isolated simulation only, never real-target attack capability or credential capture.
