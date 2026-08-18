# Polymorph

Polymorph is a deterministic, schema-driven cybersecurity simulation platform for building interconnected synthetic enterprise environments and replayable security scenarios.

Rather than generating a separate hardcoded application for each prompt, Polymorph is being designed as a reusable runtime with a shared synthetic world, event-driven behavior, multiple application projections, scenario replay, and controlled AI-assisted environment generation.

## Project Goals

Polymorph aims to support:

- Synthetic organizations, users, accounts, devices, files, sessions, and applications
- Multiple simulated applications backed by one shared world state
- Deterministic scenarios using a virtual clock and seeded randomness
- Append-only security and business events with replayable projections
- SIEM, EDR, identity, email, cloud, HR, and other application views over shared data
- Scenario authoring, validation, snapshots, replay, scoring, and ground truth
- Capability-based authorization for simulated users and analysts
- A plugin SDK for extending applications and event projections
- Headless execution through an API and CLI
- AI-assisted compilation from natural language into validated Polymorph specifications
- Strict simulation boundaries: synthetic data only, no credential harvesting, and no arbitrary generated host execution

## What Polymorph Is Not

Polymorph is not intended to be:

- An AI website generator
- A phishing kit
- A credential-capture system
- An arbitrary code execution framework
- A collection of disconnected fake dashboards

## Current Status

The repository currently contains a React + TypeScript + Vite prototype that demonstrates schema-driven pages, reusable components, a behavior engine, and chained actions.

The next architectural milestone is to convert the repository into a pnpm workspace/monorepo and separate the UI from the domain, schema, and simulation runtimes.

See [PROJECT_STATE.md](PROJECT_STATE.md), [ROADMAP.md](ROADMAP.md), and [ARCHITECTURE.md](ARCHITECTURE.md) for the current plan and design direction.
