# Polymorph Scenario Authoring

Polymorph scenarios are versioned JSON files that describe a synthetic world, an ordered opening event history, deterministic analyst response actions, and the entities the analyst workspace should focus on.

The JSON file is untrusted input. `@polymorph/schema` validates its structure first. `@polymorph/simulation` then compiles it into `WorldState` and verifies entity references, event ordering, event semantics, and deterministic replay.

## Try the example

The browser example lives at:

```text
apps/web/public/scenarios/account-compromise.json
```

Run the web app:

```bash
pnpm install --frozen-lockfile
pnpm dev
```

Open the Vite URL, normally:

```text
http://localhost:5173/
```

## Make your own local variation

Copy the example file inside the same directory:

```bash
cp apps/web/public/scenarios/account-compromise.json apps/web/public/scenarios/my-scenario.json
```

On PowerShell:

```powershell
Copy-Item apps/web/public/scenarios/account-compromise.json apps/web/public/scenarios/my-scenario.json
```

Then open:

```text
http://localhost:5173/?scenario=/scenarios/my-scenario.json
```

The query parameter is intentionally restricted to files under `/scenarios/`.

## Good first edits

You can safely experiment with synthetic presentation and telemetry values such as:

- `scenario.name` and `scenario.description`
- organization, user, account, device, and application display names
- the synthetic username and email address
- endpoint hostname and operating-system label
- documentation/example IP ranges such as `192.0.2.0/24`, `198.51.100.0/24`, and `203.0.113.0/24`
- event timestamps, as long as the history remains chronological
- alert title and severity
- process image/command-line text, keeping commands synthetic and non-executable
- action label and description

If you change an entity or event **id**, update every reference to that id as well.

## File shape

Every scenario file starts with a versioned envelope:

```json
{
  "version": 1,
  "kind": "polymorph-scenario",
  "scenario": {
    "id": "scenario-example",
    "name": "Example scenario",
    "description": "What the analyst is investigating.",
    "initialWorld": {},
    "openingEvents": [],
    "actions": [],
    "investigation": {}
  }
}
```

### `initialWorld`

The initial world is an author-friendly seed with arrays of:

- organizations
- users
- accounts
- devices
- files
- applications
- sessions

Polymorph normalizes those arrays into canonical `WorldState` records during compilation.

### `openingEvents`

Opening events are the deterministic history that exists when the analyst begins the scenario.

Current event types are:

- `AUTH_LOGIN_SUCCEEDED`
- `AUTH_LOGIN_FAILED`
- `ACCOUNT_DISABLED`
- `ACCOUNT_ENABLED`
- `SESSION_STARTED`
- `SESSION_REVOKED`
- `PROCESS_STARTED`
- `FILE_ACCESSED`
- `NETWORK_CONNECTION`
- `ENDPOINT_HEARTBEAT`
- `ALERT_CREATED`

Events must have unique ids and non-decreasing timestamps. Entity references must exist at the point the event is replayed.

### `actions`

Actions are deterministic response choices. Each action has:

- `id`
- `label`
- `description`
- one or more events that are appended when the action is performed

The first playable workspace currently exposes one primary action, but the runtime can represent multiple actions.

### `investigation`

The current analyst workspace needs a focus block:

```json
{
  "alertId": "alert-example",
  "userId": "user-example",
  "accountId": "account-example",
  "deviceId": "device-example",
  "sessionId": "session-example",
  "primaryActionId": "contain_incident"
}
```

Those ids must resolve after the opening event history has been replayed. `alertId` must identify an opening `ALERT_CREATED` event, and `primaryActionId` must identify a declared scenario action.

## Validation feedback

If the browser cannot parse or semantically compile a scenario, it shows a validation error instead of starting the investigation. Fix the JSON and press **Retry scenario** or refresh the page.

Before sharing a scenario change, run:

```bash
pnpm build
pnpm lint
pnpm test:run
```

The automated tests also read and compile the shipped account-compromise JSON file so the example cannot silently drift away from the runtime contract.

## Safety boundary

Scenario content must remain synthetic. Do not add real credentials, secrets, private customer data, or arbitrary executable host commands. Command-line telemetry is descriptive simulation data only; Polymorph does not execute scenario-authored shell commands.
