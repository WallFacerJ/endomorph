// Keep the prototype's simulation imports centralized until the web package
// formally consumes @polymorph/simulation as a workspace dependency.
export {
  accountCompromiseScenario,
  accountCompromiseScenarioIds,
} from "../../../packages/simulation/src/accountCompromiseScenario.ts";

export {
  getScenarioState,
} from "../../../packages/simulation/src/scenario.ts";

export {
  rebuildProjection,
} from "../../../packages/simulation/src/projection.ts";

export {
  identityProjection,
} from "../../../packages/simulation/src/identityProjection.ts";

export {
  edrProjection,
} from "../../../packages/simulation/src/edrProjection.ts";

export {
  siemProjection,
} from "../../../packages/simulation/src/siemProjection.ts";
