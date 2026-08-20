// Keep simulation imports centralized until the web package formally
// consumes @polymorph/simulation as a workspace dependency.
export {
  compileScenarioDefinition,
} from "../../../packages/simulation/src/scenarioCompiler.ts";

export {
  getScenarioState,
} from "../../../packages/simulation/src/scenario.ts";

export type {
  ScenarioDefinition,
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
