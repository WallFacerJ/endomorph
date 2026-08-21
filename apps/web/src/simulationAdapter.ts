export {
  addAnalystFinding,
  collectAnalystEvidence,
  compileScenarioDefinition,
  createAnalystCaseState,
  edrProjection,
  finalizeScenarioState,
  getScenarioState,
  identityProjection,
  rebuildProjection,
  resolveCollectedEvidence,
  searchSiem,
  siemProjection,
} from "@polymorph/simulation";

export type {
  ScenarioAction,
  ScenarioDefinition,
  ScenarioOutcomeStatus,
  ScenarioScore,
  ScenarioState,
  SiemEventRecord,
  SiemSearchRequest,
  SiemSearchResult,
} from "@polymorph/simulation";
