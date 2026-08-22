import type {
  MissionObjective,
} from "./MissionPanel";

import type {
  ScenarioOutcome,
} from "@endomorph/simulation";

import type {
  AnalystCaseState,
  IncidentCaseState,
} from "./simulationAdapter";

/**
 * Derives the run's checklist from state the run already keeps.
 *
 * Kept out of the component so Fast Refresh keeps working and so the rules
 * can be tested directly -- which matters more than usual here, because an
 * objective that marks itself done at the wrong moment is worse than no
 * checklist at all.
 *
 * Every item is satisfied by an artifact, never by navigation. Marking
 * "triage the alert" done because the alert console was opened would tell an
 * analyst they had done something when they had only looked at it.
 */

export interface MissionInputs {
  readonly analystCase: AnalystCaseState;
  readonly incidentCase: IncidentCaseState;
  readonly outcome: ScenarioOutcome;
  readonly finalized: boolean;
  readonly questionsAnswered: number;
  readonly questionsTotal: number;
  readonly techniquesEvidenced: number;
  readonly techniquesTotal: number;
  readonly entitiesInScope: number;
}

/** Enough collected events to have a case rather than a single record. */
const EVIDENCE_TARGET = 3;

export function buildMissionObjectives(
  inputs: MissionInputs,
): readonly MissionObjective[] {
  const {
    analystCase,
    incidentCase,
    outcome,
    finalized,
    questionsAnswered,
    questionsTotal,
    techniquesEvidenced,
    techniquesTotal,
    entitiesInScope,
  } = inputs;

  const evidenceCount =
    analystCase.collectedEventIds.length;

  const responsesMet =
    outcome.objectives.filter(
      (objective) => objective.met,
    ).length;

  const objectives: MissionObjective[] =
    [
      {
        id: "evidence",
        label: "Preserve the evidence",
        detail:
          "Collect the events that support your account of the incident, from search, the endpoint, or identity.",
        done:
          evidenceCount >=
          EVIDENCE_TARGET,
        progress: {
          done: Math.min(
            evidenceCount,
            EVIDENCE_TARGET,
          ),
          total: EVIDENCE_TARGET,
        },
        view: "siem",
      },
      {
        id: "scope",
        label: "Establish the scope",
        detail:
          "Put the accounts, hosts and addresses the incident touches into the case. The entity graph builds itself from what you collect.",
        done: entitiesInScope >= 2,
        view: "case",
      },
    ];

  if (questionsTotal > 0) {
    objectives.push({
      id: "questions",
      label:
        "Answer the investigation questions",
      detail:
        "Each answer is a value present somewhere in the telemetry. None can be derived from the alert alone.",
      done:
        questionsAnswered >=
        questionsTotal,
      progress: {
        done: questionsAnswered,
        total: questionsTotal,
      },
      view: "questions",
    });
  }

  if (techniquesTotal > 0) {
    objectives.push({
      id: "techniques",
      label:
        "Evidence the adversary behaviour",
      detail:
        "Collect at least one event for each technique the intrusion used, so the finding is supported rather than asserted.",
      done:
        techniquesEvidenced >=
        techniquesTotal,
      progress: {
        done: techniquesEvidenced,
        total: techniquesTotal,
      },
      view: "questions",
    });
  }

  objectives.push(
    {
      id: "hypothesis",
      label: "Record what you think happened",
      detail:
        "State a hypothesis so the evidence can support or refute it. Writing it down is what separates an investigation from a hunch.",
      done:
        incidentCase.hypotheses.length >
        0,
      view: "case",
    },
    {
      id: "containment",
      label: "Contain the incident",
      detail:
        "Perform the response operations the situation calls for. Some plausible-looking responses do not contain anything.",
      done:
        outcome.objectives.length > 0 &&
        responsesMet ===
          outcome.objectives.length,
      progress: {
        done: responsesMet,
        total: outcome.objectives.length,
      },
      view: "identity",
    },
    {
      id: "finalize",
      label: "Finalize the investigation",
      detail:
        "Close the run to score it and see how the shipped detections performed on the same telemetry.",
      done: finalized,
    },
  );

  return objectives;
}
