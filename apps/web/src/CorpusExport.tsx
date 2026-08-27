import { useMemo, useState } from "react";

import {
  formatCorpus,
  CORPUS_FORMATS,
  extensionFor,
} from "@endomorph/fabric";

import type {
  CorpusFormat,
} from "@endomorph/fabric";

import {
  buildScenarioCorpus,
} from "./detectionReview";

import type {
  ScenarioDefinition,
} from "./simulationAdapter";

import "./CorpusExport.css";

/**
 * Download this scenario's labelled corpus in a SIEM's own format, so a
 * detection engineer can ingest it into their real Splunk, Elastic, or Sentinel
 * and test their detections in the stack they actually run, not only in the
 * browser. The ground-truth labels travel with the data, which is the whole
 * point of moving a corpus somewhere else: the answers come with it.
 */

const FORMAT_LABELS: Readonly<
  Record<CorpusFormat, string>
> = {
  ecs: "Elastic Common Schema (ECS)",
  splunk: "Splunk (CIM-style)",
  elastic: "Elastic bulk (_bulk)",
  sentinel: "Microsoft Sentinel (JSON)",
  ocsf: "OCSF (Security Lake / open schema)",
};

export function CorpusExport({
  scenario,
  scenarioLabel,
}: {
  readonly scenario: ScenarioDefinition;
  readonly scenarioLabel: string;
}) {
  const records = useMemo(
    () => buildScenarioCorpus(scenario),
    [scenario],
  );

  const [format, setFormat] =
    useState<CorpusFormat>("ecs");

  const download = () => {
    const body = formatCorpus(records, {
      format,
    });
    const blob = new Blob([body], {
      type:
        format === "sentinel"
          ? "application/json"
          : "application/x-ndjson",
    });
    const url =
      URL.createObjectURL(blob);
    const link =
      document.createElement("a");
    link.href = url;
    link.download = `${scenarioLabel
      .toLowerCase()
      .replace(
        /[^a-z0-9]+/g,
        "-",
      )
      .replace(
        /^-|-$/g,
        "",
      )}-${format}${extensionFor(format)}`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  return (
    <section
      className="cx"
      aria-label="Export corpus"
    >
      <div className="cx-copy">
        <span className="cx-label">
          Take the data with you
        </span>
        <span className="cx-sub">
          Download this scenario's{" "}
          <strong>
            {records.length.toLocaleString()}
          </strong>{" "}
          labelled records, ground truth
          included, and ingest them into
          your own SIEM to test detections
          in your stack.
        </span>
      </div>
      <div className="cx-controls">
        <select
          className="cx-format"
          aria-label="Export format"
          value={format}
          onChange={(event) =>
            setFormat(
              event.target
                .value as CorpusFormat,
            )
          }
        >
          {CORPUS_FORMATS.map((value) => (
            <option
              key={value}
              value={value}
            >
              {FORMAT_LABELS[value]}
            </option>
          ))}
        </select>
        <button
          type="button"
          className="cx-download"
          onClick={download}
        >
          Download corpus
        </button>
      </div>
    </section>
  );
}
