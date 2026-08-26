import {
  useEffect,
  useMemo,
  useState,
} from "react";

import type {
  ScenarioDefinition,
} from "./simulationAdapter";

import "./AttackStoryboard.css";

/**
 * The attack, as a movie.
 *
 * A scenario's ground truth is an ordered kill chain, each step already has a
 * title, a technique, and a line of narration explaining what happened and why
 * it matters. This plays that chain like a storyboard: one scene at a time,
 * auto-advancing, with the ATT&CK tactics lighting up as the intrusion moves
 * through them. It makes an abstract "T1059.001 was observed" land as a story a
 * person watches unfold, which is the fastest way to make the data tangible.
 */

const SCENE_MS = 5600;

const TACTIC_LABELS: Readonly<
  Record<string, string>
> = {
  initial_access: "Initial Access",
  execution: "Execution",
  persistence: "Persistence",
  privilege_escalation:
    "Priv. Escalation",
  defense_evasion: "Defense Evasion",
  credential_access: "Cred. Access",
  discovery: "Discovery",
  lateral_movement: "Lateral Movement",
  collection: "Collection",
  command_and_control: "C2",
  exfiltration: "Exfiltration",
  impact: "Impact",
};

interface TimelineStep {
  readonly eventId: string;
  readonly title?: string;
  readonly significance?: string;
  readonly techniqueId?: string;
}

interface TechniqueMeta {
  readonly id: string;
  readonly name: string;
  readonly tactic: string;
}

interface Scene {
  readonly title: string;
  readonly narration: string;
  readonly techniqueId?: string;
  readonly techniqueName?: string;
  readonly tactic?: string;
}

export function AttackStoryboard({
  scenario,
}: {
  readonly scenario: ScenarioDefinition;
}) {
  const scenes = useMemo<Scene[]>(() => {
    const groundTruth =
      (scenario.groundTruth ?? {}) as {
        timeline?: readonly TimelineStep[];
        techniques?: readonly TechniqueMeta[];
      };

    const techniques = new Map(
      (
        groundTruth.techniques ?? []
      ).map((technique) => [
        technique.id,
        technique,
      ]),
    );

    return (groundTruth.timeline ?? []).map(
      (step) => {
        const meta = step.techniqueId
          ? techniques.get(
              step.techniqueId,
            )
          : undefined;

        return {
          title:
            step.title ??
            "Attack step",
          narration:
            step.significance ?? "",
          techniqueId: step.techniqueId,
          techniqueName: meta?.name,
          tactic: meta?.tactic,
        };
      },
    );
  }, [scenario]);

  const [current, setCurrent] =
    useState(0);
  const [playing, setPlaying] =
    useState(false);

  // Reset when the scenario changes.
  useEffect(() => {
    setCurrent(0);
    setPlaying(false);
  }, [scenario]);

  useEffect(() => {
    if (!playing) {
      return;
    }

    if (current >= scenes.length - 1) {
      setPlaying(false);
      return;
    }

    const id = window.setTimeout(() => {
      setCurrent((value) => value + 1);
    }, SCENE_MS);

    return () => window.clearTimeout(id);
  }, [playing, current, scenes.length]);

  // Order the rail by when each tactic first appears in *this* attack, not by
  // the canonical ATT&CK order, a real intrusion doesn't visit tactics in
  // textbook sequence, and the storyboard tells this attack's story.
  const { tacticsInPlay, firstIndex } =
    useMemo(() => {
      const first = new Map<
        string,
        number
      >();
      scenes.forEach((scene, index) => {
        if (
          scene.tactic &&
          !first.has(scene.tactic)
        ) {
          first.set(scene.tactic, index);
        }
      });
      return {
        tacticsInPlay: [...first.keys()],
        firstIndex: first,
      };
    }, [scenes]);

  if (scenes.length === 0) {
    return null;
  }

  const scene = scenes[current];

  return (
    <section
      className="story"
      aria-label="Attack storyboard"
    >
      <div className="story-head">
        <p className="eyebrow">
          Attack storyboard
        </p>
        <h3>Watch the intrusion unfold</h3>
      </div>

      {/* kill-chain rail */}
      <div className="story-rail">
        {tacticsInPlay.map((tactic) => {
          const state =
            tactic === scene.tactic
              ? "active"
              : (firstIndex.get(tactic) ??
                    0) < current
                ? "past"
                : "future";
          return (
            <div
              key={tactic}
              className={`story-rail-node ${state}`}
            >
              <span className="story-rail-dot" />
              <span className="story-rail-label">
                {TACTIC_LABELS[tactic] ??
                  tactic}
              </span>
            </div>
          );
        })}
      </div>

      {/* the scene */}
      <div className="story-stage">
        <div
          key={current}
          className="story-scene"
        >
          <div className="story-scene-top">
            <span className="story-step">
              Step {current + 1} /{" "}
              {scenes.length}
            </span>
            {scene.tactic && (
              <span className="story-tactic">
                {TACTIC_LABELS[
                  scene.tactic
                ] ?? scene.tactic}
              </span>
            )}
            {scene.techniqueId && (
              <span className="story-technique">
                {scene.techniqueId}
                {scene.techniqueName
                  ? ` · ${scene.techniqueName}`
                  : ""}
              </span>
            )}
          </div>

          <h4 className="story-title">
            {scene.title}
          </h4>
          <p className="story-narration">
            {scene.narration}
          </p>
        </div>

        <div
          className={`story-progress ${
            playing ? "running" : ""
          }`}
          key={`${current}-${playing}`}
          style={{
            animationDuration: `${SCENE_MS}ms`,
          }}
        />
      </div>

      {/* controls */}
      <div className="story-controls">
        <button
          type="button"
          className="story-btn"
          aria-label="Previous step"
          disabled={current === 0}
          onClick={() => {
            setPlaying(false);
            setCurrent((value) =>
              Math.max(0, value - 1),
            );
          }}
        >
          ⏮
        </button>

        <button
          type="button"
          className="story-btn story-play"
          onClick={() => {
            if (
              current >=
              scenes.length - 1
            ) {
              setCurrent(0);
              setPlaying(true);
            } else {
              setPlaying(
                (value) => !value,
              );
            }
          }}
        >
          {playing ? "⏸ Pause" : "▶ Play the attack"}
        </button>

        <button
          type="button"
          className="story-btn"
          aria-label="Next step"
          disabled={
            current >= scenes.length - 1
          }
          onClick={() => {
            setPlaying(false);
            setCurrent((value) =>
              Math.min(
                scenes.length - 1,
                value + 1,
              ),
            );
          }}
        >
          ⏭
        </button>

        <div className="story-dots">
          {scenes.map((_, index) => (
            <button
              key={index}
              type="button"
              aria-label={`Go to step ${index + 1}`}
              className={`story-dot ${
                index === current
                  ? "on"
                  : index < current
                    ? "seen"
                    : ""
              }`}
              onClick={() => {
                setPlaying(false);
                setCurrent(index);
              }}
            />
          ))}
        </div>
      </div>
    </section>
  );
}
