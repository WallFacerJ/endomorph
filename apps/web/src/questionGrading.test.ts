import {
  describe,
  expect,
  it,
} from "vitest";

import {
  gradeQuestions,
  isAnswerAccepted,
} from "./questionGrading";

import type {
  ScenarioQuestion,
} from "./simulationAdapter";

const question: ScenarioQuestion = {
  id: "q",
  prompt: "Source address?",
  accepted: ["91.219.236.18"],
  surface: "siem",
  points: 20,
};

describe("isAnswerAccepted", () => {
  it("accepts the exact answer", () => {
    expect(
      isAnswerAccepted(
        question,
        "91.219.236.18",
      ),
    ).toBe(true);
  });

  it("ignores surrounding whitespace and case", () => {
    // Presentation should not cost a point that was genuinely earned.
    expect(
      isAnswerAccepted(
        question,
        "  91.219.236.18  ",
      ),
    ).toBe(true);

    expect(
      isAnswerAccepted(
        { ...question, accepted: ["FIN-LT-004"] },
        "fin-lt-004",
      ),
    ).toBe(true);
  });

  it("rejects a different value", () => {
    expect(
      isAnswerAccepted(
        question,
        "91.219.236.19",
      ),
    ).toBe(false);
  });

  it("rejects an empty or whitespace answer", () => {
    expect(
      isAnswerAccepted(question, ""),
    ).toBe(false);

    expect(
      isAnswerAccepted(question, "   "),
    ).toBe(false);
  });

  it("rejects a partial match", () => {
    // Substring credit would let an analyst guess a prefix.
    expect(
      isAnswerAccepted(
        question,
        "91.219",
      ),
    ).toBe(false);
  });

  it("accepts any listed alternative", () => {
    expect(
      isAnswerAccepted(
        {
          ...question,
          accepted: ["FS-01", "fs-01"],
        },
        "FS-01",
      ),
    ).toBe(true);
  });
});

describe("gradeQuestions", () => {
  const questions: ScenarioQuestion[] = [
    question,
    {
      id: "q2",
      prompt: "Host?",
      accepted: ["FIN-LT-004"],
      surface: "endpoint",
      points: 10,
    },
  ];

  it("awards points only for correct answers", () => {
    const score = gradeQuestions(
      questions,
      {
        q: "91.219.236.18",
        q2: "WRONG-HOST",
      },
    );

    expect(score.earned).toBe(20);
    expect(score.available).toBe(30);
    expect(score.percentage).toBe(67);
    expect(score.answeredCount).toBe(2);
  });

  it("counts an answered-but-wrong question as answered", () => {
    // Progress and correctness are different questions; professional runs
    // show the first and withhold the second until finalization.
    const score = gradeQuestions(
      questions,
      { q: "nope" },
    );

    expect(score.answeredCount).toBe(1);
    expect(score.earned).toBe(0);
  });

  it("scores an empty submission at zero", () => {
    const score = gradeQuestions(
      questions,
      {},
    );

    expect(score.earned).toBe(0);
    expect(score.percentage).toBe(0);
    expect(score.answeredCount).toBe(0);
  });

  it("scores a full submission at 100", () => {
    expect(
      gradeQuestions(questions, {
        q: "91.219.236.18",
        q2: "fin-lt-004",
      }).percentage,
    ).toBe(100);
  });

  it("handles a scenario with no questions", () => {
    const score = gradeQuestions([], {});

    expect(score.available).toBe(0);
    expect(score.percentage).toBe(0);
    expect(score.grades).toEqual([]);
  });
});
