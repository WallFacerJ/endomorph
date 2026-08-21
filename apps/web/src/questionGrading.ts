import type {
  ScenarioQuestion,
} from "./simulationAdapter";

/**
 * Answer checking for investigation questions.
 *
 * Deterministic and forgiving about presentation but not about substance:
 * surrounding whitespace and letter case are ignored, nothing else is. An
 * analyst who found 91.219.236.18 should not lose the point for typing it
 * with a trailing space, and one who guessed a different address should not
 * gain it.
 *
 * Lives outside the component module so React Fast Refresh keeps working
 * and so grading can be tested directly.
 */
export function isAnswerAccepted(
  question: ScenarioQuestion,
  answer: string,
): boolean {
  const normalized = answer
    .trim()
    .toLowerCase();

  if (normalized.length === 0) {
    return false;
  }

  return question.accepted.some(
    (candidate) =>
      candidate.trim().toLowerCase() ===
      normalized,
  );
}

export interface QuestionGrade {
  question: ScenarioQuestion;
  answered: boolean;
  correct: boolean;
}

export interface QuestionScore {
  grades: readonly QuestionGrade[];
  earned: number;
  available: number;
  answeredCount: number;
  percentage: number;
}

export function gradeQuestions(
  questions: readonly ScenarioQuestion[],
  answers: Readonly<
    Record<string, string>
  >,
): QuestionScore {
  const grades = questions.map(
    (question) => ({
      question,
      answered: Boolean(
        answers[question.id]?.trim(),
      ),
      correct: isAnswerAccepted(
        question,
        answers[question.id] ?? "",
      ),
    }),
  );

  const earned = grades
    .filter((grade) => grade.correct)
    .reduce(
      (total, grade) =>
        total + grade.question.points,
      0,
    );

  const available = questions.reduce(
    (total, question) =>
      total + question.points,
    0,
  );

  return {
    grades,
    earned,
    available,
    answeredCount: grades.filter(
      (grade) => grade.answered,
    ).length,
    percentage:
      available === 0
        ? 0
        : Math.round(
            (earned / available) * 100,
          ),
  };
}
