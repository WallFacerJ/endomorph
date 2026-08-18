import type { AppAction } from "@polymorph/schema";

export interface BehaviorResult {
  message?: string;

  targetId?: string;

  newValue?: string | number;

  terminalLine?: string;
}

export function executeAction(action: AppAction): BehaviorResult {
  switch (action.type) {
    case "show_message":
      return {
        message: action.message,
      };

    case "update_value":
      return {
        targetId: action.targetId,
        newValue: action.value,
      };

    case "add_terminal_line":
      return {
        targetId: action.targetId,
        terminalLine: action.line,
      };

    default:
      return {};
  }
}