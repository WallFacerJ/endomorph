export type ComponentType =
  | "stat_card"
  | "table"
  | "alert"
  | "button"
  | "form"
  | "terminal";

export type ActionType =
  | "show_message"
  | "update_value"
  | "add_terminal_line";

export interface TableColumn {
  key: string;
  label: string;
}

export interface AppAction {
  id: string;
  type: ActionType;

  targetId?: string;

  message?: string;

  value?: string | number;

  line?: string;
}

export interface AppComponent {
  id: string;
  type: ComponentType;

  title?: string;
  value?: string | number;
  content?: string;

  columns?: TableColumn[];
  rows?: Record<string, string | number>[];

  label?: string;
  actionIds?: string[];

  lines?: string[];
}

export interface AppPage {
  id: string;
  name: string;
  components: AppComponent[];
}

export interface AppSpec {
  name: string;

  actions: AppAction[];

  pages: AppPage[];
}