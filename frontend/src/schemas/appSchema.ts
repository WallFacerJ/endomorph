export type ComponentType =
  | "stat_card"
  | "table"
  | "alert"
  | "button"
  | "form"
  | "terminal";

export interface TableColumn {
  key: string;
  label: string;
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
  action?: string;

  lines?: string[];
}

export interface AppPage {
  id: string;
  name: string;
  components: AppComponent[];
}

export interface AppSpec {
  name: string;
  pages: AppPage[];
}