export type ComponentType =
  | "stat_card"
  | "table"
  | "alert"
  | "button"
  | "form"
  | "terminal";

export interface AppComponent {
  id: string;
  type: ComponentType;
  title?: string;
  value?: string | number;
  content?: string;
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