import { z } from "zod";

export * from "./scenario";

export const componentTypeSchema = z.enum([
  "stat_card",
  "table",
  "alert",
  "button",
  "form",
  "terminal",
]);

export const actionTypeSchema = z.enum([
  "show_message",
  "update_value",
  "add_terminal_line",
]);

export const tableColumnSchema = z.object({
  key: z.string(),
  label: z.string(),
});

const scalarValueSchema = z.union([
  z.string(),
  z.number(),
]);

export const appActionSchema = z.object({
  id: z.string(),
  type: actionTypeSchema,

  targetId: z.string().optional(),
  message: z.string().optional(),
  value: scalarValueSchema.optional(),
  line: z.string().optional(),
});

export const appComponentSchema = z.object({
  id: z.string(),
  type: componentTypeSchema,

  title: z.string().optional(),
  value: scalarValueSchema.optional(),
  content: z.string().optional(),

  columns: z.array(tableColumnSchema).optional(),
  rows: z
    .array(
      z.record(
        z.string(),
        scalarValueSchema,
      ),
    )
    .optional(),

  label: z.string().optional(),
  actionIds: z.array(z.string()).optional(),

  lines: z.array(z.string()).optional(),
});

export const appPageSchema = z.object({
  id: z.string(),
  name: z.string(),
  components: z.array(appComponentSchema),
});

export const appSpecSchema = z.object({
  name: z.string(),
  actions: z.array(appActionSchema),
  pages: z.array(appPageSchema),
});

export type ComponentType =
  z.infer<typeof componentTypeSchema>;

export type ActionType =
  z.infer<typeof actionTypeSchema>;

export type TableColumn =
  z.infer<typeof tableColumnSchema>;

export type AppAction =
  z.infer<typeof appActionSchema>;

export type AppComponent =
  z.infer<typeof appComponentSchema>;

export type AppPage =
  z.infer<typeof appPageSchema>;

export type AppSpec =
  z.infer<typeof appSpecSchema>;

export function parseAppSpec(
  input: unknown,
): AppSpec {
  return appSpecSchema.parse(input);
}
