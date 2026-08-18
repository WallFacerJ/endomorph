import type { AppSpec } from "../schemas/appSchema";

export const appConfig: AppSpec = {
  name: "Polymorph Security Console",

  pages: [
    {
      id: "dashboard",
      name: "Dashboard",
      components: [
        {
          id: "active-alerts",
          type: "stat_card",
          title: "Active Alerts",
          value: 17,
        },
        {
          id: "endpoints",
          type: "stat_card",
          title: "Endpoints",
          value: 143,
        },
        {
          id: "system-status",
          type: "alert",
          title: "System Status",
          content: "All monitoring services are operational.",
        },
      ],
    },
    {
      id: "alerts",
      name: "Alerts",
      components: [
        {
          id: "critical-alert",
          type: "alert",
          title: "Critical Alert",
          content: "Suspicious PowerShell execution detected.",
        },
      ],
    },
    {
      id: "endpoints",
      name: "Endpoints",
      components: [],
    },
  ],
};