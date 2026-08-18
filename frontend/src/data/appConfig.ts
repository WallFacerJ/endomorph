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
          id: "alert-table",
          type: "table",
          title: "Recent Alerts",
          columns: [
            { key: "severity", label: "Severity" },
            { key: "host", label: "Host" },
            { key: "event", label: "Event" },
          ],
          rows: [
            {
              severity: "Critical",
              host: "WIN-CLIENT-01",
              event: "Suspicious PowerShell execution",
            },
            {
              severity: "High",
              host: "WEB-SERVER-02",
              event: "Multiple failed logins",
            },
            {
              severity: "Medium",
              host: "HR-LAPTOP-04",
              event: "Unsigned executable detected",
            },
          ],
        },

        {
          id: "investigate-button",
          type: "button",
          label: "Start Investigation",
          action: "start_investigation",
        },
      ],
    },

    {
      id: "endpoints",
      name: "Endpoints",
      components: [
        {
          id: "endpoint-table",
          type: "table",
          title: "Managed Endpoints",
          columns: [
            { key: "hostname", label: "Hostname" },
            { key: "os", label: "Operating System" },
            { key: "status", label: "Status" },
          ],
          rows: [
            {
              hostname: "WIN-CLIENT-01",
              os: "Windows 11",
              status: "Online",
            },
            {
              hostname: "WEB-SERVER-02",
              os: "Ubuntu Server",
              status: "Online",
            },
            {
              hostname: "HR-LAPTOP-04",
              os: "Windows 11",
              status: "Offline",
            },
          ],
        },
      ],
    },

    {
      id: "terminal",
      name: "Terminal",
      components: [
        {
          id: "terminal-window",
          type: "terminal",
          title: "Investigation Console",
          lines: [
            "Polymorph Simulation Console",
            "Connected to synthetic environment",
            "Type 'help' to view available simulated commands",
          ],
        },
      ],
    },
  ],
};