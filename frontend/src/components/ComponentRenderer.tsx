import type { AppComponent } from "../schemas/appSchema";

interface ComponentRendererProps {
  component: AppComponent;

  runtimeValue?: string | number;

  runtimeTerminalLines?: string[];

  onActions: (actionIds: string[]) => void;
}

function ComponentRenderer({
  component,
  runtimeValue,
  runtimeTerminalLines,
  onActions,
}: ComponentRendererProps) {
  switch (component.type) {
    case "stat_card":
      return (
        <div className="card">
          <h3>{component.title}</h3>

          <div className="stat-value">
            {runtimeValue ?? component.value}
          </div>
        </div>
      );

    case "alert":
      return (
        <div className="card">
          <h3>{component.title}</h3>
          <p>{component.content}</p>
        </div>
      );

    case "table":
      return (
        <div className="card table-card">
          <h3>{component.title}</h3>

          <table>
            <thead>
              <tr>
                {component.columns?.map((column) => (
                  <th key={column.key}>
                    {column.label}
                  </th>
                ))}
              </tr>
            </thead>

            <tbody>
              {component.rows?.map(
                (row, rowIndex) => (
                  <tr key={rowIndex}>
                    {component.columns?.map(
                      (column) => (
                        <td key={column.key}>
                          {row[column.key]}
                        </td>
                      )
                    )}
                  </tr>
                )
              )}
            </tbody>
          </table>
        </div>
      );

    case "button":
  return (
    <div className="card">
      <button
        className="action-button"
        onClick={() => {
          if (component.actionIds) {
            onActions(component.actionIds);
          }
        }}
      >
        {component.label}
      </button>
    </div>
  );

    case "terminal": {
      const lines = [
        ...(component.lines ?? []),
        ...(runtimeTerminalLines ?? []),
      ];

      return (
        <div className="terminal">
          <div className="terminal-header">
            {component.title}
          </div>

          <div className="terminal-body">
            {lines.map((line, index) => (
              <div key={index}>
                <span className="terminal-prompt">
                  $
                </span>{" "}
                {line}
              </div>
            ))}
          </div>
        </div>
      );
    }

    default:
      return (
        <div className="card">
          <p>
            Unsupported component:
            {" "}
            {component.type}
          </p>
        </div>
      );
  }
}

export default ComponentRenderer;