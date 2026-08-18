import { useState } from "react";
import type { AppComponent } from "../schemas/appSchema";

interface ComponentRendererProps {
  component: AppComponent;
}

function ComponentRenderer({ component }: ComponentRendererProps) {
  const [message, setMessage] = useState("");

  const handleAction = () => {
    if (component.action === "start_investigation") {
      setMessage("Investigation started successfully.");
    }
  };

  switch (component.type) {
    case "stat_card":
      return (
        <div className="card">
          <h3>{component.title}</h3>
          <div className="stat-value">{component.value}</div>
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
                  <th key={column.key}>{column.label}</th>
                ))}
              </tr>
            </thead>

            <tbody>
              {component.rows?.map((row, rowIndex) => (
                <tr key={rowIndex}>
                  {component.columns?.map((column) => (
                    <td key={column.key}>{row[column.key]}</td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      );

    case "button":
      return (
        <div className="card">
          <button className="action-button" onClick={handleAction}>
            {component.label}
          </button>

          {message && <p className="action-message">{message}</p>}
        </div>
      );

    case "terminal":
      return (
        <div className="terminal">
          <div className="terminal-header">{component.title}</div>

          <div className="terminal-body">
            {component.lines?.map((line, index) => (
              <div key={index}>
                <span className="terminal-prompt">$</span> {line}
              </div>
            ))}
          </div>
        </div>
      );

    default:
      return (
        <div className="card">
          <p>Unsupported component: {component.type}</p>
        </div>
      );
  }
}

export default ComponentRenderer;