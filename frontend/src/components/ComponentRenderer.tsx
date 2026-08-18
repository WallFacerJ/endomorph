import type { AppComponent } from "../schemas/appSchema";

interface ComponentRendererProps {
  component: AppComponent;
}

function ComponentRenderer({ component }: ComponentRendererProps) {
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

    default:
      return (
        <div className="card">
          <p>Unsupported component: {component.type}</p>
        </div>
      );
  }
}

export default ComponentRenderer;