import { useState } from "react";

import "./App.css";

import { appConfig } from "./data/appConfig";

import ComponentRenderer from "./components/ComponentRenderer";

import { executeAction } from "./engine/behaviorEngine";

function App() {
  const [activePageId, setActivePageId] = useState(
    appConfig.pages[0].id
  );

  const [componentValues, setComponentValues] = useState<
    Record<string, string | number>
  >({});

  const [terminalLines, setTerminalLines] = useState<
    Record<string, string[]>
  >({});

  const [message, setMessage] = useState("");

  const activePage = appConfig.pages.find(
    (page) => page.id === activePageId
  );

  const handleAction = (actionId: string) => {
    const action = appConfig.actions.find(
      (action) => action.id === actionId
    );

    if (!action) {
      return;
    }

    const result = executeAction(action);

    if (result.message) {
      setMessage(result.message);
    }

    if (
      result.targetId &&
      result.newValue !== undefined
    ) {
      setComponentValues((current) => ({
        ...current,
        [result.targetId!]: result.newValue!,
      }));
    }

    if (
      result.targetId &&
      result.terminalLine
    ) {
      setTerminalLines((current) => ({
        ...current,

        [result.targetId!]: [
          ...(current[result.targetId!] ?? []),
          result.terminalLine!,
        ],
      }));
    }
  };

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <h1>{appConfig.name}</h1>

        <nav>
          {appConfig.pages.map((page) => (
            <button
              key={page.id}
              className="nav-item"
              onClick={() => setActivePageId(page.id)}
            >
              {page.name}
            </button>
          ))}
        </nav>
      </aside>

      <main className="main-content">
        <h2>{activePage?.name}</h2>

        {message && (
          <div className="global-message">
            {message}
          </div>
        )}

        <div className="component-grid">
          {activePage?.components.map((component) => (
            <ComponentRenderer
              key={component.id}
              component={component}
              runtimeValue={
                componentValues[component.id]
              }
              runtimeTerminalLines={
                terminalLines[component.id]
              }
              onAction={handleAction}
            />
          ))}
        </div>
      </main>
    </div>
  );
}

export default App;