import { useState } from "react";
import "./App.css";
import { appConfig } from "./data/appConfig";
import ComponentRenderer from "./components/ComponentRenderer";

function App() {
  const [activePageId, setActivePageId] = useState(appConfig.pages[0].id);

  const activePage = appConfig.pages.find(
    (page) => page.id === activePageId
  );

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

        <div className="component-grid">
          {activePage?.components.map((component) => (
            <ComponentRenderer
              key={component.id}
              component={component}
            />
          ))}
        </div>
      </main>
    </div>
  );
}

export default App;