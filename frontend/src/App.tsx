import "./App.css";
import { appConfig } from "./data/appConfig";

function App() {
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <h1>{appConfig.name}</h1>

        <nav>
          {appConfig.navigation.map((item) => (
            <button key={item} className="nav-item">
              {item}
            </button>
          ))}
        </nav>
      </aside>

      <main className="main-content">
        <h2>Dashboard</h2>
        <p>Polymorph renderer is running.</p>
      </main>
    </div>
  );
}

export default App;