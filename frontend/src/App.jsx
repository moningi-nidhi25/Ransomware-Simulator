
import { useEffect, useState } from "react";
import "./App.css";

const API = "http://127.0.0.1:8000";

export default function App() {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function loadAlerts() {
    try {
      const response = await fetch(`${API}/api/alerts`);
      if (!response.ok) throw new Error("Could not load alerts");
      setAlerts(await response.json());
      setError("");
    } catch {
      setError("Backend unavailable. Start the FastAPI server first.");
    }
  }

  async function runSimulation(scenario) {
    setLoading(true);
    setError("");

    try {
      const response = await fetch(
        `${API}/api/simulate/${scenario}`,
        { method: "POST" }
      );

      if (!response.ok) throw new Error("Simulation failed");

      const result = await response.json();
      if (result.error) throw new Error(result.error);

      await loadAlerts();
    } catch (err) {
      setError(err.message || "Could not run simulation");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
  let ignore = false;

  async function fetchInitialAlerts() {
    try {
      const response = await fetch(
        "http://127.0.0.1:8000/api/alerts"
      );

      if (!response.ok) {
        throw new Error("Failed to fetch alerts");
      }

      const data = await response.json();

      if (!ignore) {
        setAlerts(data);
        setError("");
      }
    } catch {
      if (!ignore) {
        setError("Could not load alerts. Check the backend.");
      }
    }
  }

  fetchInitialAlerts();

  return () => {
    ignore = true;
  };
}, []);

  const highAlerts = alerts.filter(
    (alert) => alert.severity === "High"
  ).length;

  return (
    <main className="dashboard">
      <header>
        <div className="brand">RansomShield</div>
        <span className="status">● Simulation Mode</span>
      </header>

      <section className="intro">
        <p className="eyebrow">CYBERSECURITY MONITOR</p>
        <h1>Ransomware Detection Dashboard</h1>
        <p>
          Simulate file activity, identify suspicious patterns,
          and review security alerts.
        </p>
      </section>

      <section className="stats">
        <article className="stat">
          <span>Total Events</span>
          <strong>{alerts.length}</strong>
        </article>
        <article className="stat">
          <span>High-Severity Alerts</span>
          <strong>{highAlerts}</strong>
        </article>
        <article className="stat">
          <span>Normal Events</span>
          <strong>
            {alerts.filter((a) => a.scenario === "normal").length}
          </strong>
        </article>
      </section>

      <section className="panel">
        <h2>Run a Simulation</h2>
        <p>Choose an activity pattern to test the detector.</p>

        <div className="actions">
          <button
            disabled={loading}
            onClick={() => runSimulation("normal")}
          >
            Simulate Normal Activity
          </button>
          <button
            className="danger"
            disabled={loading}
            onClick={() => runSimulation("suspicious")}
          >
            Simulate Suspicious Activity
          </button>
          <button
            className="secondary"
            disabled={loading}
            onClick={loadAlerts}
          >
            Refresh Alerts
          </button>
        </div>

        {loading && <p>Running simulation...</p>}
        {error && <p className="error">{error}</p>}
      </section>

      <section className="panel">
        <h2>Security Alerts</h2>

        {alerts.length === 0 ? (
          <p>No alerts yet. Run a simulation to begin.</p>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Scenario</th>
                  <th>Severity</th>
                  <th>Files (simulated)</th>
                  <th>Detection Message</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map((alert) => (
                  <tr key={alert.id}>
                    <td>
                      {new Date(alert.timestamp).toLocaleTimeString()}
                    </td>
                    <td>{alert.scenario}</td>
                    <td>
                      <span className={
                        alert.severity === "High" ? "high" : "low"
                      }>
                        {alert.severity}
                      </span>
                    </td>
                    <td>{alert.files_affected}</td>
                    <td>{alert.message}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <footer>
        Educational simulation only. No real files are encrypted.
      </footer>
    </main>
  );
}
