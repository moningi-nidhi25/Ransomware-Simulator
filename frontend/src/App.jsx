import { useCallback, useEffect, useState } from "react";
import "./App.css";

const API = "http://127.0.0.1:8000";
const DEFAULT_SETTINGS = {
  event_window: 10,
  modification_threshold: 20,
  rename_threshold: 10,
  deletion_threshold: 10,
};

async function api(path, options = {}) {
  const response = await fetch(`${API}${path}`, {
    ...options,
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
  });
  if (!response.ok) {
    let message = `Request failed (${response.status})`;
    try {
      const data = await response.json();
      if (typeof data.detail === "string") {
        message = data.detail;
      } else if (Array.isArray(data.detail)) {
        message = data.detail
          .map((item) => {
            const loc = (item.loc || []).filter((x) => x !== "body").join(".");
            return loc ? `${loc}: ${item.msg}` : item.msg;
          })
          .join("; ");
      } else if (data.message) {
        message = data.message;
      }
    } catch {}
    throw new Error(message);
  }
  return response.json();
}

function StatCard({ label, value, detail }) {
  return <article className="stat-card"><span>{label}</span><strong>{value}</strong><small>{detail}</small></article>;
}

function Badge({ children, tone = "" }) {
  return <span className={`badge ${tone}`}>{children}</span>;
}

export default function App() {
  const [alerts, setAlerts] = useState([]);
  const [stats, setStats] = useState(null);
  const [settings, setSettings] = useState(DEFAULT_SETTINGS);
  const [filters, setFilters] = useState({ severity: "", source: "", status: "" });
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [modal, setModal] = useState(null);
  const [busy, setBusy] = useState(false);
  const [settingsLoaded, setSettingsLoaded] = useState(false);

  useEffect(() => {
    if (!modal) return;
    const timer = setTimeout(() => setModal(null), 3500);
    return () => clearTimeout(timer);
  }, [modal]);

  useEffect(() => {
    if (!notice) return;
    const timer = setTimeout(() => setNotice(""), 4000);
    return () => clearTimeout(timer);
  }, [notice]);

  const load = useCallback(async () => {
    try {
      const query = new URLSearchParams();
      Object.entries(filters).forEach(([key, value]) => { if (value) query.set(key, value); });
      const [alertRows, statsData, settingsData] = await Promise.all([
        api(`/api/alerts?${query}`), api("/api/stats"), api("/api/settings"),
      ]);
      setAlerts(alertRows);
      setStats(statsData);
      if (!settingsLoaded) {
        setSettings(settingsData);
        setSettingsLoaded(true);
      }
      setError("");
    } catch (e) {
      setError(`${e.message}. Check that the backend is running at ${API}.`);
    }
  }, [filters, settingsLoaded]);

  useEffect(() => {
    load();
    const timer = setInterval(load, 5000);
    return () => clearInterval(timer);
  }, [load]);

  async function runSimulation(scenario) {
    setBusy(true); setNotice(""); setError("");
    try {
      const result = await api(`/api/simulate/${scenario}`, { method: "POST" });
      setNotice(`${result.message} Risk score: ${result.risk_score}/100 · ${result.severity} severity.`);
      await load();
    } catch (e) { setError(e.message); }
    finally { setBusy(false); }
  }

  async function changeStatus(id, status) {
    try {
      await api(`/api/alerts/${id}/status`, {
        method: "PATCH", body: JSON.stringify({ status }),
      });
      setNotice(`Alert #${id} status updated to ${status}.`);
      await load();
    } catch (e) { setError(e.message); }
  }

  async function saveSettings(event) {
    event.preventDefault(); setBusy(true); setNotice(""); setError("");
    try {
      const body = Object.fromEntries(Object.entries(settings).map(([key, value]) => [key, Number(value)]));
      const saved = await api("/api/settings", { method: "PUT", body: JSON.stringify(body) });
      setSettings(saved);
      setSettingsLoaded(true);
      setModal({
        title: "Settings Saved",
        message: "Detection settings saved successfully.",
        type: "success",
      });
      setNotice("Detection settings saved successfully.");
      await load();
    } catch (e) { setError(e.message); }
    finally { setBusy(false); }
  }

  const activity = stats?.activity || [];
  const maxActivity = Math.max(1, ...activity.map((item) => item.count));

  return (
    <main className="dashboard">
      {modal && (
        <div className="modal-overlay" onClick={() => setModal(null)}>
          <div className={`modal-card modal-${modal.type}`} onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <div className="modal-title-wrap">
                <span className="modal-icon">{modal.type === "success" ? "✓" : "ℹ"}</span>
                <h3>{modal.title}</h3>
              </div>
              <button className="modal-close" onClick={() => setModal(null)} aria-label="Close modal">×</button>
            </div>
            <p className="modal-body">{modal.message}</p>
            <div className="modal-footer">
              <button className="btn btn-primary" onClick={() => setModal(null)}>OK</button>
            </div>
          </div>
        </div>
      )}

      <header className="topbar">
        <div className="brand-symbol">RS</div>
        <div className="brand-copy"><div className="brand">RansomShield</div><p>Ransomware-like activity monitor</p></div>
        <span className="system-pill"><span className="pulse" /> API dashboard</span>
      </header>

      <section className="intro">
        <div><p className="eyebrow">SECURITY OVERVIEW</p><h1>Detection dashboard</h1><p className="subhead">Review detections, monitor risk, and manage alert status.</p></div>
        <div className="actions">
          <button className="btn btn-secondary" disabled={busy} onClick={() => runSimulation("normal")}>Simulate normal</button>
          <button className="btn btn-danger" disabled={busy} onClick={() => runSimulation("suspicious")}>Simulate suspicious</button>
        </div>
      </section>

      {error && <div className="notice error-notice">{error}</div>}
      {notice && <div className="notice success-notice">{notice}</div>}

      <section className="stats-grid">
        <StatCard label="Total alerts" value={stats?.total_alerts ?? "—"} detail="All saved detections" />
        <StatCard label="Unresolved alerts" value={stats?.open_alerts ?? "—"} detail="Open or investigating" />
        <StatCard label="High severity" value={stats?.high_alerts ?? "—"} detail="High-risk detections" />
        <StatCard label="Average risk" value={stats ? `${stats.average_risk}/100` : "—"} detail="Across saved alerts" />
      </section>

      <section className="two-column">
        <article className="panel">
          <div className="panel-heading"><div><h2>File event activity</h2><p>Recent events captured by the monitor</p></div><Badge>Last 24 hours</Badge></div>
          {activity.length ? <div className="chart" aria-label="File event activity chart">
            {activity.map((item, index) => <div className="chart-column" key={`${item.time}-${index}`} title={`${item.time}: ${item.count} events`}>
              <div className="bar-area"><div className="bar" style={{ height: `${Math.max(5, (item.count / maxActivity) * 100)}%` }} /></div>
              <span>{item.time}</span>
            </div>)}
          </div> : <div className="empty-chart"><strong>No file events yet</strong><span>Optional monitoring can be enabled for backend/test_data.</span></div>}
        </article>

        <article className="panel latest-panel">
          <div className="panel-heading"><div><h2>Latest detection</h2><p>Most recently recorded alert</p></div></div>
          {stats?.latest_alert ? <>
            <div className="risk-score"><strong>{stats.latest_alert.risk_score}</strong><span>/100 risk score</span></div>
            <Badge tone={`tone-${String(stats.latest_alert.severity).toLowerCase()}`}>{stats.latest_alert.severity} severity</Badge>
            <p className="latest-message">{stats.latest_alert.message}</p>
            <p className="timestamp">{stats.latest_alert.timestamp}</p>
            {(stats.latest_alert.reasons || []).length > 0 && <ul className="reasons">{stats.latest_alert.reasons.map((reason, i) => <li key={i}>{reason}</li>)}</ul>}
          </> : <div className="empty-chart"><strong>No alerts yet</strong><span>Run a synthetic simulation to populate this panel.</span></div>}
        </article>
      </section>

      <section className="panel">
        <div className="panel-heading"><div><h2>Alert history</h2><p>Filter detections and update investigation status</p></div><a className="btn btn-secondary export-link" href={`${API}/api/reports/export`}>Export CSV</a></div>
        <div className="filters">
          <label>Severity<select value={filters.severity} onChange={(e) => setFilters({ ...filters, severity: e.target.value })}><option value="">All severities</option><option>Low</option><option>Medium</option><option>High</option></select></label>
          <label>Source<select value={filters.source} onChange={(e) => setFilters({ ...filters, source: e.target.value })}><option value="">All sources</option><option value="simulation">Simulation</option><option value="file_monitor">File monitor</option></select></label>
          <label>Status<select value={filters.status} onChange={(e) => setFilters({ ...filters, status: e.target.value })}><option value="">All statuses</option><option value="open">Open</option><option value="investigating">Investigating</option><option value="resolved">Resolved</option></select></label>
        </div>
        <div className="table-wrap"><table>
          <thead><tr><th>Alert</th><th>Detection</th><th>Risk</th><th>Source</th><th>Status</th></tr></thead>
          <tbody>
            {alerts.map((alert) => <tr key={alert.id}>
              <td><strong>#{alert.id}</strong><small>{alert.timestamp}</small></td>
              <td><Badge tone={`tone-${String(alert.severity).toLowerCase()}`}>{alert.severity}</Badge><p className="message-cell">{alert.message}</p></td>
              <td><div className="risk-cell"><strong>{alert.risk_score ?? 0}</strong><div className="risk-track"><span style={{ width: `${alert.risk_score ?? 0}%` }} /></div></div></td>
              <td><span className="source-label">{alert.source || "simulation"}</span></td>
              <td><select className="status-select" value={alert.status || "open"} onChange={(e) => changeStatus(alert.id, e.target.value)}><option value="open">Open</option><option value="investigating">Investigating</option><option value="resolved">Resolved</option></select></td>
            </tr>)}
            {!alerts.length && <tr><td colSpan="5" className="empty-row">No alerts match these filters.</td></tr>}
          </tbody>
        </table></div>
      </section>

      <section className="panel settings-panel">
        <div className="panel-heading"><div><h2>Detection settings</h2><p>Settings are stored in SQLite and used by the detector.</p></div></div>
        {error && <div className="notice error-notice">{error}</div>}
        {notice && <div className="notice success-notice">{notice}</div>}
        <form className="settings-form" onSubmit={saveSettings}>
          {[
            ["event_window", "Event window (seconds)", 1, 300],
            ["modification_threshold", "Modification threshold", 1, 10000],
            ["rename_threshold", "Rename threshold", 1, 10000],
            ["deletion_threshold", "Deletion threshold", 1, 10000],
          ].map(([key, label, min, max]) => <label key={key}>{label}<input type="number" min={min} max={max} required value={settings[key]} onChange={(e) => setSettings({ ...settings, [key]: e.target.value })} /></label>)}
          <div style={{ display: "flex", gap: "0.75rem", marginTop: "1rem" }}>
            <button className="btn btn-primary" type="submit" disabled={busy}>Save settings</button>
            <button className="btn btn-secondary" type="button" disabled={busy} onClick={() => setSettings(DEFAULT_SETTINGS)}>Reset to defaults</button>
          </div>
        </form>
      </section>

      <footer>RansomShield · Educational simulation only · Synthetic simulations never alter real files.</footer>
    </main>
  );
}
