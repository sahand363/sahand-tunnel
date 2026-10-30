
import { useEffect, useState } from "react";
import {
  Activity,
  ArrowDown,
  ArrowUp,
  ChevronDown,
  ChevronRight,
  Globe2,
  Pause,
  Play,
  Plus,
  Server,
  Settings2,
  Shield,
  Trash2,
  Wifi,
  X,
} from "lucide-react";

type Tab = "servers" | "tunnels" | "analytics";

type ServerItem = {
  id: number;
  name: string;
  ip: string;
  running: boolean;
};

type TunnelItem = {
  id: number;
  name: string;
  enabled: boolean;
  port: string;
};

const initialTunnels: TunnelItem[] = Array.from(
  { length: 30 },
  (_, index) => ({
    id: index + 1,
    name: `Tunnel ${String(index + 1).padStart(2, "0")}`,
    enabled: false,
    port: "",
  })
);

export default function App() {
  const [activeTab, setActiveTab] = useState<Tab>("servers");
  const [servers, setServers] = useState<ServerItem[]>([]);
  const [serverName, setServerName] = useState("");
  const [serverIP, setServerIP] = useState("");
  const [expandedTunnel, setExpandedTunnel] = useState<number | null>(null);
  const [tunnels, setTunnels] = useState(initialTunnels);
  const [darkMode, setDarkMode] = useState(true);

  useEffect(() => {
    document.documentElement.dataset.theme = darkMode ? "dark" : "light";
  }, [darkMode]);

  function addServer(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();

    const name = serverName.trim();
    const ip = serverIP.trim();

    if (!name || !ip) return;

    setServers((current) => [
      ...current,
      {
        id: Date.now(),
        name,
        ip,
        running: false,
      },
    ]);

    setServerName("");
    setServerIP("");
  }

  function toggleServer(id: number) {
    setServers((current) =>
      current.map((server) =>
        server.id === id
          ? { ...server, running: !server.running }
          : server
      )
    );
  }

  function removeServer(id: number) {
    setServers((current) => current.filter((server) => server.id !== id));
  }

  function toggleTunnel(id: number) {
    setTunnels((current) =>
      current.map((tunnel) =>
        tunnel.id === id
          ? { ...tunnel, enabled: !tunnel.enabled }
          : tunnel
      )
    );
  }

  function updateTunnelPort(id: number, port: string) {
    setTunnels((current) =>
      current.map((tunnel) =>
        tunnel.id === id ? { ...tunnel, port } : tunnel
      )
    );
  }

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand">
          <div className="brand-mark">
            <Shield size={19} strokeWidth={2.2} />
          </div>
          <span>Sahand<span className="brand-light">Tunnel</span></span>
        </div>

        <div className="topbar-right">
          <div className="system-status">
            <span className="status-dot" />
            <span>LOCAL</span>
          </div>

          <button
            className="icon-button theme-button"
            onClick={() => setDarkMode((value) => !value)}
            aria-label="Change theme"
            title="Change theme"
          >
            {darkMode ? <Globe2 size={17} /> : <Activity size={17} />}
          </button>
        </div>
      </header>

      <main className="main-content">
        <nav className="tab-bar">
          <button
            className={`tab-button ${activeTab === "servers" ? "active" : ""}`}
            onClick={() => setActiveTab("servers")}
          >
            <Server size={16} />
            <span>Servers</span>
          </button>

          <button
            className={`tab-button ${activeTab === "tunnels" ? "active" : ""}`}
            onClick={() => setActiveTab("tunnels")}
          >
            <Shield size={16} />
            <span>Tunnels</span>
          </button>

          <button
            className={`tab-button ${activeTab === "analytics" ? "active" : ""}`}
            onClick={() => setActiveTab("analytics")}
          >
            <Activity size={16} />
            <span>Analytics</span>
          </button>
        </nav>

        {activeTab === "servers" && (
          <section className="page-section">
            <form className="add-server-form" onSubmit={addServer}>
              <div className="form-field name-field">
                <label htmlFor="server-name">NAME</label>
                <input
                  id="server-name"
                  value={serverName}
                  onChange={(event) => setServerName(event.target.value)}
                  placeholder="Server name"
                  autoComplete="off"
                />
              </div>

              <div className="form-field ip-field">
                <label htmlFor="server-ip">IP ADDRESS</label>
                <input
                  id="server-ip"
                  value={serverIP}
                  onChange={(event) => setServerIP(event.target.value)}
                  placeholder="192.168.1.1"
                  autoComplete="off"
                />
              </div>

              <button className="add-button" type="submit">
                <Plus size={17} />
                <span>Add server</span>
              </button>
            </form>

            <div className="section-divider" />

            <div className="list-heading">
              <span>YOUR SERVERS</span>
              <span className="item-count">{servers.length}</span>
            </div>

            {servers.length === 0 ? (
              <div className="empty-state">
                <div className="empty-icon">
                  <Server size={23} />
                </div>
                <p>No servers added</p>
              </div>
            ) : (
              <div className="server-list">
                {servers.map((server) => (
                  <article className="server-row" key={server.id}>
                    <div className="server-symbol">
                      <Server size={19} />
                    </div>

                    <div className="server-info">
                      <div className="server-name">{server.name}</div>
                      <div className="server-address">{server.ip}</div>
                    </div>

                    <div className="server-state">
                      <span
                        className={`state-dot ${server.running ? "online" : ""}`}
                      />
                      <span>{server.running ? "Active" : "Paused"}</span>
                    </div>

                    <button
                      className={`server-action ${server.running ? "pause" : "play"}`}
                      onClick={() => toggleServer(server.id)}
                      title={server.running ? "Pause" : "Play"}
                      aria-label={server.running ? "Pause server" : "Start server"}
                    >
                      {server.running ? (
                        <Pause size={16} />
                      ) : (
                        <Play size={16} />
                      )}
                    </button>

                    <button
                      className="icon-button delete-button"
                      onClick={() => removeServer(server.id)}
                      title="Remove server"
                      aria-label="Remove server"
                    >
                      <Trash2 size={16} />
                    </button>
                  </article>
                ))}
              </div>
            )}
          </section>
        )}

        {activeTab === "tunnels" && (
          <section className="page-section">
            <div className="list-heading tunnel-heading">
              <span>TUNNEL METHODS</span>
              <span className="item-count">30</span>
            </div>

            <div className="tunnel-list">
              {tunnels.map((tunnel) => {
                const expanded = expandedTunnel === tunnel.id;

                return (
                  <article
                    className={`tunnel-card ${expanded ? "expanded" : ""}`}
                    key={tunnel.id}
                  >
                    <div className="tunnel-row">
                      <button
                        className="tunnel-expand"
                        onClick={() =>
                          setExpandedTunnel(expanded ? null : tunnel.id)
                        }
                        aria-expanded={expanded}
                      >
                        <span className="tunnel-number">
                          {String(tunnel.id).padStart(2, "0")}
                        </span>

                        <span className="tunnel-title">{tunnel.name}</span>

                        {expanded ? (
                          <ChevronDown size={17} />
                        ) : (
                          <ChevronRight size={17} />
                        )}
                      </button>

                      <button
                        className={`switch ${tunnel.enabled ? "switch-on" : ""}`}
                        onClick={() => toggleTunnel(tunnel.id)}
                        role="switch"
                        aria-checked={tunnel.enabled}
                        aria-label={`Toggle ${tunnel.name}`}
                      >
                        <span />
                      </button>
                    </div>

                    {expanded && (
                      <div className="tunnel-settings">
                        <div className="settings-title">
                          <Settings2 size={15} />
                          <span>Settings</span>
                        </div>

                        <div className="settings-grid">
                          <div className="form-field">
                            <label htmlFor={`port-${tunnel.id}`}>
                              LISTEN PORT
                            </label>
                            <input
                              id={`port-${tunnel.id}`}
                              inputMode="numeric"
                              placeholder="Default"
                              value={tunnel.port}
                              onChange={(event) =>
                                updateTunnelPort(tunnel.id, event.target.value)
                              }
                            />
                          </div>

                          <div className="setting-status">
                            <span className="setting-label">STATUS</span>
                            <span
                              className={`setting-value ${
                                tunnel.enabled ? "enabled-text" : ""
                              }`}
                            >
                              {tunnel.enabled ? "Enabled" : "Disabled"}
                            </span>
                          </div>
                        </div>
                      </div>
                    )}
                  </article>
                );
              })}
            </div>
          </section>
        )}

        {activeTab === "analytics" && (
          <section className="page-section analytics-section">
            <div className="traffic-grid">
              <div className="traffic-card">
                <div className="traffic-label">
                  <ArrowDown size={16} />
                  <span>DOWNLOAD</span>
                </div>
                <div className="traffic-value">—</div>
                <div className="traffic-unit">Mbps</div>
              </div>

              <div className="traffic-card">
                <div className="traffic-label">
                  <ArrowUp size={16} />
                  <span>UPLOAD</span>
                </div>
                <div className="traffic-value">—</div>
                <div className="traffic-unit">Mbps</div>
              </div>
            </div>

            <div className="traffic-total">
              <div>
                <span className="total-label">TOTAL DATA</span>
                <div className="total-value">—</div>
              </div>
              <Wifi size={21} />
            </div>

            <div className="analytics-waiting">
              <span className="status-dot" />
              Traffic monitor not connected
            </div>
          </section>
        )}
      </main>

      <footer className="app-footer">
        <span>SAHAND TUNNEL</span>
        <span>0.3.0</span>
      </footer>
    </div>
  );
}
