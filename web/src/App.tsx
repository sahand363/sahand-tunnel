import { useEffect, useState } from "react";
import {
  Activity,
  ArrowDown,
  ArrowUp,
  Check,
  ChevronDown,
  ChevronRight,
  Copy,
  Globe2,
  Lock,
  Pause,
  Play,
  Plus,
  RefreshCw,
  Save,
  Server,
  Settings2,
  Shield,
  SkipForward,
  Trash2,
} from "lucide-react";

type Tab = "servers" | "tunnels" | "analytics";
type Role = "master" | "agent";

type MethodResult = {
  method_id: number;
  success: boolean;
  direction: string;
  latency_ms: number;
  error_reason?: string;
  tested_at?: string;
};

type LifelineEvent = {
  method_id: number;
  method_name: string;
  port: number;
  security: number;
  latency_ms: number;
  direction: string;
  initiator?: string;
  connected_at: string;
};

type TunnelConfig = {
  id: number;
  name: string;
  security: number;
  traffic_type: string;
  implemented: boolean;
  enabled: boolean;
  listen_port: number;
  forward_ports: string;
  sni?: string;
  ws_path?: string;
  cert_pin?: string;
  heartbeat_sec?: number;
  stream_limit?: number;
  speed_limit_mbps?: string;
  last_discovery: MethodResult;
};

type ServerPeer = {
  id: string;
  name: string;
  ip: string;
  token: string;
  config_version: number;
  sync_state: string;
  status: string;
  running: boolean;
  active_method_id: number;
  active_method: string;
  active_port: number;
  active_security: number;
  active_latency_ms: number;
  active_direction?: string;
  active_initiator?: string;
  next_retry_at?: string;
  recent_lifelines: LifelineEvent[];
  tunnels: TunnelConfig[];
};

type DailyUsage = {
  date: string;
  rx_bytes: number;
  tx_bytes: number;
};

function formatBytes(bytes: number): string {
  if (!bytes || bytes <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let idx = 0;
  let val = bytes;
  while (val >= 1024 && idx < units.length - 1) {
    val /= 1024;
    idx++;
  }
  return `${val.toFixed(val >= 10 || idx === 0 ? 0 : 1)} ${units[idx]}`;
}

function securityTierClass(sec: number): string {
  if (sec >= 85) return "sec-high";
  if (sec >= 65) return "sec-mid";
  return "sec-low";
}

function formatInitiatorFallback(role: Role, dir?: string, explicit?: string): string {
  if (explicit) return explicit;
  if (!dir) return "";
  if (role === "master") {
    return dir === "outbound" ? "Master → Agent" : "Agent → Master";
  }
  return dir === "outbound" ? "Agent → Master" : "Master → Agent";
}

export default function App() {
  const [activeTab, setActiveTab] = useState<Tab>("servers");
  const [role, setRole] = useState<Role>("master");
  const [appVersion, setAppVersion] = useState("0.4.3");
  const [servers, setServers] = useState<ServerPeer[]>([]);
  const [selectedServerID, setSelectedServerID] = useState<string>("");

  // Master & Agent Form Inputs
  const [serverName, setServerName] = useState("");
  const [serverIP, setServerIP] = useState("");
  const [agentToken, setAgentToken] = useState("");
  const [formError, setFormError] = useState("");
  const [copiedID, setCopiedID] = useState<string | null>(null);
  const [expandedHistoryID, setExpandedHistoryID] = useState<string | null>(null);
  const [switchingServerID, setSwitchingServerID] = useState<string | null>(null);
  const [switchNotice, setSwitchNotice] = useState<Record<string, string>>({});

  // Tunnels Tab State & Drafts
  const [expandedTunnel, setExpandedTunnel] = useState<number | null>(null);
  const [draftTunnels, setDraftTunnels] = useState<Record<string, TunnelConfig>>({});
  const [savingTunnelKey, setSavingTunnelKey] = useState<string | null>(null);
  const [savedNotice, setSavedNotice] = useState<Record<string, string>>({});

  // Analytics Tab State
  const [analyticsRange, setAnalyticsRange] = useState<7 | 30>(7);
  const [daysUsage, setDaysUsage] = useState<DailyUsage[]>([]);

  // Theme State
  const [darkMode, setDarkMode] = useState(true);

  useEffect(() => {
    document.documentElement.dataset.theme = darkMode ? "dark" : "light";
  }, [darkMode]);

  async function fetchState() {
    try {
      const res = await fetch("/api/v1/state");
      if (!res.ok) return;
      const data = await res.json();
      if (data.role === "master" || data.role === "agent") {
        setRole(data.role);
      }
      if (data.app_version) {
        setAppVersion(data.app_version);
      }
      const list: ServerPeer[] = Array.isArray(data.servers) ? data.servers : [];
      setServers(list);
      setSelectedServerID((prev) => {
        if (prev && list.some((s) => s.id === prev)) return prev;
        return list.length > 0 ? list[0].id : "";
      });
    } catch {
      // Ignore transient local polling errors
    }
  }

  async function fetchAnalytics() {
    try {
      const res = await fetch("/api/v1/analytics");
      if (!res.ok) return;
      const data = await res.json();
      if (Array.isArray(data.days)) {
        setDaysUsage(data.days);
      }
    } catch {
      // Ignore transient local polling errors
    }
  }

  useEffect(() => {
    fetchState();
    fetchAnalytics();
    const timer = setInterval(() => {
      fetchState();
    }, 3500);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    if (activeTab === "analytics") {
      fetchAnalytics();
    }
  }, [activeTab]);

  async function handleAddOrConnectServer(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setFormError("");

    const ip = serverIP.trim();
    if (role === "master") {
      const name = serverName.trim();
      if (!name || !ip) return;
      const res = await fetch("/api/v1/servers", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name, ip }),
      });
      if (!res.ok) {
        setFormError(await res.text());
        return;
      }
      setServerName("");
      setServerIP("");
      await fetchState();
    } else {
      const token = agentToken.trim();
      if (!ip || !token) return;
      const res = await fetch("/api/v1/servers", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip, token }),
      });
      if (!res.ok) {
        setFormError(await res.text());
        return;
      }
      setServerIP("");
      setAgentToken("");
      await fetchState();
    }
  }

  async function handleServerAction(
    serverID: string,
    action: "play" | "pause" | "delete" | "regen_token"
  ) {
    await fetch("/api/v1/servers/action", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ server_id: serverID, action }),
    });
    await fetchState();
  }

  async function handleNextMethod(serverID: string) {
    if (switchingServerID) return;
    setSwitchingServerID(serverID);
    try {
      const res = await fetch("/api/v1/servers/action", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ server_id: serverID, action: "next_method" }),
      });
      if (res.ok) {
        const data = await res.json();
        const msg =
          data.message || (data.switched ? "Switched method" : "No other method available");
        setSwitchNotice((prev) => ({ ...prev, [serverID]: msg }));
        setTimeout(() => {
          setSwitchNotice((prev) => {
            const next = { ...prev };
            delete next[serverID];
            return next;
          });
        }, 4000);
        await fetchState();
      }
    } finally {
      setSwitchingServerID(null);
    }
  }

  async function copyToken(id: string, token: string) {
    try {
      await navigator.clipboard.writeText(token);
      setCopiedID(id);
      setTimeout(() => setCopiedID(null), 1800);
    } catch {
      // Clipboard fallback ignored
    }
  }

  function getDraftTunnel(serverID: string, tunnel: TunnelConfig): TunnelConfig {
    const key = `${serverID}:${tunnel.id}`;
    return draftTunnels[key] || tunnel;
  }

  function updateDraftTunnel(serverID: string, updated: TunnelConfig) {
    const key = `${serverID}:${updated.id}`;
    setDraftTunnels((prev) => ({ ...prev, [key]: updated }));
  }

  async function commitTunnelConfig(serverID: string, updated: TunnelConfig) {
    if (role !== "master") return;
    const key = `${serverID}:${updated.id}`;
    setSavingTunnelKey(key);

    try {
      const res = await fetch("/api/v1/tunnels", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ server_id: serverID, tunnel: updated }),
      });
      if (res.ok) {
        const data = await res.json();
        setDraftTunnels((prev) => {
          const next = { ...prev };
          delete next[key];
          return next;
        });
        const verText = data.config_version ? ` (v${data.config_version})` : "";
        setSavedNotice((prev) => ({
          ...prev,
          [key]: `Saved & Token Updated${verText}`,
        }));
        setTimeout(() => {
          setSavedNotice((prev) => {
            const next = { ...prev };
            delete next[key];
            return next;
          });
        }, 3200);
        await fetchState();
      }
    } finally {
      setSavingTunnelKey(null);
    }
  }

  const selectedServer =
    servers.find((s) => s.id === selectedServerID) || servers[0] || null;
  const visibleAnalytics = daysUsage.slice(-analyticsRange);
  const rawMaxBytes = Math.max(
    0,
    ...visibleAnalytics.map((d) => Math.max(d.rx_bytes, d.tx_bytes))
  );
  const chartScaleMax = rawMaxBytes > 0 ? rawMaxBytes : 1073741824;
  const yAxisTicks = [
    chartScaleMax,
    Math.round(chartScaleMax * 0.75),
    Math.round(chartScaleMax * 0.5),
    Math.round(chartScaleMax * 0.25),
    0,
  ];
  const totalRx = visibleAnalytics.reduce((acc, d) => acc + d.rx_bytes, 0);
  const totalTx = visibleAnalytics.reduce((acc, d) => acc + d.tx_bytes, 0);

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand">
          <div className="brand-mark">
            <Shield size={19} strokeWidth={2.2} />
          </div>
          <span>
            Sahand<span className="brand-light">Tunnel</span>
          </span>
        </div>

        <div className="topbar-right">
          <div className="system-status">
            <span className="status-dot" />
            <span>{role.toUpperCase()}</span>
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
            <form className="add-server-form" onSubmit={handleAddOrConnectServer}>
              {role === "master" ? (
                <>
                  <div className="form-field name-field">
                    <label htmlFor="server-name">SERVER NAME</label>
                    <input
                      id="server-name"
                      value={serverName}
                      onChange={(event) => setServerName(event.target.value)}
                      placeholder="Agent Frankfurt"
                      autoComplete="off"
                    />
                  </div>

                  <div className="form-field ip-field">
                    <label htmlFor="server-ip">AGENT IP ADDRESS</label>
                    <input
                      id="server-ip"
                      value={serverIP}
                      onChange={(event) => setServerIP(event.target.value)}
                      placeholder="198.51.100.12"
                      autoComplete="off"
                    />
                  </div>

                  <button className="add-button" type="submit">
                    <Plus size={17} />
                    <span>Generate Token</span>
                  </button>
                </>
              ) : (
                <>
                  <div className="form-field ip-field">
                    <label htmlFor="master-ip">MASTER IP ADDRESS</label>
                    <input
                      id="master-ip"
                      value={serverIP}
                      onChange={(event) => setServerIP(event.target.value)}
                      placeholder="203.0.113.10"
                      autoComplete="off"
                    />
                  </div>

                  <div className="form-field name-field">
                    <label htmlFor="master-token">MASTER CONNECTION TOKEN</label>
                    <input
                      id="master-token"
                      value={agentToken}
                      onChange={(event) => setAgentToken(event.target.value)}
                      placeholder="st1.eyJ2IjoxLC..."
                      autoComplete="off"
                    />
                  </div>

                  <button className="add-button" type="submit">
                    <Play size={16} />
                    <span>Connect</span>
                  </button>
                </>
              )}
            </form>

            {formError && <div className="form-error-banner">{formError}</div>}

            <div className="section-divider" />

            <div className="list-heading">
              <span>{role === "master" ? "REGISTERED AGENTS" : "MASTER CONNECTION"}</span>
              <span className="item-count">{servers.length}</span>
            </div>

            {servers.length === 0 ? (
              <div className="empty-state">
                <div className="empty-icon">
                  <Server size={23} />
                </div>
                <p>{role === "master" ? "No agents added" : "Not paired with a Master"}</p>
              </div>
            ) : (
              <div className="server-list">
                {servers.map((server) => {
                  const historyOpen = expandedHistoryID === server.id;
                  const isSwitching = switchingServerID === server.id;
                  const switchMsg = switchNotice[server.id];
                  const whoConnected = formatInitiatorFallback(
                    role,
                    server.active_direction,
                    server.active_initiator
                  );

                  return (
                    <article className="server-card-block" key={server.id}>
                      <div className="server-row">
                        <div className="server-symbol">
                          <Server size={19} />
                        </div>

                        <div className="server-info">
                          <div className="server-title-row">
                            <span className="server-name">{server.name}</span>
                            <span className="version-pill">v{server.config_version}</span>
                          </div>
                          <div className="server-address">
                            {server.ip}
                            {server.active_method ? (
                              <span className="active-carrier-tag">
                                {" "}
                                • Method {String(server.active_method_id).padStart(2, "0")} (
                                {server.active_method} {server.active_security}%) • Port{" "}
                                {server.active_port || 11300 + server.active_method_id} •{" "}
                                {server.active_latency_ms}ms
                                {whoConnected ? ` • ${whoConnected}` : ""}
                              </span>
                            ) : server.next_retry_at ? (
                              <span className="retry-tag">
                                {" "}
                                • Next retry at {server.next_retry_at}
                              </span>
                            ) : null}
                          </div>
                        </div>

                        <div className="server-state">
                          <span
                            className={`state-dot ${
                              server.status === "CONNECTED"
                                ? "online"
                                : server.status === "TESTING"
                                ? "testing"
                                : ""
                            }`}
                          />
                          <span>{server.status}</span>
                        </div>

                        {role === "master" && (
                          <button
                            className="next-method-btn"
                            onClick={() => handleNextMethod(server.id)}
                            disabled={isSwitching}
                            title="Test and switch to the next working method without disconnecting"
                            aria-label="Next working method"
                          >
                            <SkipForward size={13} />
                            <span>{isSwitching ? "Checking..." : "Next"}</span>
                          </button>
                        )}

                        {role === "master" && (
                          <button
                            className="icon-button"
                            onClick={() => copyToken(server.id, server.token)}
                            title="Copy connection token (includes current ports)"
                            aria-label="Copy connection token"
                          >
                            {copiedID === server.id ? <Check size={15} /> : <Copy size={15} />}
                          </button>
                        )}

                        {role === "master" && (
                          <button
                            className="icon-button"
                            onClick={() => handleServerAction(server.id, "regen_token")}
                            title="Regenerate token with latest ports"
                            aria-label="Regenerate token"
                          >
                            <RefreshCw size={15} />
                          </button>
                        )}

                        <button
                          className={`server-action ${server.running ? "pause" : "play"}`}
                          onClick={() =>
                            handleServerAction(server.id, server.running ? "pause" : "play")
                          }
                          title={server.running ? "Pause discovery" : "Start discovery"}
                          aria-label={server.running ? "Pause discovery" : "Start discovery"}
                        >
                          {server.running ? <Pause size={16} /> : <Play size={16} />}
                        </button>

                        <button
                          className="icon-button delete-button"
                          onClick={() => handleServerAction(server.id, "delete")}
                          title="Remove server"
                          aria-label="Remove server"
                        >
                          <Trash2 size={16} />
                        </button>
                      </div>

                      <div className="server-subbar">
                        <button
                          className="history-toggle-btn"
                          onClick={() =>
                            setExpandedHistoryID(historyOpen ? null : server.id)
                          }
                        >
                          <span>
                            Recent Working Methods ({server.recent_lifelines?.length || 0}/5)
                          </span>
                          {historyOpen ? (
                            <ChevronDown size={14} />
                          ) : (
                            <ChevronRight size={14} />
                          )}
                        </button>

                        <span className="sync-badge">
                          {switchMsg
                            ? switchMsg
                            : copiedID === server.id
                            ? "✓ Token Copied"
                            : server.sync_state === "synced"
                            ? `Token Ready (v${server.config_version})`
                            : `Token Updated (v${server.config_version})`}
                        </span>
                      </div>

                      {historyOpen && (
                        <div className="lifeline-history-drawer">
                          {!server.recent_lifelines ||
                          server.recent_lifelines.length === 0 ? (
                            <div className="history-empty">
                              No successful connection methods recorded yet.
                            </div>
                          ) : (
                            server.recent_lifelines.map((item, idx) => {
                              const itemWho = formatInitiatorFallback(
                                role,
                                item.direction,
                                item.initiator
                              );
                              return (
                                <div className="history-row" key={idx}>
                                  <span className="history-method">
                                    #{String(item.method_id).padStart(2, "0")} {item.method_name}
                                  </span>
                                  <span
                                    className={`sec-badge ${securityTierClass(item.security)}`}
                                  >
                                    {item.security}%
                                  </span>
                                  <span className="history-meta">
                                    Port {item.port || 11300 + item.method_id} • {item.latency_ms}
                                    ms • {itemWho || item.direction}
                                  </span>
                                  <span className="history-time">{item.connected_at}</span>
                                </div>
                              );
                            })
                          )}
                        </div>
                      )}
                    </article>
                  );
                })}
              </div>
            )}
          </section>
        )}

        {activeTab === "tunnels" && (
          <section className="page-section">
            <div className="tunnels-toolbar">
              <div className="server-selector-group">
                <label htmlFor="tunnel-server-select">TARGET SERVER</label>
                <select
                  id="tunnel-server-select"
                  className="server-select"
                  value={selectedServer?.id || ""}
                  onChange={(e) => setSelectedServerID(e.target.value)}
                  disabled={servers.length === 0}
                >
                  {servers.length === 0 ? (
                    <option value="">No servers available</option>
                  ) : (
                    servers.map((srv) => (
                      <option key={srv.id} value={srv.id}>
                        {srv.name} ({srv.ip}) — {srv.status}
                      </option>
                    ))
                  )}
                </select>
              </div>

              {role === "agent" && (
                <div className="readonly-banner">
                  <Lock size={13} />
                  <span>READ-ONLY (MANAGED BY MASTER)</span>
                </div>
              )}
            </div>

            {!selectedServer ? (
              <div className="empty-state">
                <div className="empty-icon">
                  <Shield size={23} />
                </div>
                <p>Add or connect a server in the Servers tab to view its 30 tunnel methods</p>
              </div>
            ) : (
              <>
                <div className="list-heading tunnel-heading">
                  <span>TUNNEL METHODS</span>
                  <span className="item-count">{selectedServer.tunnels.length}</span>
                </div>

                <div className="tunnel-list">
                  {selectedServer.tunnels.map((tunnel) => {
                    const expanded = expandedTunnel === tunnel.id;
                    const disc = tunnel.last_discovery;
                    const draft = getDraftTunnel(selectedServer.id, tunnel);
                    const tunnelKey = `${selectedServer.id}:${tunnel.id}`;
                    const isSaving = savingTunnelKey === tunnelKey;
                    const noticeText = savedNotice[tunnelKey];

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

                            <span className="port-chip">:{tunnel.listen_port}</span>

                            <span className={`sec-badge ${securityTierClass(tunnel.security)}`}>
                              {tunnel.security}%
                            </span>

                            <span className="proto-badge">
                              {tunnel.traffic_type.toUpperCase()}
                            </span>

                            {disc?.tested_at && (
                              <span
                                className={`disc-pill ${
                                  disc.success ? "disc-ok" : "disc-fail"
                                }`}
                              >
                                {disc.success
                                  ? `OK ${disc.latency_ms}ms`
                                  : disc.error_reason || "Failed"}
                              </span>
                            )}

                            {noticeText && !expanded && (
                              <span className="save-feedback-inline">✓ {noticeText}</span>
                            )}

                            {expanded ? (
                              <ChevronDown size={17} />
                            ) : (
                              <ChevronRight size={17} />
                            )}
                          </button>

                          <button
                            className={`switch ${tunnel.enabled ? "switch-on" : ""} ${
                              role === "agent" ? "switch-disabled" : ""
                            }`}
                            onClick={() =>
                              role === "master" &&
                              commitTunnelConfig(selectedServer.id, {
                                ...draft,
                                enabled: !tunnel.enabled,
                              })
                            }
                            disabled={role === "agent" || isSaving}
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
                              <span>
                                {tunnel.name} Configuration ({tunnel.traffic_type.toUpperCase()})
                              </span>
                            </div>

                            <div className="settings-grid">
                              <div className="form-field">
                                <label htmlFor={`lport-${tunnel.id}`}>
                                  TUNNEL LISTEN PORT
                                </label>
                                <input
                                  id={`lport-${tunnel.id}`}
                                  type="number"
                                  disabled={role === "agent"}
                                  value={draft.listen_port}
                                  onChange={(e) =>
                                    updateDraftTunnel(selectedServer.id, {
                                      ...draft,
                                      listen_port: Number(e.target.value) || 0,
                                    })
                                  }
                                />
                              </div>

                              <div className="form-field">
                                <label htmlFor={`fport-${tunnel.id}`}>
                                  FORWARDING PORTS (CSV)
                                </label>
                                <input
                                  id={`fport-${tunnel.id}`}
                                  disabled={role === "agent"}
                                  placeholder="2053, 2083"
                                  value={draft.forward_ports}
                                  onChange={(e) =>
                                    updateDraftTunnel(selectedServer.id, {
                                      ...draft,
                                      forward_ports: e.target.value,
                                    })
                                  }
                                />
                              </div>

                              {draft.sni !== undefined && (
                                <div className="form-field">
                                  <label htmlFor={`sni-${tunnel.id}`}>TLS SNI</label>
                                  <input
                                    id={`sni-${tunnel.id}`}
                                    disabled={role === "agent"}
                                    placeholder="www.speedtest.net"
                                    value={draft.sni}
                                    onChange={(e) =>
                                      updateDraftTunnel(selectedServer.id, {
                                        ...draft,
                                        sni: e.target.value,
                                      })
                                    }
                                  />
                                </div>
                              )}

                              {draft.ws_path !== undefined && (
                                <div className="form-field">
                                  <label htmlFor={`path-${tunnel.id}`}>HTTP / WS PATH</label>
                                  <input
                                    id={`path-${tunnel.id}`}
                                    disabled={role === "agent"}
                                    placeholder="/ws"
                                    value={draft.ws_path}
                                    onChange={(e) =>
                                      updateDraftTunnel(selectedServer.id, {
                                        ...draft,
                                        ws_path: e.target.value,
                                      })
                                    }
                                  />
                                </div>
                              )}

                              {draft.speed_limit_mbps !== undefined && (
                                <div className="form-field">
                                  <label htmlFor={`spd-${tunnel.id}`}>
                                    SPEED LIMIT (MB/S, 0=UNLIMITED)
                                  </label>
                                  <input
                                    id={`spd-${tunnel.id}`}
                                    disabled={role === "agent"}
                                    placeholder="0"
                                    value={draft.speed_limit_mbps}
                                    onChange={(e) =>
                                      updateDraftTunnel(selectedServer.id, {
                                        ...draft,
                                        speed_limit_mbps: e.target.value,
                                      })
                                    }
                                  />
                                </div>
                              )}

                              <div className="setting-status">
                                <span className="setting-label">TRAFFIC TUNNEL</span>
                                <span
                                  className={`setting-value ${
                                    tunnel.enabled ? "enabled-text" : ""
                                  }`}
                                >
                                  {tunnel.enabled ? "Enabled" : "Disabled"}
                                </span>
                              </div>
                            </div>

                            {role === "master" && (
                              <div className="settings-actions-row">
                                <button
                                  type="button"
                                  className="save-tunnel-btn"
                                  disabled={isSaving}
                                  onClick={() =>
                                    commitTunnelConfig(selectedServer.id, draft)
                                  }
                                >
                                  <Save size={14} />
                                  <span>{isSaving ? "Saving..." : "Save Settings"}</span>
                                </button>

                                {noticeText && (
                                  <span className="save-feedback-text">
                                    ✓ {noticeText}
                                  </span>
                                )}
                              </div>
                            )}
                          </div>
                        )}
                      </article>
                    );
                  })}
                </div>
              </>
            )}
          </section>
        )}

        {activeTab === "analytics" && (
          <section className="page-section analytics-section">
            <div className="analytics-header">
              <div className="analytics-totals">
                <span className="legend-item">
                  <ArrowDown size={14} className="rx-icon" />
                  <span>Download: {formatBytes(totalRx)}</span>
                </span>
                <span className="legend-item">
                  <ArrowUp size={14} className="tx-icon" />
                  <span>Upload: {formatBytes(totalTx)}</span>
                </span>
              </div>

              <div className="range-selector">
                <button
                  className={`range-btn ${analyticsRange === 7 ? "active" : ""}`}
                  onClick={() => setAnalyticsRange(7)}
                >
                  7D
                </button>
                <button
                  className={`range-btn ${analyticsRange === 30 ? "active" : ""}`}
                  onClick={() => setAnalyticsRange(30)}
                >
                  30D
                </button>
              </div>
            </div>

            <div className="chart-card">
              <div className="chart-layout">
                <div className="y-axis-labels">
                  {yAxisTicks.map((val, i) => (
                    <span key={i}>{formatBytes(val)}</span>
                  ))}
                </div>

                <div className="chart-plot-area">
                  <div className="y-grid-lines">
                    {yAxisTicks.map((_, i) => (
                      <div className="y-grid-line" key={i} />
                    ))}
                  </div>

                  <div className="bars-container">
                    {visibleAnalytics.map((day) => {
                      const rxPct =
                        day.rx_bytes > 0
                          ? Math.max(4, Math.round((day.rx_bytes / chartScaleMax) * 100))
                          : 2;
                      const txPct =
                        day.tx_bytes > 0
                          ? Math.max(4, Math.round((day.tx_bytes / chartScaleMax) * 100))
                          : 2;
                      const shortDate = day.date.slice(5);

                      return (
                        <div
                          className="day-column"
                          key={day.date}
                          title={`${day.date} • ↓ ${formatBytes(day.rx_bytes)} | ↑ ${formatBytes(
                            day.tx_bytes
                          )}`}
                        >
                          <div className="day-bars">
                            <div className="bar rx-bar" style={{ height: `${rxPct}%` }} />
                            <div className="bar tx-bar" style={{ height: `${txPct}%` }} />
                          </div>
                          <span className="day-label">{shortDate}</span>
                        </div>
                      );
                    })}
                  </div>
                </div>
              </div>
            </div>
          </section>
        )}
      </main>

      <footer className="app-footer">
        <span>SAHAND TUNNEL</span>
        <span>{appVersion}</span>
      </footer>
    </div>
  );
}
