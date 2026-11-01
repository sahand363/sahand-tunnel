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
  speed_limit_mbps: string;
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

type PortDraftMap = Record<
  number,
  { listen_port: number; forward_ports: string }
>;

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
  const [activeTab, setActiveTab] = useState<Tab>(() => {
    const saved = localStorage.getItem("sahand_tab");
    if (saved === "servers" || saved === "tunnels" || saved === "analytics") {
      return saved as Tab;
    }
    return "servers";
  });

  const [role, setRole] = useState<Role>("master");
  const [appVersion, setAppVersion] = useState("0.4.5");
  const [masterTime, setMasterTime] = useState("");
  const [servers, setServers] = useState<ServerPeer[]>([]);
  const [selectedServerID, setSelectedServerID] = useState<string>(() => {
    return localStorage.getItem("sahand_server_id") || "";
  });

  const [serverName, setServerName] = useState("");
  const [serverIP, setServerIP] = useState("");
  const [agentToken, setAgentToken] = useState("");
  const [formError, setFormError] = useState("");
  const [copiedID, setCopiedID] = useState<string | null>(null);
  const [expandedHistoryID, setExpandedHistoryID] = useState<string | null>(null);
  const [switchingServerID, setSwitchingServerID] = useState<string | null>(null);
  const [switchNotice, setSwitchNotice] = useState<Record<string, string>>({});

  const [expandedTunnel, setExpandedTunnel] = useState<number | null>(null);
  const [draftTunnels, setDraftTunnels] = useState<Record<string, TunnelConfig>>({});
  const [savingTunnelKey, setSavingTunnelKey] = useState<string | null>(null);
  const [savedNotice, setSavedNotice] = useState<Record<string, string>>({});
  const [pingingKey, setPingingKey] = useState<string | null>(null);

  // Top-bar Nut Icon (Port & Theme Settings Modal) state
  const [showPortSettings, setShowPortSettings] = useState(false);
  const [portDrafts, setPortDrafts] = useState<PortDraftMap>({});
  const [engine1BasePort, setEngine1BasePort] = useState(28001);
  const [engine2BasePort, setEngine2BasePort] = useState(32001);
  const [savingBatchPorts, setSavingBatchPorts] = useState(false);
  const [batchPortNotice, setBatchPortNotice] = useState("");

  const [analyticsRange, setAnalyticsRange] = useState<7 | 30>(7);
  const [daysUsage, setDaysUsage] = useState<DailyUsage[]>([]);
  const [darkMode, setDarkMode] = useState<boolean>(() => {
    const saved = localStorage.getItem("sahand_theme");
    return saved ? saved === "dark" : true;
  });

  useEffect(() => {
    document.documentElement.dataset.theme = darkMode ? "dark" : "light";
    localStorage.setItem("sahand_theme", darkMode ? "dark" : "light");
  }, [darkMode]);

  const switchTab = (tab: Tab) => {
    setActiveTab(tab);
    localStorage.setItem("sahand_tab", tab);
  };

  const handleSelectServer = (id: string) => {
    setSelectedServerID(id);
    localStorage.setItem("sahand_server_id", id);
  };

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
      if (data.server_time) {
        setMasterTime(data.server_time);
      }
      const list: ServerPeer[] = Array.isArray(data.servers) ? data.servers : [];
      setServers(list);
      setSelectedServerID((prev) => {
        if (prev && list.some((s) => s.id === prev)) return prev;
        const saved = localStorage.getItem("sahand_server_id");
        if (saved && list.some((s) => s.id === saved)) return saved;
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

  const selectedServer =
    servers.find((s) => s.id === selectedServerID) || servers[0] || null;

  function openPortSettingsModal() {
    if (selectedServer) {
      const initial: PortDraftMap = {};
      for (const t of selectedServer.tunnels) {
        initial[t.id] = {
          listen_port: t.listen_port || 28000 + t.id,
          forward_ports: t.forward_ports || String(32000 + t.id),
        };
      }
      setPortDrafts(initial);
    }
    setBatchPortNotice("");
    setShowPortSettings(true);
  }

  function applyEngine1BaseRange(base: number) {
    const start = Math.max(1024, Math.min(65500, base));
    setEngine1BasePort(start);
    setPortDrafts((prev) => {
      const next: PortDraftMap = { ...prev };
      for (let id = 1; id <= 30; id++) {
        next[id] = {
          listen_port: start + id - 1,
          forward_ports: next[id]?.forward_ports || String(32000 + id),
        };
      }
      return next;
    });
  }

  function applyEngine2BaseRange(base: number) {
    const start = Math.max(1024, Math.min(65500, base));
    setEngine2BasePort(start);
    setPortDrafts((prev) => {
      const next: PortDraftMap = { ...prev };
      for (let id = 1; id <= 30; id++) {
        next[id] = {
          listen_port: next[id]?.listen_port || 28000 + id,
          forward_ports: String(start + id - 1),
        };
      }
      return next;
    });
  }

  async function handleSaveAllPorts() {
    if (!selectedServer || role !== "master") return;
    setSavingBatchPorts(true);
    setBatchPortNotice("");

    const items = selectedServer.tunnels.map((t) => ({
      id: t.id,
      listen_port: portDrafts[t.id]?.listen_port ?? t.listen_port,
      forward_ports: portDrafts[t.id]?.forward_ports ?? t.forward_ports,
    }));

    try {
      const res = await fetch("/api/v1/tunnels/ports", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          server_id: selectedServer.id,
          items,
        }),
      });
      if (res.ok) {
        const data = await res.json();
        const verText = data.config_version ? ` (v${data.config_version})` : "";
        setBatchPortNotice(`Saved & Token Updated${verText}`);
        await fetchState();
      }
    } finally {
      setSavingBatchPorts(false);
    }
  }

  async function handlePingTunnel(serverID: string, methodID: number) {
    const key = `${serverID}:${methodID}`;
    if (pingingKey) return;
    setPingingKey(key);
    try {
      const res = await fetch("/api/v1/tunnels/ping", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ server_id: serverID, method_id: methodID }),
      });
      if (res.ok) {
        await fetchState();
      }
    } finally {
      setPingingKey(null);
    }
  }

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
    const t = draftTunnels[key] || tunnel;
    return {
      ...t,
      speed_limit_mbps: t.speed_limit_mbps ?? "0",
    };
  }

  function updateDraftTunnel(serverID: string, updated: TunnelConfig) {
    const key = `${serverID}:${updated.id}`;
    setDraftTunnels((prev) => ({ ...prev, [key]: updated }));
  }

  async function commitTunnelConfig(serverID: string, updated: TunnelConfig) {
    if (role !== "master") return;
    const key = `${serverID}:${updated.id}`;
    setSavingTunnelKey(key);

    const safeSpeed =
      updated.speed_limit_mbps && updated.speed_limit_mbps.trim() !== ""
        ? updated.speed_limit_mbps.trim()
        : "0";

    const payload = {
      ...updated,
      speed_limit_mbps: safeSpeed,
    };

    try {
      const res = await fetch("/api/v1/tunnels", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ server_id: serverID, tunnel: payload }),
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

  // Explicit theme-aware palette for the Settings Modal
  const modalTheme = darkMode
    ? {
        backdrop: "rgba(5, 9, 20, 0.78)",
        cardBg: "#12192b",
        cardBorder: "#26334d",
        textMain: "#f1f5f9",
        textMuted: "#94a3b8",
        itemBg: "#0c1324",
        itemBorder: "#23304a",
        inputBg: "#080d1a",
        inputBorder: "#2e3d5c",
        inputText: "#f8fafc",
      }
    : {
        backdrop: "rgba(15, 23, 42, 0.45)",
        cardBg: "#ffffff",
        cardBorder: "#cbd5e1",
        textMain: "#0f172a",
        textMuted: "#475569",
        itemBg: "#f8fafc",
        itemBorder: "#e2e8f0",
        inputBg: "#ffffff",
        inputBorder: "#cbd5e1",
        inputText: "#0f172a",
      };

  return (
    <div className="app-shell">
      <style>{`
        .sahand-chart-card {
          padding: 16px 14px 14px 10px !important;
        }
        .sahand-chart-layout {
          display: flex !important;
          align-items: stretch !important;
          gap: 8px !important;
          width: 100% !important;
        }
        .sahand-y-axis {
          display: flex !important;
          flex-direction: column !important;
          justify-content: space-between !important;
          width: 46px !important;
          min-width: 46px !important;
          padding-bottom: 22px !important;
          text-align: right !important;
          font-size: 11px !important;
          opacity: 0.75 !important;
          user-select: none !important;
        }
        .sahand-plot-area {
          position: relative !important;
          flex: 1 1 0% !important;
          min-width: 0 !important;
          height: 230px !important;
          display: flex !important;
          flex-direction: column !important;
        }
        .sahand-grid-lines {
          position: absolute !important;
          inset: 0 0 22px 0 !important;
          display: flex !important;
          flex-direction: column !important;
          justify-content: space-between !important;
          pointer-events: none !important;
        }
        .sahand-bars-grid {
          position: relative !important;
          z-index: 1 !important;
          flex: 1 1 0% !important;
          display: grid !important;
          align-items: end !important;
          width: 100% !important;
          height: 100% !important;
          padding: 0 !important;
          margin: 0 !important;
        }
        .sahand-bars-grid.range-7 {
          grid-template-columns: repeat(7, minmax(0, 1fr)) !important;
          gap: 8px !important;
        }
        .sahand-bars-grid.range-30 {
          grid-template-columns: repeat(30, minmax(0, 1fr)) !important;
          gap: 2px !important;
        }
        .sahand-day-col {
          display: flex !important;
          flex-direction: column !important;
          align-items: center !important;
          justify-content: flex-end !important;
          height: 100% !important;
          min-width: 0 !important;
          width: 100% !important;
        }
        .sahand-day-bars {
          flex: 1 1 0% !important;
          width: 100% !important;
          display: flex !important;
          align-items: flex-end !important;
          justify-content: center !important;
          gap: 2px !important;
          padding-bottom: 4px !important;
        }
        .sahand-bars-grid.range-30 .sahand-day-bars {
          gap: 1px !important;
        }
        .sahand-bar {
          flex: 1 1 0% !important;
          max-width: 14px !important;
          min-width: 2px !important;
          border-radius: 3px 3px 0 0 !important;
          transition: height 0.25s ease !important;
        }
        .sahand-date-cell {
          height: 18px !important;
          display: flex !important;
          align-items: center !important;
          justify-content: center !important;
          font-size: 10px !important;
          opacity: 0.78 !important;
          white-space: nowrap !important;
          overflow: visible !important;
        }
      `}</style>

      <header className="topbar">
        <div className="brand">
          <div className="brand-mark">
            <Shield size={18} strokeWidth={2.2} />
          </div>
          <span>
            Sahand<span className="brand-light">Tunnel</span>
          </span>
        </div>

        <div className="topbar-right" style={{ gap: "8px" }}>
          {masterTime && (
            <span
              className="master-clock-pill"
              style={{ whiteSpace: "nowrap", fontSize: "11.5px", padding: "4px 9px" }}
            >
              {masterTime}
            </span>
          )}

          <div
            className="system-status"
            title={role === "master" ? "MASTER NODE" : "AGENT NODE"}
            style={{ padding: "4px 9px", gap: "6px" }}
          >
            <span className="status-dot" />
            <span style={{ fontWeight: 700 }}>
              {role === "master" ? "M" : "A"}
            </span>
          </div>

          <button
            className="icon-button theme-button"
            onClick={openPortSettingsModal}
            aria-label="Settings"
            title="Settings (Ports & Theme)"
          >
            <svg
              width="17"
              height="17"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z" />
              <circle cx="12" cy="12" r="4" />
            </svg>
          </button>
        </div>
      </header>

      {showPortSettings && (
        <div
          style={{
            position: "fixed",
            inset: 0,
            backgroundColor: modalTheme.backdrop,
            backdropFilter: "blur(6px)",
            zIndex: 9999,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            padding: "14px",
          }}
          onClick={() => setShowPortSettings(false)}
        >
          <div
            style={{
              width: "min(860px, 100%)",
              maxHeight: "90vh",
              backgroundColor: modalTheme.cardBg,
              color: modalTheme.textMain,
              border: `1px solid ${modalTheme.cardBorder}`,
              borderRadius: "16px",
              display: "flex",
              flexDirection: "column",
              overflow: "hidden",
              boxShadow: "0 24px 60px rgba(0,0,0,0.45)",
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <div
              style={{
                padding: "16px 20px",
                borderBottom: `1px solid ${modalTheme.cardBorder}`,
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                gap: "10px",
                flexWrap: "wrap",
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                <Settings2 size={18} />
                <div>
                  <div
                    style={{
                      fontWeight: 700,
                      fontSize: "15px",
                      color: modalTheme.textMain,
                    }}
                  >
                    Application & Port Settings
                  </div>
                  <div style={{ fontSize: "12px", color: modalTheme.textMuted }}>
                    Customize appearance and Engine 1 / Engine 2 port mappings
                  </div>
                </div>
              </div>

              <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                <button
                  type="button"
                  className="next-method-btn"
                  onClick={() => setDarkMode((value) => !value)}
                  title="Switch Light / Dark Theme"
                >
                  <Globe2 size={14} />
                  <span>{darkMode ? "Theme: Dark" : "Theme: Light"}</span>
                </button>

                <button
                  type="button"
                  className="icon-button"
                  onClick={() => setShowPortSettings(false)}
                  title="Close settings"
                  style={{ color: modalTheme.textMain }}
                >
                  ✕
                </button>
              </div>
            </div>

            {!selectedServer ? (
              <div
                style={{
                  padding: "36px",
                  textAlign: "center",
                  color: modalTheme.textMuted,
                }}
              >
                Add or select a server first to configure its 30 method ports.
              </div>
            ) : (
              <>
                <div
                  style={{
                    padding: "14px 20px",
                    borderBottom: `1px solid ${modalTheme.cardBorder}`,
                    display: "flex",
                    flexWrap: "wrap",
                    alignItems: "center",
                    justifyContent: "space-between",
                    gap: "12px",
                  }}
                >
                  <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                    <span
                      style={{
                        fontSize: "12px",
                        fontWeight: 600,
                        color: modalTheme.textMuted,
                      }}
                    >
                      TARGET:
                    </span>
                    <select
                      className="server-select"
                      value={selectedServer.id}
                      style={{
                        backgroundColor: modalTheme.inputBg,
                        color: modalTheme.inputText,
                        borderColor: modalTheme.inputBorder,
                      }}
                      onChange={(e) => {
                        const newID = e.target.value;
                        handleSelectServer(newID);
                        const srv = servers.find((s) => s.id === newID);
                        if (srv) {
                          const nextMap: PortDraftMap = {};
                          for (const t of srv.tunnels) {
                            nextMap[t.id] = {
                              listen_port: t.listen_port,
                              forward_ports: t.forward_ports,
                            };
                          }
                          setPortDrafts(nextMap);
                        }
                      }}
                    >
                      {servers.map((srv) => (
                        <option key={srv.id} value={srv.id}>
                          {srv.name} ({srv.ip}) — v{srv.config_version}
                        </option>
                      ))}
                    </select>
                  </div>

                  {role === "master" && (
                    <div
                      style={{
                        display: "flex",
                        flexWrap: "wrap",
                        alignItems: "center",
                        gap: "10px",
                      }}
                    >
                      <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                        <span
                          style={{ fontSize: "12px", color: modalTheme.textMuted }}
                        >
                          Engine 1 Start:
                        </span>
                        <input
                          type="number"
                          value={engine1BasePort}
                          onChange={(e) =>
                            setEngine1BasePort(Number(e.target.value) || 28001)
                          }
                          style={{
                            width: "82px",
                            padding: "6px 8px",
                            borderRadius: "8px",
                            border: `1px solid ${modalTheme.inputBorder}`,
                            backgroundColor: modalTheme.inputBg,
                            color: modalTheme.inputText,
                            fontSize: "13px",
                          }}
                        />
                        <button
                          type="button"
                          className="next-method-btn"
                          onClick={() => applyEngine1BaseRange(engine1BasePort)}
                        >
                          Fill E1 ({engine1BasePort}–{engine1BasePort + 29})
                        </button>
                      </div>

                      <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                        <span
                          style={{ fontSize: "12px", color: modalTheme.textMuted }}
                        >
                          Engine 2 Start:
                        </span>
                        <input
                          type="number"
                          value={engine2BasePort}
                          onChange={(e) =>
                            setEngine2BasePort(Number(e.target.value) || 32001)
                          }
                          style={{
                            width: "82px",
                            padding: "6px 8px",
                            borderRadius: "8px",
                            border: `1px solid ${modalTheme.inputBorder}`,
                            backgroundColor: modalTheme.inputBg,
                            color: modalTheme.inputText,
                            fontSize: "13px",
                          }}
                        />
                        <button
                          type="button"
                          className="next-method-btn"
                          onClick={() => applyEngine2BaseRange(engine2BasePort)}
                        >
                          Fill E2 ({engine2BasePort}–{engine2BasePort + 29})
                        </button>
                      </div>
                    </div>
                  )}
                </div>

                <div
                  style={{
                    padding: "16px 20px",
                    overflowY: "auto",
                    display: "grid",
                    gridTemplateColumns: "repeat(auto-fill, minmax(240px, 1fr))",
                    gap: "10px",
                  }}
                >
                  {selectedServer.tunnels.map((t) => {
                    const rowDraft = portDrafts[t.id] || {
                      listen_port: t.listen_port,
                      forward_ports: t.forward_ports,
                    };
                    return (
                      <div
                        key={t.id}
                        style={{
                          padding: "10px 12px",
                          borderRadius: "10px",
                          border: `1px solid ${modalTheme.itemBorder}`,
                          backgroundColor: modalTheme.itemBg,
                          display: "flex",
                          flexDirection: "column",
                          gap: "8px",
                        }}
                      >
                        <div
                          style={{
                            display: "flex",
                            alignItems: "center",
                            justifyContent: "space-between",
                            fontSize: "13px",
                            fontWeight: 600,
                            color: modalTheme.textMain,
                          }}
                        >
                          <span>
                            #{String(t.id).padStart(2, "0")} {t.name}
                          </span>
                          <span className={`sec-badge ${securityTierClass(t.security)}`}>
                            {t.security}%
                          </span>
                        </div>

                        <div
                          style={{
                            display: "grid",
                            gridTemplateColumns: "1fr 1fr",
                            gap: "8px",
                          }}
                        >
                          <div>
                            <label
                              style={{
                                display: "block",
                                fontSize: "10px",
                                fontWeight: 600,
                                color: modalTheme.textMuted,
                                marginBottom: "3px",
                              }}
                            >
                              ENGINE 1 PORT
                            </label>
                            <input
                              type="number"
                              disabled={role === "agent"}
                              value={rowDraft.listen_port}
                              onChange={(e) =>
                                setPortDrafts((prev) => ({
                                  ...prev,
                                  [t.id]: {
                                    ...rowDraft,
                                    listen_port: Number(e.target.value) || 0,
                                  },
                                }))
                              }
                              style={{
                                width: "100%",
                                padding: "6px 8px",
                                borderRadius: "7px",
                                border: `1px solid ${modalTheme.inputBorder}`,
                                backgroundColor: modalTheme.inputBg,
                                color: modalTheme.inputText,
                                fontSize: "13px",
                              }}
                            />
                          </div>

                          <div>
                            <label
                              style={{
                                display: "block",
                                fontSize: "10px",
                                fontWeight: 600,
                                color: modalTheme.textMuted,
                                marginBottom: "3px",
                              }}
                            >
                              ENGINE 2 PORTS
                            </label>
                            <input
                              type="text"
                              disabled={role === "agent"}
                              value={rowDraft.forward_ports}
                              onChange={(e) =>
                                setPortDrafts((prev) => ({
                                  ...prev,
                                  [t.id]: {
                                    ...rowDraft,
                                    forward_ports: e.target.value,
                                  },
                                }))
                              }
                              style={{
                                width: "100%",
                                padding: "6px 8px",
                                borderRadius: "7px",
                                border: `1px solid ${modalTheme.inputBorder}`,
                                backgroundColor: modalTheme.inputBg,
                                color: modalTheme.inputText,
                                fontSize: "13px",
                              }}
                            />
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>

                <div
                  style={{
                    padding: "14px 20px",
                    borderTop: `1px solid ${modalTheme.cardBorder}`,
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    gap: "12px",
                    flexWrap: "wrap",
                  }}
                >
                  <div style={{ fontSize: "13px", color: "#10b981", fontWeight: 600 }}>
                    {batchPortNotice && `✓ ${batchPortNotice}`}
                  </div>

                  <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                    {role === "master" && selectedServer && (
                      <button
                        type="button"
                        className="next-method-btn"
                        onClick={() => copyToken(selectedServer.id, selectedServer.token)}
                      >
                        {copiedID === selectedServer.id ? (
                          <Check size={14} />
                        ) : (
                          <Copy size={14} />
                        )}
                        <span>
                          {copiedID === selectedServer.id ? "Token Copied" : "Copy Token"}
                        </span>
                      </button>
                    )}

                    {role === "master" && (
                      <button
                        type="button"
                        className="save-tunnel-btn"
                        disabled={savingBatchPorts}
                        onClick={handleSaveAllPorts}
                      >
                        <Save size={14} />
                        <span>
                          {savingBatchPorts
                            ? "Saving..."
                            : "Save Ports & Update Token"}
                        </span>
                      </button>
                    )}
                  </div>
                </div>
              </>
            )}
          </div>
        </div>
      )}

      <main className="main-content">
        <nav className="tab-bar">
          <button
            className={`tab-button ${activeTab === "servers" ? "active" : ""}`}
            onClick={() => switchTab("servers")}
          >
            <Server size={16} />
            <span>Servers</span>
          </button>

          <button
            className={`tab-button ${activeTab === "tunnels" ? "active" : ""}`}
            onClick={() => switchTab("tunnels")}
          >
            <Shield size={16} />
            <span>Tunnels</span>
          </button>

          <button
            className={`tab-button ${activeTab === "analytics" ? "active" : ""}`}
            onClick={() => switchTab("analytics")}
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
                        <div className="server-main-col">
                          <div className="server-symbol">
                            <Server size={19} />
                          </div>

                          <div className="server-info">
                            <div className="server-title-row">
                              <span className="server-name">{server.name}</span>
                              <span className="version-pill">v{server.config_version}</span>
                            </div>
                            <div className="server-address">
                              <span className="ip-text">{server.ip}</span>
                              {server.active_method ? (
                                <span className="active-carrier-tag">
                                  {" "}
                                  • Method {String(server.active_method_id).padStart(2, "0")} (
                                  {server.active_method} {server.active_security}%) • Port{" "}
                                  {server.active_port || 28000 + server.active_method_id} •{" "}
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
                        </div>

                        <div className="server-controls-col">
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

                          <div className="server-buttons-group">
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
                                {copiedID === server.id ? (
                                  <Check size={15} />
                                ) : (
                                  <Copy size={15} />
                                )}
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
                                handleServerAction(
                                  server.id,
                                  server.running ? "pause" : "play"
                                )
                              }
                              title={server.running ? "Pause discovery" : "Start discovery"}
                              aria-label={
                                server.running ? "Pause discovery" : "Start discovery"
                              }
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
                        </div>
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
                                  <div className="history-head">
                                    <span className="history-method">
                                      #{String(item.method_id).padStart(2, "0")}{" "}
                                      {item.method_name}
                                    </span>
                                    <span
                                      className={`sec-badge ${securityTierClass(
                                        item.security
                                      )}`}
                                    >
                                      {item.security}%
                                    </span>
                                  </div>

                                  <span className="history-meta">
                                    Port {item.port || 28000 + item.method_id} •{" "}
                                    {item.latency_ms}ms • {itemWho || item.direction}
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
                  onChange={(e) => handleSelectServer(e.target.value)}
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
                    const isPinging = pingingKey === tunnelKey;
                    const noticeText = savedNotice[tunnelKey];

                    return (
                      <article
                        className={`tunnel-card ${expanded ? "expanded" : ""}`}
                        key={tunnel.id}
                      >
                        {/* Top Ribbon: Method ID, Name, Protocol Badge (TCP / TCP+UDP), and Toggle */}
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

                            <span className="proto-badge">
                              {tunnel.traffic_type.toUpperCase()}
                            </span>

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

                        {/* Lower Narrow Footer: Port, Security %, Ping Result, and Ping Button */}
                        <div
                          className="server-subbar"
                          style={{
                            padding: "6px 14px",
                            display: "flex",
                            alignItems: "center",
                            justifyContent: "space-between",
                            gap: "8px",
                            flexWrap: "wrap",
                          }}
                        >
                          <div
                            style={{
                              display: "flex",
                              alignItems: "center",
                              gap: "6px",
                              flexWrap: "wrap",
                            }}
                          >
                            <span className="port-chip">:{tunnel.listen_port}</span>

                            <span className={`sec-badge ${securityTierClass(tunnel.security)}`}>
                              {tunnel.security}%
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
                          </div>

                          <button
                            type="button"
                            className="next-method-btn"
                            style={{ padding: "4px 10px", fontSize: "11.5px" }}
                            disabled={isPinging || !tunnel.implemented}
                            onClick={() => handlePingTunnel(selectedServer.id, tunnel.id)}
                            title={`Test ping on ${tunnel.name} (:${tunnel.listen_port})`}
                          >
                            <Activity size={12} />
                            <span>{isPinging ? "Pinging..." : "Ping"}</span>
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
                                  placeholder="32001, 32002"
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

                              <div className="form-field">
                                <label htmlFor={`spd-${tunnel.id}`}>
                                  SPEED LIMIT (MB/S, 0=UNLIMITED)
                                </label>
                                <input
                                  id={`spd-${tunnel.id}`}
                                  disabled={role === "agent"}
                                  placeholder="0"
                                  value={draft.speed_limit_mbps ?? "0"}
                                  onChange={(e) =>
                                    updateDraftTunnel(selectedServer.id, {
                                      ...draft,
                                      speed_limit_mbps: e.target.value,
                                    })
                                  }
                                />
                              </div>

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

            <div className="chart-card sahand-chart-card">
              <div className="sahand-chart-layout">
                <div className="sahand-y-axis">
                  {yAxisTicks.map((val, i) => (
                    <span key={i}>{formatBytes(val)}</span>
                  ))}
                </div>

                <div className="sahand-plot-area">
                  <div className="sahand-grid-lines">
                    {yAxisTicks.map((_, i) => (
                      <div className="y-grid-line" key={i} />
                    ))}
                  </div>

                  <div
                    className={`sahand-bars-grid ${
                      analyticsRange === 30 ? "range-30" : "range-7"
                    }`}
                  >
                    {visibleAnalytics.map((day, idx) => {
                      const rxPct =
                        day.rx_bytes > 0
                          ? Math.max(4, Math.round((day.rx_bytes / chartScaleMax) * 100))
                          : 2;
                      const txPct =
                        day.tx_bytes > 0
                          ? Math.max(4, Math.round((day.tx_bytes / chartScaleMax) * 100))
                          : 2;
                      const shortDate = day.date.slice(5);
                      const showLabel =
                        analyticsRange === 7 ||
                        idx === 0 ||
                        idx === visibleAnalytics.length - 1 ||
                        idx % 5 === 0;

                      return (
                        <div
                          className="sahand-day-col"
                          key={day.date}
                          title={`${day.date} • ↓ ${formatBytes(day.rx_bytes)} | ↑ ${formatBytes(
                            day.tx_bytes
                          )}`}
                        >
                          <div className="sahand-day-bars">
                            <div
                              className="bar rx-bar sahand-bar"
                              style={{ height: `${rxPct}%` }}
                            />
                            <div
                              className="bar tx-bar sahand-bar"
                              style={{ height: `${txPct}%` }}
                            />
                          </div>
                          <div className="sahand-date-cell">
                            {showLabel ? shortDate : ""}
                          </div>
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
