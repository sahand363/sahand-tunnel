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

type GREFRPForwardRule = {
  name: string;
  protocol: string;
  local_addr: string;
  local_port: string;
  remote_port: string;
  use_encryption: boolean;
  use_compression: boolean;
  proxy_proto_v2: boolean;
};

type GREFRPDiagnostics = {
  engine_name: string;
  gre_interface_status: string;
  gre_private_ping_ok: boolean;
  gre_packet_loss_pct: number;
  gre_rtt_ms: number;
  frps_service_status: string;
  frpc_service_status: string;
  active_path: string;
  port_forward_status: string;
  service_uptime: string;
  reconnect_count: number;
  last_failure_reason?: string;
  last_recovery_at?: string;
  recent_logs?: string[];
};

type GREFRPConfig = {
  internal_engine: string;
  local_public_ip: string;
  remote_public_ip: string;
  gre_interface_name: string;
  private_subnet_cidr: string;
  local_private_ip: string;
  remote_private_ip: string;
  mtu: number;
  route_config: string;
  health_check_sec: number;
  failure_threshold: number;
  recovery_threshold: number;
  auto_public_fallback: boolean;
  auto_restore_gre: boolean;
  frp_version: string;
  frp_transport: string;
  frp_server_port: number;
  frp_auth_token: string;
  frp_encryption: boolean;
  frp_compression: boolean;
  frp_tcp_mux: boolean;
  frp_proxy_proto_v2: boolean;
  forwarding_rules: GREFRPForwardRule[];
  diagnostics: GREFRPDiagnostics;
};

type SpoofDirectionCheck = {
  supported: boolean;
  status_badge: string;
  spoof_ip_tested: string;
  observed_source_ip?: string;
  packets_sent: number;
  packets_received: number;
  detail: string;
};

type SpoofCapabilityReport = {
  tested: boolean;
  overall_supported: boolean;
  overall_badge: string;
  summary: string;
  master_to_agent: SpoofDirectionCheck;
  agent_to_master: SpoofDirectionCheck;
  tested_at?: string;
};

type SpoofTesterResult = {
  ip: string;
  received: number;
  sent: number;
  loss_pct: number;
};

type SpoofTesterStatus = {
  status: string;
  mode: string;
  protocol: string;
  error?: string;
  progress: number;
  passed: SpoofTesterResult[];
  started?: string;
  finished?: string;
};

type SpoofWGHealth = {
  binary_installed: boolean;
  binary_version?: string;
  binary_sha256_ok?: boolean;
  wg_tools_present?: boolean;
  core_active: boolean;
  wg_active: boolean;
  peer_ping: boolean;
  real_spoof_active?: boolean;
  spoof_mode_badge?: string;
  warning_banner?: string;
  handshake?: string;
  active_path?: string;
  last_error?: string;
};

type SpoofWGConfig = {
  role: string;
  service_enabled: boolean;
  require_real_spoof?: boolean;
  peer_public_ip: string;
  local_public_ip: string;
  spoof_listen_port: number;
  recv_port: number;
  spoof_port: number;
  spoof_ips: string[];
  send_transport: string;
  recv_transport: string;
  wg_interface: string;
  wg_priv_key?: string;
  wg_pub_key: string;
  wg_peer_pub: string;
  wg_peer_priv?: string;
  wg_local_ip: string;
  wg_peer_ip: string;
  wg_listen: number;
  core_port: number;
  wg_mtu: number;
  last_bundle?: string;
  last_error?: string;
  updated_at?: string;
  health: SpoofWGHealth;
  tester?: SpoofTesterStatus;
};

type SpoofNativeHealth = {
  binary_installed: boolean;
  binary_version?: string;
  binary_sha256_ok?: boolean;
  wg_tools_present?: boolean;
  core_active: boolean;
  wg_active: boolean;
  end_to_end_verified: boolean;
  real_spoof_active: boolean;
  connection_state: string;
  status_badge: string;
  active_adapter: string;
  active_path?: string;
  handshake?: string;
  last_verified_at?: string;
  last_rtt_ms?: number;
  packet_loss_pct?: number;
  warning_banner?: string;
  security_note?: string;
  last_error?: string;
};

type SpoofNativeConfig = {
  role: string;
  mode: string; // "pure" | "wireguard" | "quic" | "noise"
  service_enabled: boolean;
  strict_real_spoof: boolean;
  peer_public_ip: string;
  local_public_ip: string;
  spoof_listen_port: number;
  recv_port: number;
  spoof_port: number;
  spoof_ips: string[];
  send_transport: string;
  recv_transport: string;
  core_port: number;
  adapter_port: number;
  mtu: number;
  keepalive_sec: number;
  timeout_sec: number;
  packet_count: number;
  max_loss_pct: number;
  wg_interface: string;
  wg_priv_key?: string;
  wg_pub_key?: string;
  wg_peer_pub?: string;
  wg_peer_priv?: string;
  wg_local_ip?: string;
  wg_peer_ip?: string;
  noise_priv_key?: string;
  noise_pub_key?: string;
  noise_peer_pub?: string;
  noise_peer_priv?: string;
  last_bundle?: string;
  last_error?: string;
  updated_at?: string;
  health: SpoofNativeHealth;
  tester?: SpoofTesterStatus;
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
  raw_transport?: string;
  gre_frp?: GREFRPConfig;
  spoof_wg?: SpoofWGConfig;
  spoof_native?: SpoofNativeConfig;
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

function defaultClientGREFRP(listenPort: number, peerIP: string): GREFRPConfig {
  return {
    internal_engine: "gre-frp",
    local_public_ip: "",
    remote_public_ip: peerIP,
    gre_interface_name: "sahand-gre0",
    private_subnet_cidr: "10.77.25.0/30",
    local_private_ip: "10.77.25.1",
    remote_private_ip: "10.77.25.2",
    mtu: 1400,
    route_config: "10.77.25.0/30 via sahand-gre0",
    health_check_sec: 5,
    failure_threshold: 3,
    recovery_threshold: 2,
    auto_public_fallback: true,
    auto_restore_gre: true,
    frp_version: "0.61.1",
    frp_transport: "tcp",
    frp_server_port: listenPort || 28025,
    frp_auth_token: "",
    frp_encryption: true,
    frp_compression: false,
    frp_tcp_mux: true,
    frp_proxy_proto_v2: false,
    forwarding_rules: [
      {
        name: "rule-01",
        protocol: "tcp+udp",
        local_addr: "127.0.0.1",
        local_port: "32025",
        remote_port: "32025",
        use_encryption: true,
        use_compression: false,
        proxy_proto_v2: false,
      },
    ],
    diagnostics: {
      engine_name: "gre-frp",
      gre_interface_status: "READY",
      gre_private_ping_ok: false,
      gre_packet_loss_pct: 0,
      gre_rtt_ms: 0,
      frps_service_status: "READY",
      frpc_service_status: "READY",
      active_path: "GRE",
      port_forward_status: "READY",
      service_uptime: "0s",
      reconnect_count: 0,
      recent_logs: [],
    },
  };
}

function defaultClientSpoofWG(role: Role, peerIP: string): SpoofWGConfig {
  const isLocal = role === "master";
  return {
    role: isLocal ? "local" : "remote",
    service_enabled: false,
    require_real_spoof: false,
    peer_public_ip: peerIP,
    local_public_ip: "",
    spoof_listen_port: 8090,
    recv_port: 5001,
    spoof_port: isLocal ? 443 : 8090,
    spoof_ips: ["8.8.8.8"],
    send_transport: isLocal ? "tcp" : "udp",
    recv_transport: isLocal ? "udp" : "tcp",
    wg_interface: "wg-spoof",
    wg_pub_key: "",
    wg_peer_pub: "",
    wg_local_ip: isLocal ? "10.20.0.1" : "10.20.0.2",
    wg_peer_ip: isLocal ? "10.20.0.2" : "10.20.0.1",
    wg_listen: 51820,
    core_port: 5000,
    wg_mtu: 1280,
    health: {
      binary_installed: false,
      core_active: false,
      wg_active: false,
      peer_ping: false,
      real_spoof_active: false,
      spoof_mode_badge: "FALLBACK ONLY (NO IP SPOOFING)",
      active_path: "DIRECT_CARRIER_FALLBACK",
    },
    tester: {
      status: "idle",
      mode: isLocal ? "sender" : "receiver",
      protocol: "icmp",
      progress: 0,
      passed: [],
    },
  };
}

function defaultClientSpoofNative(role: Role, peerIP: string): SpoofNativeConfig {
  const isLocal = role === "master";
  return {
    role: isLocal ? "local" : "remote",
    mode: "pure",
    service_enabled: false,
    strict_real_spoof: true,
    peer_public_ip: peerIP,
    local_public_ip: "",
    spoof_listen_port: 8091,
    recv_port: 5011,
    spoof_port: isLocal ? 443 : 8091,
    spoof_ips: [],
    send_transport: isLocal ? "tcp" : "udp",
    recv_transport: isLocal ? "udp" : "tcp",
    core_port: 5010,
    adapter_port: 51827,
    mtu: 1280,
    keepalive_sec: 25,
    timeout_sec: 30,
    packet_count: 10,
    max_loss_pct: 20,
    wg_interface: "wg-spoof27",
    wg_local_ip: isLocal ? "10.27.0.1" : "10.27.0.2",
    wg_peer_ip: isLocal ? "10.27.0.2" : "10.27.0.1",
    health: {
      binary_installed: false,
      core_active: false,
      wg_active: false,
      end_to_end_verified: false,
      real_spoof_active: false,
      connection_state: "DISCONNECTED",
      status_badge: "DISCONNECTED",
      active_adapter: "pure",
      active_path: "NONE",
    },
    tester: {
      status: "idle",
      mode: isLocal ? "sender" : "receiver",
      protocol: "icmp",
      progress: 0,
      passed: [],
    },
  };
}

function parseSpoofIPsCSV(raw: string): string[] {
  return raw
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
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
  const [spoofIPsRawDraft, setSpoofIPsRawDraft] = useState<Record<string, string>>({});
  const [savingTunnelKey, setSavingTunnelKey] = useState<string | null>(null);
  const [savedNotice, setSavedNotice] = useState<Record<string, string>>({});
  const [tunnelError, setTunnelError] = useState<Record<string, string>>({});
  const [pingingKey, setPingingKey] = useState<string | null>(null);
  const [greActionBusy, setGreActionBusy] = useState<string | null>(null);
  const [greActionNotice, setGreActionNotice] = useState<string>("");

  // Bidirectional Spoof Capability states (shared on top of Method 26 & Method 27)
  const [spoofCapabilities, setSpoofCapabilities] = useState<
    Record<string, SpoofCapabilityReport>
  >({});
  const [verifyingSpoofCapID, setVerifyingSpoofCapID] = useState<string | null>(
    null
  );
  const [spoofCapError, setSpoofCapError] = useState<Record<string, string>>({});
  const [capCustomIPsDraft, setCapCustomIPsDraft] = useState<
    Record<string, string>
  >({});

  // Method 26 states
  const [spoofActionBusy, setSpoofActionBusy] = useState<string | null>(null);
  const [spoofActionNotice, setSpoofActionNotice] = useState<string>("");
  const [spoofBundleInput, setSpoofBundleInput] = useState<string>("");
  const [copiedBundle, setCopiedBundle] = useState<boolean>(false);

  const [testerMode, setTesterMode] = useState<"receiver" | "sender">("receiver");
  const [testerProto, setTesterProto] = useState<"icmp" | "tcp">("icmp");
  const [testerSourcesRaw, setTesterSourcesRaw] = useState<string>(
    "8.8.8.8, 1.1.1.1, 9.9.9.9, 208.67.222.222"
  );
  const [testerDstIP, setTesterDstIP] = useState<string>("");
  const [testerDstPort, setTesterDstPort] = useState<number>(80);
  const [testerTimeout, setTesterTimeout] = useState<number>(30);
  const [testerPacketCount, setTesterPacketCount] = useState<number>(10);
  const [testerMaxLoss, setTesterMaxLoss] = useState<number>(20);

  // Method 27 (Independent Native Spoof Engine) states
  const [m27ActionBusy, setM27ActionBusy] = useState<string | null>(null);
  const [m27ActionNotice, setM27ActionNotice] = useState<string>("");
  const [m27BundleInput, setM27BundleInput] = useState<string>("");
  const [copiedM27Bundle, setCopiedM27Bundle] = useState<boolean>(false);
  const [m27TesterMode, setM27TesterMode] = useState<"receiver" | "sender">("receiver");
  const [m27TesterProto, setM27TesterProto] = useState<"icmp" | "tcp">("icmp");
  const [m27TesterSourcesRaw, setM27TesterSourcesRaw] = useState<string>(
    "8.8.8.8, 1.1.1.1, 9.9.9.9, 208.67.222.222"
  );
  const [m27TesterDstIP, setM27TesterDstIP] = useState<string>("");
  const [m27TesterDstPort, setM27TesterDstPort] = useState<number>(80);

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
      if (data.spoof_capabilities && typeof data.spoof_capabilities === "object") {
        setSpoofCapabilities(data.spoof_capabilities);
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

  async function handleVerifySpoofCapability(
    serverID: string,
    rawCandidatesCSV?: string
  ) {
    if (verifyingSpoofCapID) return;
    setVerifyingSpoofCapID(serverID);
    setSpoofCapError((prev) => {
      const next = { ...prev };
      delete next[serverID];
      return next;
    });

    const csv =
      rawCandidatesCSV !== undefined
        ? rawCandidatesCSV
        : capCustomIPsDraft[serverID] ||
          "172.67.150.10, 1.1.1.1, 9.9.9.9, 8.8.8.8";
    const parsedList = parseSpoofIPsCSV(csv);

    try {
      const res = await fetch("/api/v1/tunnels/spoof-capability", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          server_id: serverID,
          spoof_ip: csv,
          spoof_ips:
            parsedList.length > 0
              ? parsedList
              : ["172.67.150.10", "1.1.1.1", "8.8.8.8"],
        }),
      });
      if (res.ok) {
        const data = await res.json();
        if (data.report) {
          setSpoofCapabilities((prev) => ({
            ...prev,
            [serverID]: data.report,
          }));
        }
        await fetchState();
      } else {
        const errText = await res.text();
        setSpoofCapError((prev) => ({
          ...prev,
          [serverID]: errText.trim() || "Verification failed",
        }));
      }
    } catch (e) {
      setSpoofCapError((prev) => ({
        ...prev,
        [serverID]: String(e),
      }));
    } finally {
      setVerifyingSpoofCapID(null);
    }
  }

  async function handleGREFRPServiceAction(serverID: string, action: string) {
    if (greActionBusy) return;
    setGreActionBusy(action);
    setGreActionNotice("");
    try {
      const res = await fetch("/api/v1/tunnels/gre-frp", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ server_id: serverID, action }),
      });
      if (res.ok) {
        const data = await res.json();
        setGreActionNotice(data.message || "Operation completed");
        await fetchState();
      } else {
        setGreActionNotice("Error: " + (await res.text()));
      }
    } finally {
      setGreActionBusy(null);
    }
  }

  async function handleSpoofWGAction(
    serverID: string,
    action:
      | "bundle"
      | "import"
      | "up"
      | "down"
      | "restart"
      | "install_binary"
      | "tester_start"
      | "tester_stop"
      | "tester_clear",
    currentDraft: TunnelConfig
  ) {
    if (spoofActionBusy) return;
    setSpoofActionBusy(action);
    setSpoofActionNotice("");
    const key = `${serverID}:26`;
    const rawIPs = spoofIPsRawDraft[key];
    const effectiveSpoofWG = currentDraft.spoof_wg
      ? {
          ...currentDraft.spoof_wg,
          spoof_ips:
            rawIPs !== undefined
              ? parseSpoofIPsCSV(rawIPs)
              : currentDraft.spoof_wg.spoof_ips,
        }
      : undefined;

    const testerReq =
      action === "tester_start"
        ? {
            action: "start",
            mode: testerMode,
            protocol: testerProto,
            sources: testerSourcesRaw
              .split(/[\n,]+/)
              .map((s) => s.trim())
              .filter(Boolean),
            dst_ip:
              testerDstIP.trim() ||
              effectiveSpoofWG?.peer_public_ip ||
              selectedServer?.ip ||
              "",
            dst_port: testerDstPort || 80,
            timeout: testerTimeout || 30,
            packet_count: testerPacketCount || 10,
            max_loss: testerMaxLoss,
          }
        : undefined;

    try {
      const res = await fetch("/api/v1/tunnels/spoof-wg", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          server_id: serverID,
          action,
          bundle: spoofBundleInput,
          spoof_wg: effectiveSpoofWG,
          tester_req: testerReq,
        }),
      });
      if (res.ok) {
        const data = await res.json();
        setSpoofActionNotice(data.message || "Operation completed");
        if (data.spoof_wg) {
          updateDraftTunnel(serverID, {
            ...currentDraft,
            spoof_wg: data.spoof_wg,
          });
          setSpoofIPsRawDraft((prev) => ({
            ...prev,
            [key]: (data.spoof_wg.spoof_ips || []).join(", "),
          }));
        }
        if (action === "import") {
          setSpoofBundleInput("");
        }
        await fetchState();
      } else {
        setSpoofActionNotice("Error: " + (await res.text()));
      }
    } finally {
      setSpoofActionBusy(null);
    }
  }

  async function handleSpoofNativeAction(
    serverID: string,
    action:
      | "save"
      | "bundle"
      | "import"
      | "up"
      | "down"
      | "restart"
      | "verify_pipe"
      | "install_binary"
      | "tester_start"
      | "tester_stop"
      | "tester_clear",
    currentDraft: TunnelConfig
  ) {
    if (m27ActionBusy) return;
    setM27ActionBusy(action);
    setM27ActionNotice("");
    const key = `${serverID}:27`;
    const rawIPs = spoofIPsRawDraft[key];
    const effectiveNative = currentDraft.spoof_native
      ? {
          ...currentDraft.spoof_native,
          spoof_ips:
            rawIPs !== undefined
              ? parseSpoofIPsCSV(rawIPs)
              : currentDraft.spoof_native.spoof_ips,
        }
      : undefined;

    const testerReq =
      action === "tester_start"
        ? {
            action: "start",
            mode: m27TesterMode,
            protocol: m27TesterProto,
            sources: m27TesterSourcesRaw
              .split(/[\n,]+/)
              .map((s) => s.trim())
              .filter(Boolean),
            dst_ip:
              m27TesterDstIP.trim() ||
              effectiveNative?.peer_public_ip ||
              selectedServer?.ip ||
              "",
            dst_port: m27TesterDstPort || 80,
            timeout: effectiveNative?.timeout_sec || 30,
            packet_count: effectiveNative?.packet_count || 10,
            max_loss: effectiveNative?.max_loss_pct ?? 20,
          }
        : undefined;

    try {
      const res = await fetch("/api/v1/tunnels/spoof-native", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          server_id: serverID,
          action,
          bundle: m27BundleInput,
          spoof_native: effectiveNative,
          tester_req: testerReq,
        }),
      });
      if (res.ok) {
        const data = await res.json();
        setM27ActionNotice(data.message || "Operation completed");
        if (data.spoof_native) {
          updateDraftTunnel(serverID, {
            ...currentDraft,
            spoof_native: data.spoof_native,
          });
          setSpoofIPsRawDraft((prev) => ({
            ...prev,
            [key]: (data.spoof_native.spoof_ips || []).join(", "),
          }));
        }
        if (action === "import") {
          setM27BundleInput("");
        }
        await fetchState();
      } else {
        setM27ActionNotice("Error: " + (await res.text()));
      }
    } finally {
      setM27ActionBusy(null);
    }
  }

  async function copyTextUniversal(text: string): Promise<boolean> {
    if (!text) return false;
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
        return true;
      }
    } catch {
      // Fall through to textarea fallback
    }
    try {
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.setAttribute("readonly", "");
      ta.style.position = "fixed";
      ta.style.top = "-9999px";
      ta.style.left = "-9999px";
      document.body.appendChild(ta);
      ta.focus();
      ta.select();
      ta.setSelectionRange(0, text.length);
      const ok = document.execCommand("copy");
      document.body.removeChild(ta);
      if (ok) return true;
    } catch {
      // Fall through to prompt fallback
    }
    window.prompt("Copy text to clipboard:", text);
    return true;
  }

  async function copySpoofBundleText(bundleStr: string) {
    if (await copyTextUniversal(bundleStr)) {
      setCopiedBundle(true);
      setTimeout(() => setCopiedBundle(false), 1800);
    }
  }

  async function copyM27BundleText(bundleStr: string) {
    if (await copyTextUniversal(bundleStr)) {
      setCopiedM27Bundle(true);
      setTimeout(() => setCopiedM27Bundle(false), 1800);
    }
  }

  async function copyToken(id: string, token: string) {
    let tok = token;
    if (!tok) {
      try {
        const res = await fetch("/api/v1/state");
        if (res.ok) {
          const data = await res.json();
          const srv = (data.servers || []).find((s: ServerPeer) => s.id === id);
          if (srv?.token) tok = srv.token;
        }
      } catch {
        // Ignore fetch fallback errors
      }
    }
    if (await copyTextUniversal(tok)) {
      setCopiedID(id);
      setTimeout(() => setCopiedID(null), 1800);
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
    setTunnelError((prev) => {
      const next = { ...prev };
      delete next[key];
      return next;
    });

    const safeSpeed =
      updated.speed_limit_mbps && updated.speed_limit_mbps.trim() !== ""
        ? updated.speed_limit_mbps.trim()
        : "0";

    const rawSpoofIPs = spoofIPsRawDraft[key];
    const finalSpoofWG =
      updated.id === 26 && updated.spoof_wg
        ? {
            ...updated.spoof_wg,
            spoof_ips:
              rawSpoofIPs !== undefined
                ? parseSpoofIPsCSV(rawSpoofIPs)
                : updated.spoof_wg.spoof_ips,
          }
        : updated.spoof_wg;

    const finalSpoofNative =
      updated.id === 27 && updated.spoof_native
        ? {
            ...updated.spoof_native,
            spoof_ips:
              rawSpoofIPs !== undefined
                ? parseSpoofIPsCSV(rawSpoofIPs)
                : updated.spoof_native.spoof_ips,
          }
        : updated.spoof_native;

    const payload: TunnelConfig = {
      ...updated,
      speed_limit_mbps: safeSpeed,
      spoof_wg: finalSpoofWG,
      spoof_native: finalSpoofNative,
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
        setSpoofIPsRawDraft((prev) => {
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
      } else {
        const errText = await res.text();
        setTunnelError((prev) => ({ ...prev, [key]: errText }));
      }
    } finally {
      setSavingTunnelKey(null);
    }
  }

  // Renders the shared Bidirectional Spoof Capability Verifier box at the top of Method 26 & Method 27
  function renderSpoofCapabilityPrecheckBox(
    serverID: string,
    defaultCandidateCSV: string,
    onApplyWorkingIPs: (ips: string[]) => void
  ) {
    const cap = spoofCapabilities[serverID];
    const isBusy = verifyingSpoofCapID === serverID;
    const errMsg = spoofCapError[serverID];

    const customCSVValue =
      capCustomIPsDraft[serverID] !== undefined
        ? capCustomIPsDraft[serverID]
        : defaultCandidateCSV || "172.67.150.10, 1.1.1.1, 9.9.9.9, 8.8.8.8";

    const borderCol = !cap?.tested
      ? "rgba(56, 189, 248, 0.35)"
      : cap.overall_supported
      ? "rgba(16, 185, 129, 0.55)"
      : "rgba(239, 68, 68, 0.55)";

    const bgCol = !cap?.tested
      ? "rgba(15, 23, 42, 0.4)"
      : cap.overall_supported
      ? "rgba(16, 185, 129, 0.1)"
      : "rgba(239, 68, 68, 0.1)";

    const discoveredWorkingIPs: string[] = [];
    if (cap?.tested) {
      for (const side of [cap.master_to_agent, cap.agent_to_master]) {
        if (side?.supported && side.observed_source_ip) {
          for (const ip of parseSpoofIPsCSV(side.observed_source_ip)) {
            if (!discoveredWorkingIPs.includes(ip)) {
              discoveredWorkingIPs.push(ip);
            }
          }
        }
      }
    }

    return (
      <div
        style={{
          marginBottom: "14px",
          padding: "12px 14px",
          borderRadius: "10px",
          border: `1px solid ${borderCol}`,
          background: bgCol,
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
            flexWrap: "wrap",
            gap: "8px",
          }}
        >
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: "8px",
              flexWrap: "wrap",
            }}
          >
            <Shield size={15} />
            <strong style={{ fontSize: "13px" }}>
              Pre-Flight Server Spoof Capability Check (Master ↔ Agent)
            </strong>
            {cap?.tested && (
              <span
                className={`disc-pill ${
                  cap.overall_supported ? "disc-ok" : "disc-fail"
                }`}
              >
                {cap.overall_supported
                  ? "✓ BOTH SERVERS SUPPORT SPOOFING"
                  : `✕ ${cap.overall_badge}`}
              </span>
            )}
          </div>

          <div style={{ display: "flex", gap: "6px", flexWrap: "wrap" }}>
            {discoveredWorkingIPs.length > 0 && (
              <button
                type="button"
                className="next-method-btn"
                style={{ borderColor: "#10b981", color: "#10b981" }}
                onClick={() => onApplyWorkingIPs(discoveredWorkingIPs)}
                title="Copy the verified working Spoof IP(s) into this tunnel's configuration"
              >
                <Check size={13} />
                <span>
                  Use Working IP ({discoveredWorkingIPs.join(", ")})
                </span>
              </button>
            )}

            <button
              type="button"
              className="next-method-btn"
              disabled={isBusy}
              onClick={() =>
                handleVerifySpoofCapability(serverID, customCSVValue)
              }
              title="Test your custom candidate IPs (plus auto Same-/24 neighbor IP) using iptables SNAT+ping, tcpdump icmp, and raw ICMP/TCP/UDP"
            >
              <Activity size={13} />
              <span>
                {isBusy
                  ? "Testing Both Sides (~4s)..."
                  : "Verify Spoof Support (Both Sides)"}
              </span>
            </button>
          </div>
        </div>

        {/* Custom Candidate Spoof IP Input Row */}
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "1fr",
            gap: "4px",
            marginTop: "2px",
          }}
        >
          <label
            style={{
              fontSize: "10.5px",
              fontWeight: 700,
              opacity: 0.78,
              letterSpacing: "0.04em",
            }}
          >
            CUSTOM CANDIDATE SPOOF IPS TO TEST (CSV — ALSO AUTO-TESTS SAME-/24 SUBNET NEIGHBOR IP)
          </label>
          <input
            value={customCSVValue}
            onChange={(e) =>
              setCapCustomIPsDraft((prev) => ({
                ...prev,
                [serverID]: e.target.value,
              }))
            }
            placeholder="172.67.150.10, 1.1.1.1, 9.9.9.9, 8.8.8.8"
            style={{
              width: "100%",
              padding: "7px 10px",
              fontSize: "12.5px",
              borderRadius: "8px",
            }}
          />
        </div>

        <div style={{ fontSize: "12px", opacity: 0.9 }}>
          {errMsg ? (
            <span style={{ color: "#ef4444" }}>
              Verification error: {errMsg}
            </span>
          ) : cap?.tested ? (
            cap.summary
          ) : (
            "Enter any candidate Spoof IPs above and click 'Verify Spoof Support (Both Sides)' to test iptables SNAT + ping + tcpdump ICMP as well as raw ICMP/TCP/UDP packets."
          )}
        </div>

        {cap?.tested && (
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))",
              gap: "8px",
              marginTop: "2px",
            }}
          >
            <div
              style={{
                padding: "8px 10px",
                borderRadius: "8px",
                background: "rgba(15, 23, 42, 0.45)",
                border: "1px solid rgba(148, 163, 184, 0.18)",
                fontSize: "11.5px",
              }}
            >
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  marginBottom: "4px",
                }}
              >
                <strong>1. Master (Iran) → Agent (Foreign)</strong>
                <span
                  className={`disc-pill ${
                    cap.master_to_agent.supported ? "disc-ok" : "disc-fail"
                  }`}
                >
                  {cap.master_to_agent.supported
                    ? `✓ ${cap.master_to_agent.status_badge}`
                    : cap.master_to_agent.status_badge}
                </span>
              </div>
              <div style={{ opacity: 0.85 }}>{cap.master_to_agent.detail}</div>
            </div>

            <div
              style={{
                padding: "8px 10px",
                borderRadius: "8px",
                background: "rgba(15, 23, 42, 0.45)",
                border: "1px solid rgba(148, 163, 184, 0.18)",
                fontSize: "11.5px",
              }}
            >
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  marginBottom: "4px",
                }}
              >
                <strong>2. Agent (Foreign) → Master (Iran)</strong>
                <span
                  className={`disc-pill ${
                    cap.agent_to_master.supported ? "disc-ok" : "disc-fail"
                  }`}
                >
                  {cap.agent_to_master.supported
                    ? `✓ ${cap.agent_to_master.status_badge}`
                    : cap.agent_to_master.status_badge}
                </span>
              </div>
              <div style={{ opacity: 0.85 }}>{cap.agent_to_master.detail}</div>
            </div>
          </div>
        )}
      </div>
    );
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
                    {batchPortNotice
                      ? `✓ ${batchPortNotice}`
                      : copiedID === selectedServer.id
                      ? "✓ Connection Token Copied to Clipboard!"
                      : ""}
                  </div>

                  <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                    {role === "master" && selectedServer && (
                      <button
                        type="button"
                        className="next-method-btn"
                        style={
                          copiedID === selectedServer.id
                            ? {
                                borderColor: "#10b981",
                                color: "#10b981",
                              }
                            : undefined
                        }
                        onClick={() => copyToken(selectedServer.id, selectedServer.token)}
                      >
                        {copiedID === selectedServer.id ? (
                          <Check size={14} />
                        ) : (
                          <Copy size={14} />
                        )}
                        <span>
                          {copiedID === selectedServer.id
                            ? "✓ Token Copied!"
                            : "Copy Token"}
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
                      placeholder="st2.eyJ2IjoyLC..."
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
                  const isCopied = copiedID === server.id;
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
                                className="next-method-btn"
                                onClick={() => copyToken(server.id, server.token)}
                                title="Copy connection token (includes current ports)"
                                aria-label="Copy connection token"
                                style={
                                  isCopied
                                    ? {
                                        borderColor: "#10b981",
                                        color: "#10b981",
                                        padding: "5px 10px",
                                      }
                                    : { padding: "5px 10px" }
                                }
                              >
                                {isCopied ? <Check size={14} /> : <Copy size={14} />}
                                <span>{isCopied ? "Copied!" : "Copy Token"}</span>
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
                            Recent Working Methods ({server.recent_lifelines?.length || 0}/20)
                          </span>
                          {historyOpen ? (
                            <ChevronDown size={14} />
                          ) : (
                            <ChevronRight size={14} />
                          )}
                        </button>

                        <span
                          className="sync-badge"
                          style={isCopied ? { color: "#10b981", fontWeight: 700 } : undefined}
                        >
                          {switchMsg
                            ? switchMsg
                            : isCopied
                            ? "✓ Token Copied to Clipboard!"
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
                    const errBanner = tunnelError[tunnelKey];

                    const gfDraft =
                      tunnel.id === 25
                        ? draft.gre_frp ||
                          defaultClientGREFRP(draft.listen_port, selectedServer.ip)
                        : null;

                    const updateGFDraft = (patch: Partial<GREFRPConfig>) => {
                      if (!gfDraft) return;
                      const merged: GREFRPConfig = {
                        ...gfDraft,
                        ...patch,
                      };
                      updateDraftTunnel(selectedServer.id, {
                        ...draft,
                        listen_port: merged.frp_server_port || draft.listen_port,
                        gre_frp: merged,
                      });
                    };

                    const swgDraft =
                      tunnel.id === 26
                        ? draft.spoof_wg ||
                          defaultClientSpoofWG(role, selectedServer.ip)
                        : null;

                    const updateSWGDraft = (patch: Partial<SpoofWGConfig>) => {
                      if (!swgDraft) return;
                      const merged: SpoofWGConfig = {
                        ...swgDraft,
                        ...patch,
                      };
                      updateDraftTunnel(selectedServer.id, {
                        ...draft,
                        spoof_wg: merged,
                      });
                    };

                    const snDraft =
                      tunnel.id === 27
                        ? draft.spoof_native ||
                          defaultClientSpoofNative(role, selectedServer.ip)
                        : null;

                    const updateSNDraft = (patch: Partial<SpoofNativeConfig>) => {
                      if (!snDraft) return;
                      const merged: SpoofNativeConfig = {
                        ...snDraft,
                        ...patch,
                      };
                      updateDraftTunnel(selectedServer.id, {
                        ...draft,
                        spoof_native: merged,
                      });
                    };

                    const spoofIPsInputValue =
                      spoofIPsRawDraft[tunnelKey] !== undefined
                        ? spoofIPsRawDraft[tunnelKey]
                        : tunnel.id === 27
                        ? (snDraft?.spoof_ips || []).join(", ")
                        : (swgDraft?.spoof_ips || []).join(", ");

                    const liveHealth = tunnel.spoof_wg?.health;
                    const liveTester = tunnel.spoof_wg?.tester;

                    const m27Health = tunnel.spoof_native?.health;
                    const m27Tester = tunnel.spoof_native?.tester;

                    const srvCap = spoofCapabilities[selectedServer.id];
                    const isVerifyingCap =
                      verifyingSpoofCapID === selectedServer.id;

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

                            {tunnel.id === 25 && tunnel.gre_frp?.diagnostics?.active_path && (
                              <span className="proto-badge">
                                PATH: {tunnel.gre_frp.diagnostics.active_path}
                              </span>
                            )}

                            {tunnel.id === 26 && tunnel.spoof_wg && (
                              <>
                                <span className="proto-badge">
                                  {tunnel.spoof_wg.send_transport.toUpperCase()}/
                                  {tunnel.spoof_wg.recv_transport.toUpperCase()} •{" "}
                                  {tunnel.spoof_wg.wg_local_ip} ↔ {tunnel.spoof_wg.wg_peer_ip}
                                </span>

                                <span
                                  className={`disc-pill ${
                                    liveHealth?.real_spoof_active
                                      ? "disc-ok"
                                      : "disc-fail"
                                  }`}
                                >
                                  {liveHealth?.real_spoof_active
                                    ? "REAL SPOOF ACTIVE"
                                    : liveHealth?.spoof_mode_badge ||
                                      "FALLBACK ONLY (NOT SPOOFING)"}
                                </span>
                              </>
                            )}

                            {tunnel.id === 27 && tunnel.spoof_native && (
                              <>
                                <span className="proto-badge">
                                  MODE: {(tunnel.spoof_native.mode || "pure").toUpperCase()} •{" "}
                                  {tunnel.spoof_native.send_transport.toUpperCase()}/
                                  {tunnel.spoof_native.recv_transport.toUpperCase()}
                                </span>

                                <span
                                  className={`disc-pill ${
                                    m27Health?.connection_state === "REAL SPOOF ACTIVE"
                                      ? "disc-ok"
                                      : "disc-fail"
                                  }`}
                                >
                                  {m27Health?.connection_state || "DISCONNECTED"}
                                </span>
                              </>
                            )}

                            {(tunnel.id === 26 || tunnel.id === 27) &&
                              srvCap?.tested && (
                                <span
                                  className={`disc-pill ${
                                    srvCap.overall_supported
                                      ? "disc-ok"
                                      : "disc-fail"
                                  }`}
                                  title={srvCap.summary}
                                >
                                  {srvCap.overall_supported
                                    ? "✓ SPOOF SUPPORTED"
                                    : `✕ ${srvCap.overall_badge}`}
                                </span>
                              )}

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

                          <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                            {(tunnel.id === 26 || tunnel.id === 27) && (
                              <button
                                type="button"
                                className="next-method-btn"
                                style={{ padding: "4px 10px", fontSize: "11.5px" }}
                                disabled={isVerifyingCap}
                                onClick={() =>
                                  handleVerifySpoofCapability(
                                    selectedServer.id,
                                    capCustomIPsDraft[selectedServer.id] ||
                                      spoofIPsInputValue ||
                                      "172.67.150.10, 1.1.1.1, 9.9.9.9, 8.8.8.8"
                                  )
                                }
                                title="Test if both Master and Agent servers allow sending spoofed-source packets"
                              >
                                <Shield size={12} />
                                <span>
                                  {isVerifyingCap ? "Verifying..." : "Verify Spoof"}
                                </span>
                              </button>
                            )}

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
                        </div>

                        {expanded &&
                          tunnel.id !== 25 &&
                          tunnel.id !== 26 &&
                          tunnel.id !== 27 && (
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

                                {tunnel.id === 24 ? (
                                  <div className="form-field">
                                    <label htmlFor={`rawmode-${tunnel.id}`}>
                                      RAW TRANSPORT MODE
                                    </label>
                                    <select
                                      id={`rawmode-${tunnel.id}`}
                                      className="server-select"
                                      disabled={role === "agent"}
                                      value={draft.raw_transport || "auto"}
                                      onChange={(e) =>
                                        updateDraftTunnel(selectedServer.id, {
                                          ...draft,
                                          raw_transport: e.target.value,
                                        })
                                      }
                                      style={{ width: "100%", padding: "10px 12px" }}
                                    >
                                      <option value="auto">
                                        Auto (Prefer RAW_IP, Fallback UDP)
                                      </option>
                                      <option value="raw_ip">
                                        Strict RAW_IP (Linux ip4:tcp Socket)
                                      </option>
                                      <option value="udp">
                                        UDP_FALLBACK (Encrypted UDP Carrier)
                                      </option>
                                    </select>
                                  </div>
                                ) : (
                                  <>
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
                                        <label htmlFor={`path-${tunnel.id}`}>
                                          HTTP / WS PATH
                                        </label>
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
                                  </>
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

                              {errBanner && (
                                <div
                                  className="form-error-banner"
                                  style={{ marginTop: "10px" }}
                                >
                                  {errBanner}
                                </div>
                              )}

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
                                    <span>
                                      {isSaving ? "Saving..." : "Save Settings"}
                                    </span>
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

                        {expanded && tunnel.id === 25 && gfDraft && (
                          <div className="tunnel-settings">
                            <div className="settings-title">
                              <Settings2 size={15} />
                              <span>1. GRE Point-to-Point Network Tunnel Settings</span>
                            </div>

                            <div className="settings-grid">
                              <div className="form-field">
                                <label>GRE INTERFACE NAME</label>
                                <input
                                  disabled={role === "agent"}
                                  value={gfDraft.gre_interface_name}
                                  onChange={(e) =>
                                    updateGFDraft({ gre_interface_name: e.target.value })
                                  }
                                  placeholder="sahand-gre0"
                                />
                              </div>

                              <div className="form-field">
                                <label>PRIVATE IPV4 SUBNET (/30)</label>
                                <input
                                  disabled={role === "agent"}
                                  value={gfDraft.private_subnet_cidr}
                                  onChange={(e) =>
                                    updateGFDraft({ private_subnet_cidr: e.target.value })
                                  }
                                  placeholder="10.77.25.0/30"
                                />
                              </div>

                              <div className="form-field">
                                <label>LOCAL GRE PRIVATE IP</label>
                                <input
                                  disabled={role === "agent"}
                                  value={gfDraft.local_private_ip}
                                  onChange={(e) =>
                                    updateGFDraft({ local_private_ip: e.target.value })
                                  }
                                  placeholder="10.77.25.1"
                                />
                              </div>

                              <div className="form-field">
                                <label>REMOTE GRE PRIVATE IP</label>
                                <input
                                  disabled={role === "agent"}
                                  value={gfDraft.remote_private_ip}
                                  onChange={(e) =>
                                    updateGFDraft({ remote_private_ip: e.target.value })
                                  }
                                  placeholder="10.77.25.2"
                                />
                              </div>

                              <div className="form-field">
                                <label>LOCAL PUBLIC IP (OPTIONAL=AUTO)</label>
                                <input
                                  disabled={role === "agent"}
                                  value={gfDraft.local_public_ip}
                                  onChange={(e) =>
                                    updateGFDraft({ local_public_ip: e.target.value })
                                  }
                                  placeholder="Auto-detect outbound IP"
                                />
                              </div>

                              <div className="form-field">
                                <label>REMOTE PUBLIC IP</label>
                                <input
                                  disabled={role === "agent"}
                                  value={gfDraft.remote_public_ip || selectedServer.ip}
                                  onChange={(e) =>
                                    updateGFDraft({ remote_public_ip: e.target.value })
                                  }
                                  placeholder={selectedServer.ip}
                                />
                              </div>

                              <div className="form-field">
                                <label>GRE MTU (576–9000)</label>
                                <input
                                  type="number"
                                  disabled={role === "agent"}
                                  value={gfDraft.mtu}
                                  onChange={(e) =>
                                    updateGFDraft({ mtu: Number(e.target.value) || 1400 })
                                  }
                                />
                              </div>

                              <div className="form-field">
                                <label>ROUTE CONFIGURATION</label>
                                <input
                                  disabled={role === "agent"}
                                  value={gfDraft.route_config}
                                  onChange={(e) =>
                                    updateGFDraft({ route_config: e.target.value })
                                  }
                                />
                              </div>

                              <div className="form-field">
                                <label>HEALTH-CHECK INTERVAL (SEC)</label>
                                <input
                                  type="number"
                                  disabled={role === "agent"}
                                  value={gfDraft.health_check_sec}
                                  onChange={(e) =>
                                    updateGFDraft({
                                      health_check_sec: Number(e.target.value) || 5,
                                    })
                                  }
                                />
                              </div>

                              <div className="form-field">
                                <label>FAILURE / RECOVERY THRESHOLD</label>
                                <div style={{ display: "flex", gap: "6px" }}>
                                  <input
                                    type="number"
                                    disabled={role === "agent"}
                                    value={gfDraft.failure_threshold}
                                    title="Failure threshold"
                                    onChange={(e) =>
                                      updateGFDraft({
                                        failure_threshold: Number(e.target.value) || 3,
                                      })
                                    }
                                  />
                                  <input
                                    type="number"
                                    disabled={role === "agent"}
                                    value={gfDraft.recovery_threshold}
                                    title="Recovery threshold"
                                    onChange={(e) =>
                                      updateGFDraft({
                                        recovery_threshold: Number(e.target.value) || 2,
                                      })
                                    }
                                  />
                                </div>
                              </div>

                              <div className="form-field">
                                <label>AUTO PUBLIC-IP FALLBACK & GRE RESTORE</label>
                                <div
                                  style={{
                                    display: "flex",
                                    gap: "14px",
                                    alignItems: "center",
                                    paddingTop: "8px",
                                    fontSize: "13px",
                                  }}
                                >
                                  <label style={{ display: "flex", gap: "6px", alignItems: "center" }}>
                                    <input
                                      type="checkbox"
                                      disabled={role === "agent"}
                                      checked={gfDraft.auto_public_fallback}
                                      onChange={(e) =>
                                        updateGFDraft({
                                          auto_public_fallback: e.target.checked,
                                        })
                                      }
                                    />
                                    <span>Public Fallback</span>
                                  </label>

                                  <label style={{ display: "flex", gap: "6px", alignItems: "center" }}>
                                    <input
                                      type="checkbox"
                                      disabled={role === "agent"}
                                      checked={gfDraft.auto_restore_gre}
                                      onChange={(e) =>
                                        updateGFDraft({
                                          auto_restore_gre: e.target.checked,
                                        })
                                      }
                                    />
                                    <span>Auto-Restore GRE</span>
                                  </label>
                                </div>
                              </div>
                            </div>

                            <div className="settings-title" style={{ marginTop: "18px" }}>
                              <Shield size={15} />
                              <span>
                                2. FRP Port-Forwarding Engine Settings (Official v{gfDraft.frp_version || "0.61.1"})
                              </span>
                            </div>

                            <div className="settings-grid">
                              <div className="form-field">
                                <label>FRP TRANSPORT PROTOCOL</label>
                                <select
                                  className="server-select"
                                  disabled={role === "agent"}
                                  value={gfDraft.frp_transport || "tcp"}
                                  onChange={(e) =>
                                    updateGFDraft({ frp_transport: e.target.value })
                                  }
                                  style={{ width: "100%", padding: "10px 12px" }}
                                >
                                  <option value="tcp">TCP</option>
                                  <option value="kcp">KCP (UDP ARQ)</option>
                                  <option value="quic">QUIC (RFC 9000)</option>
                                  <option value="websocket">WebSocket</option>
                                  <option value="wss">WSS (WebSocket over TLS)</option>
                                </select>
                              </div>

                              <div className="form-field">
                                <label>FRP SERVER BIND PORT</label>
                                <input
                                  type="number"
                                  disabled={role === "agent"}
                                  value={gfDraft.frp_server_port || draft.listen_port}
                                  onChange={(e) => {
                                    const p = Number(e.target.value) || 28025;
                                    updateGFDraft({ frp_server_port: p });
                                  }}
                                />
                              </div>

                              <div className="form-field">
                                <label>FRP AUTH TOKEN (EMPTY=PAIR TOKEN DERIVED)</label>
                                <input
                                  disabled={role === "agent"}
                                  value={gfDraft.frp_auth_token || ""}
                                  onChange={(e) =>
                                    updateGFDraft({ frp_auth_token: e.target.value })
                                  }
                                  placeholder="Derived automatically from server pairing token"
                                />
                              </div>

                              <div className="form-field">
                                <label>SPEED LIMIT (MB/S, 0=UNLIMITED)</label>
                                <input
                                  disabled={role === "agent"}
                                  value={draft.speed_limit_mbps ?? "0"}
                                  onChange={(e) =>
                                    updateDraftTunnel(selectedServer.id, {
                                      ...draft,
                                      speed_limit_mbps: e.target.value,
                                    })
                                  }
                                />
                              </div>

                              <div className="form-field" style={{ gridColumn: "1 / -1" }}>
                                <label>FRP SECURITY & MULTIPLEXING FEATURES (GRE IS UNENCRYPTED; KEEP FRP ENCRYPTION ON)</label>
                                <div
                                  style={{
                                    display: "flex",
                                    flexWrap: "wrap",
                                    gap: "16px",
                                    paddingTop: "8px",
                                    fontSize: "13px",
                                  }}
                                >
                                  <label style={{ display: "flex", gap: "6px", alignItems: "center" }}>
                                    <input
                                      type="checkbox"
                                      disabled={role === "agent"}
                                      checked={gfDraft.frp_encryption}
                                      onChange={(e) =>
                                        updateGFDraft({ frp_encryption: e.target.checked })
                                      }
                                    />
                                    <span>Transport Encryption (AEAD)</span>
                                  </label>

                                  <label style={{ display: "flex", gap: "6px", alignItems: "center" }}>
                                    <input
                                      type="checkbox"
                                      disabled={role === "agent"}
                                      checked={gfDraft.frp_compression}
                                      onChange={(e) =>
                                        updateGFDraft({ frp_compression: e.target.checked })
                                      }
                                    />
                                    <span>Compression (DEFLATE)</span>
                                  </label>

                                  <label style={{ display: "flex", gap: "6px", alignItems: "center" }}>
                                    <input
                                      type="checkbox"
                                      disabled={role === "agent"}
                                      checked={gfDraft.frp_tcp_mux}
                                      onChange={(e) =>
                                        updateGFDraft({ frp_tcp_mux: e.target.checked })
                                      }
                                    />
                                    <span>TCP Stream Multiplexing (tcpMux)</span>
                                  </label>

                                  <label style={{ display: "flex", gap: "6px", alignItems: "center" }}>
                                    <input
                                      type="checkbox"
                                      disabled={role === "agent"}
                                      checked={gfDraft.frp_proxy_proto_v2}
                                      onChange={(e) =>
                                        updateGFDraft({ frp_proxy_proto_v2: e.target.checked })
                                      }
                                    />
                                    <span>PROXY Protocol v2</span>
                                  </label>
                                </div>
                              </div>
                            </div>

                            <div
                              className="settings-title"
                              style={{
                                marginTop: "18px",
                                display: "flex",
                                justifyContent: "space-between",
                                alignItems: "center",
                              }}
                            >
                              <span>3. Port Forwarding Rules (Single Ports & Ranges e.g. 45001-45005)</span>
                              {role === "master" && (
                                <button
                                  type="button"
                                  className="next-method-btn"
                                  onClick={() => {
                                    const nextIdx = (gfDraft.forwarding_rules?.length || 0) + 1;
                                    const newRule: GREFRPForwardRule = {
                                      name: `rule-${String(nextIdx).padStart(2, "0")}`,
                                      protocol: "tcp+udp",
                                      local_addr: "127.0.0.1",
                                      local_port: String(32024 + nextIdx),
                                      remote_port: String(32024 + nextIdx),
                                      use_encryption: gfDraft.frp_encryption,
                                      use_compression: gfDraft.frp_compression,
                                      proxy_proto_v2: gfDraft.frp_proxy_proto_v2,
                                    };
                                    updateGFDraft({
                                      forwarding_rules: [
                                        ...(gfDraft.forwarding_rules || []),
                                        newRule,
                                      ],
                                    });
                                  }}
                                >
                                  <Plus size={13} />
                                  <span>Add Forwarding Rule</span>
                                </button>
                              )}
                            </div>

                            <div style={{ display: "flex", flexDirection: "column", gap: "8px", marginTop: "8px" }}>
                              {(gfDraft.forwarding_rules || []).map((rule, rIdx) => (
                                <div
                                  key={rIdx}
                                  style={{
                                    display: "grid",
                                    gridTemplateColumns: "1.1fr 0.9fr 1.1fr 1fr 1fr auto",
                                    gap: "8px",
                                    alignItems: "center",
                                    padding: "8px 10px",
                                    borderRadius: "9px",
                                    border: "1px solid rgba(148, 163, 184, 0.2)",
                                  }}
                                >
                                  <input
                                    disabled={role === "agent"}
                                    value={rule.name}
                                    placeholder="rule-01"
                                    title="Rule Name"
                                    onChange={(e) => {
                                      const next = [...gfDraft.forwarding_rules];
                                      next[rIdx] = { ...rule, name: e.target.value };
                                      updateGFDraft({ forwarding_rules: next });
                                    }}
                                  />
                                  <select
                                    className="server-select"
                                    disabled={role === "agent"}
                                    value={rule.protocol}
                                    title="Protocol"
                                    onChange={(e) => {
                                      const next = [...gfDraft.forwarding_rules];
                                      next[rIdx] = { ...rule, protocol: e.target.value };
                                      updateGFDraft({ forwarding_rules: next });
                                    }}
                                  >
                                    <option value="tcp+udp">TCP+UDP</option>
                                    <option value="tcp">TCP</option>
                                    <option value="udp">UDP</option>
                                  </select>
                                  <input
                                    disabled={role === "agent"}
                                    value={rule.local_addr}
                                    placeholder="127.0.0.1"
                                    title="Local Target Address on Agent"
                                    onChange={(e) => {
                                      const next = [...gfDraft.forwarding_rules];
                                      next[rIdx] = { ...rule, local_addr: e.target.value };
                                      updateGFDraft({ forwarding_rules: next });
                                    }}
                                  />
                                  <input
                                    disabled={role === "agent"}
                                    value={rule.remote_port}
                                    placeholder="Entry Port (45001)"
                                    title="Master Entry Port or Range (e.g. 45001-45005)"
                                    onChange={(e) => {
                                      const next = [...gfDraft.forwarding_rules];
                                      next[rIdx] = { ...rule, remote_port: e.target.value };
                                      updateGFDraft({ forwarding_rules: next });
                                    }}
                                  />
                                  <input
                                    disabled={role === "agent"}
                                    value={rule.local_port}
                                    placeholder="Dest Port (45001)"
                                    title="Agent Destination Port or Range (e.g. 45001-45005)"
                                    onChange={(e) => {
                                      const next = [...gfDraft.forwarding_rules];
                                      next[rIdx] = { ...rule, local_port: e.target.value };
                                      updateGFDraft({ forwarding_rules: next });
                                    }}
                                  />
                                  {role === "master" && (
                                    <button
                                      type="button"
                                      className="icon-button delete-button"
                                      disabled={gfDraft.forwarding_rules.length <= 1}
                                      onClick={() => {
                                        const next = gfDraft.forwarding_rules.filter(
                                          (_, idx) => idx !== rIdx
                                        );
                                        updateGFDraft({ forwarding_rules: next });
                                      }}
                                      title="Delete rule"
                                    >
                                      <Trash2 size={14} />
                                    </button>
                                  )}
                                </div>
                              ))}
                            </div>

                            {tunnel.gre_frp?.diagnostics && (
                              <div
                                style={{
                                  marginTop: "18px",
                                  padding: "12px 14px",
                                  borderRadius: "10px",
                                  border: "1px solid rgba(56, 189, 248, 0.25)",
                                  background: "rgba(15, 23, 42, 0.35)",
                                }}
                              >
                                <div
                                  style={{
                                    display: "flex",
                                    justifyContent: "space-between",
                                    alignItems: "center",
                                    flexWrap: "wrap",
                                    gap: "8px",
                                    marginBottom: "10px",
                                  }}
                                >
                                  <span style={{ fontWeight: 700, fontSize: "13px" }}>
                                    4. Live GRE + FRP Diagnostics & Service Management
                                  </span>
                                  <div style={{ display: "flex", gap: "6px", flexWrap: "wrap" }}>
                                    <button
                                      type="button"
                                      className="next-method-btn"
                                      disabled={greActionBusy !== null}
                                      onClick={() =>
                                        handleGREFRPServiceAction(
                                          selectedServer.id,
                                          "reapply_gre"
                                        )
                                      }
                                    >
                                      <span>Re-Apply GRE</span>
                                    </button>
                                    <button
                                      type="button"
                                      className="next-method-btn"
                                      disabled={greActionBusy !== null}
                                      onClick={() =>
                                        handleGREFRPServiceAction(
                                          selectedServer.id,
                                          "install_frp"
                                        )
                                      }
                                    >
                                      <span>Install FRP v0.61.1</span>
                                    </button>
                                    <button
                                      type="button"
                                      className="next-method-btn"
                                      disabled={greActionBusy !== null}
                                      onClick={() =>
                                        handleGREFRPServiceAction(
                                          selectedServer.id,
                                          "restart"
                                        )
                                      }
                                    >
                                      <span>Restart Engine</span>
                                    </button>
                                  </div>
                                </div>

                                {greActionNotice && (
                                  <div
                                    style={{
                                      fontSize: "12px",
                                      color: "#38bdf8",
                                      marginBottom: "8px",
                                    }}
                                  >
                                    {greActionNotice}
                                  </div>
                                )}

                                <div
                                  style={{
                                    display: "grid",
                                    gridTemplateColumns: "repeat(auto-fit, minmax(175px, 1fr))",
                                    gap: "8px",
                                    fontSize: "12px",
                                  }}
                                >
                                  <div>
                                    <span style={{ opacity: 0.7 }}>ACTIVE PATH: </span>
                                    <strong>{tunnel.gre_frp.diagnostics.active_path}</strong>
                                  </div>
                                  <div>
                                    <span style={{ opacity: 0.7 }}>GRE INTERFACE: </span>
                                    <strong>
                                      {tunnel.gre_frp.diagnostics.gre_interface_status}
                                    </strong>
                                  </div>
                                  <div>
                                    <span style={{ opacity: 0.7 }}>GRE RTT / LOSS: </span>
                                    <strong>
                                      {tunnel.gre_frp.diagnostics.gre_rtt_ms}ms /{" "}
                                      {tunnel.gre_frp.diagnostics.gre_packet_loss_pct}%
                                    </strong>
                                  </div>
                                  <div>
                                    <span style={{ opacity: 0.7 }}>FRPS STATUS: </span>
                                    <strong>
                                      {tunnel.gre_frp.diagnostics.frps_service_status}
                                    </strong>
                                  </div>
                                  <div>
                                    <span style={{ opacity: 0.7 }}>FRPC STATUS: </span>
                                    <strong>
                                      {tunnel.gre_frp.diagnostics.frpc_service_status}
                                    </strong>
                                  </div>
                                  <div>
                                    <span style={{ opacity: 0.7 }}>UPTIME / FAILOVERS: </span>
                                    <strong>
                                      {tunnel.gre_frp.diagnostics.service_uptime} (
                                      {tunnel.gre_frp.diagnostics.reconnect_count})
                                    </strong>
                                  </div>
                                </div>
                              </div>
                            )}

                            {errBanner && (
                              <div className="form-error-banner" style={{ marginTop: "10px" }}>
                                {errBanner}
                              </div>
                            )}

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
                                  <span>
                                    {isSaving ? "Saving..." : "Save GRE + FRP Settings"}
                                  </span>
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

                        {expanded && tunnel.id === 26 && swgDraft && (
                          <div className="tunnel-settings">
                            {/* TOP PRE-FLIGHT CAPABILITY CHECK BOX */}
                            {renderSpoofCapabilityPrecheckBox(
                              selectedServer.id,
                              spoofIPsInputValue,
                              (ips) => {
                                setSpoofIPsRawDraft((prev) => ({
                                  ...prev,
                                  [tunnelKey]: ips.join(", "),
                                }));
                                updateSWGDraft({ spoof_ips: ips });
                              }
                            )}

                            {/* REAL SPOOF VS FALLBACK STATUS BANNER */}
                            <div
                              style={{
                                marginBottom: "16px",
                                padding: "12px 14px",
                                borderRadius: "10px",
                                border: liveHealth?.real_spoof_active
                                  ? "1px solid rgba(16, 185, 129, 0.45)"
                                  : "1px solid rgba(245, 158, 11, 0.55)",
                                background: liveHealth?.real_spoof_active
                                  ? "rgba(16, 185, 129, 0.12)"
                                  : "rgba(245, 158, 11, 0.12)",
                                display: "flex",
                                flexDirection: "column",
                                gap: "6px",
                              }}
                            >
                              <div
                                style={{
                                  display: "flex",
                                  alignItems: "center",
                                  justifyContent: "space-between",
                                  flexWrap: "wrap",
                                  gap: "8px",
                                }}
                              >
                                <strong
                                  style={{
                                    fontSize: "13px",
                                    color: liveHealth?.real_spoof_active
                                      ? "#10b981"
                                      : "#f59e0b",
                                  }}
                                >
                                  {liveHealth?.real_spoof_active
                                    ? "✓ REAL LAYER-3 IP SPOOFING + WIREGUARD PIPE IS ACTIVE"
                                    : `⚠️ ${
                                        liveHealth?.spoof_mode_badge ||
                                        "NOT USING REAL SPOOF BINARY (FALLBACK MODE)"
                                      }`}
                                </strong>

                                <label
                                  style={{
                                    display: "flex",
                                    alignItems: "center",
                                    gap: "6px",
                                    fontSize: "12px",
                                    cursor: "pointer",
                                  }}
                                >
                                  <input
                                    type="checkbox"
                                    disabled={role === "agent"}
                                    checked={Boolean(swgDraft.require_real_spoof)}
                                    onChange={(e) =>
                                      updateSWGDraft({
                                        require_real_spoof: e.target.checked,
                                      })
                                    }
                                  />
                                  <span>Strict Real Spoof Only (Disable Fallback)</span>
                                </label>
                              </div>

                              {!liveHealth?.real_spoof_active &&
                                liveHealth?.warning_banner && (
                                  <div style={{ fontSize: "12px", opacity: 0.9 }}>
                                    {liveHealth.warning_banner}
                                  </div>
                                )}
                            </div>

                            {/* SECTION 1: SPOOF PIPE & CARRIER SETTINGS */}
                            <div className="settings-title">
                              <Settings2 size={15} />
                              <span>1. Spoof Tunnel Pipe & Carrier Settings</span>
                            </div>

                            <div className="settings-grid">
                              <div className="form-field">
                                <label>SPOOF NODE ROLE</label>
                                <select
                                  className="server-select"
                                  disabled={role === "agent"}
                                  value={swgDraft.role || "local"}
                                  onChange={(e) => {
                                    const newRole = e.target.value;
                                    updateSWGDraft({
                                      role: newRole,
                                      wg_local_ip:
                                        newRole === "local" ? "10.20.0.1" : "10.20.0.2",
                                      wg_peer_ip:
                                        newRole === "local" ? "10.20.0.2" : "10.20.0.1",
                                      spoof_port:
                                        newRole === "local"
                                          ? 443
                                          : swgDraft.spoof_listen_port || 8090,
                                    });
                                  }}
                                  style={{ width: "100%", padding: "10px 12px" }}
                                >
                                  <option value="local">Local (Iran / Initiator)</option>
                                  <option value="remote">Remote (Foreign / Receiver)</option>
                                </select>
                              </div>

                              <div className="form-field">
                                <label>PEER PUBLIC IPV4 ADDRESS</label>
                                <input
                                  disabled={role === "agent"}
                                  value={swgDraft.peer_public_ip || selectedServer.ip}
                                  onChange={(e) =>
                                    updateSWGDraft({ peer_public_ip: e.target.value })
                                  }
                                  placeholder="198.51.100.12"
                                />
                              </div>

                              <div className="form-field">
                                <label>THIS SERVER'S PUBLIC IPV4 (FOR BUNDLE)</label>
                                <input
                                  disabled={role === "agent"}
                                  value={swgDraft.local_public_ip || ""}
                                  onChange={(e) =>
                                    updateSWGDraft({ local_public_ip: e.target.value })
                                  }
                                  placeholder="Auto-detect or enter Iran IPv4"
                                />
                              </div>

                              <div className="form-field">
                                <label>REMOTE LISTEN PORT (DEFAULT 8090)</label>
                                <input
                                  type="number"
                                  disabled={role === "agent"}
                                  value={swgDraft.spoof_listen_port}
                                  onChange={(e) =>
                                    updateSWGDraft({
                                      spoof_listen_port: Number(e.target.value) || 8090,
                                    })
                                  }
                                />
                              </div>

                              <div className="form-field">
                                <label>LOCAL RECV / CLIENT PORT (DEFAULT 5001)</label>
                                <input
                                  type="number"
                                  disabled={role === "agent"}
                                  value={swgDraft.recv_port}
                                  onChange={(e) =>
                                    updateSWGDraft({
                                      recv_port: Number(e.target.value) || 5001,
                                    })
                                  }
                                />
                              </div>

                              <div className="form-field">
                                <label>OUTGOING SPOOF PORT (DEFAULT 443)</label>
                                <input
                                  type="number"
                                  disabled={role === "agent"}
                                  value={swgDraft.spoof_port}
                                  onChange={(e) =>
                                    updateSWGDraft({
                                      spoof_port: Number(e.target.value) || 443,
                                    })
                                  }
                                />
                              </div>

                              <div className="form-field">
                                <label>SEND TRANSPORT CARRIER</label>
                                <select
                                  className="server-select"
                                  disabled={role === "agent"}
                                  value={swgDraft.send_transport || "tcp"}
                                  onChange={(e) =>
                                    updateSWGDraft({ send_transport: e.target.value })
                                  }
                                  style={{ width: "100%", padding: "10px 12px" }}
                                >
                                  <option value="tcp">TCP</option>
                                  <option value="udp">UDP</option>
                                  <option value="icmp">ICMP</option>
                                  <option value="icmpv6">ICMPv6</option>
                                </select>
                              </div>

                              <div className="form-field">
                                <label>RECEIVE TRANSPORT CARRIER</label>
                                <select
                                  className="server-select"
                                  disabled={role === "agent"}
                                  value={swgDraft.recv_transport || "udp"}
                                  onChange={(e) =>
                                    updateSWGDraft({ recv_transport: e.target.value })
                                  }
                                  style={{ width: "100%", padding: "10px 12px" }}
                                >
                                  <option value="udp">UDP</option>
                                  <option value="tcp">TCP</option>
                                  <option value="icmp">ICMP</option>
                                  <option value="icmpv6">ICMPv6</option>
                                </select>
                              </div>

                              <div className="form-field" style={{ gridColumn: "1 / -1" }}>
                                <label>
                                  FORGED SPOOF SOURCE IPV4 ADDRESSES (CSV — ROUND-ROBIN WHEN MULTIPLE)
                                </label>
                                <input
                                  disabled={role === "agent"}
                                  value={spoofIPsInputValue}
                                  onChange={(e) => {
                                    const raw = e.target.value;
                                    setSpoofIPsRawDraft((prev) => ({
                                      ...prev,
                                      [tunnelKey]: raw,
                                    }));
                                    updateSWGDraft({
                                      spoof_ips: parseSpoofIPsCSV(raw),
                                    });
                                  }}
                                  placeholder="8.8.8.8, 1.1.1.1, 9.9.9.9"
                                />
                              </div>
                            </div>

                            {/* SECTION 2: WIREGUARD OVERLAY & PORT FORWARDING SETTINGS */}
                            <div className="settings-title" style={{ marginTop: "18px" }}>
                              <Shield size={15} />
                              <span>2. WireGuard Encrypted Overlay (wg-spoof) & Port Forwarding</span>
                            </div>

                            <div className="settings-grid">
                              <div className="form-field">
                                <label>LOCAL WIREGUARD IP (/24)</label>
                                <input
                                  disabled={role === "agent"}
                                  value={swgDraft.wg_local_ip}
                                  onChange={(e) =>
                                    updateSWGDraft({ wg_local_ip: e.target.value })
                                  }
                                  placeholder="10.20.0.1"
                                />
                              </div>

                              <div className="form-field">
                                <label>PEER WIREGUARD IP (/32)</label>
                                <input
                                  disabled={role === "agent"}
                                  value={swgDraft.wg_peer_ip}
                                  onChange={(e) =>
                                    updateSWGDraft({ wg_peer_ip: e.target.value })
                                  }
                                  placeholder="10.20.0.2"
                                />
                              </div>

                              <div className="form-field">
                                <label>LOCAL CORE UDP PORT (DEFAULT 5000)</label>
                                <input
                                  type="number"
                                  disabled={role === "agent"}
                                  value={swgDraft.core_port}
                                  onChange={(e) =>
                                    updateSWGDraft({
                                      core_port: Number(e.target.value) || 5000,
                                    })
                                  }
                                />
                              </div>

                              <div className="form-field">
                                <label>FOREIGN WG LISTEN PORT (DEFAULT 51820)</label>
                                <input
                                  type="number"
                                  disabled={role === "agent"}
                                  value={swgDraft.wg_listen}
                                  onChange={(e) =>
                                    updateSWGDraft({
                                      wg_listen: Number(e.target.value) || 51820,
                                    })
                                  }
                                />
                              </div>

                              <div className="form-field">
                                <label>WIREGUARD MTU (DEFAULT 1280)</label>
                                <input
                                  type="number"
                                  disabled={role === "agent"}
                                  value={swgDraft.wg_mtu || 1280}
                                  onChange={(e) =>
                                    updateSWGDraft({
                                      wg_mtu: Number(e.target.value) || 1280,
                                    })
                                  }
                                />
                              </div>

                              <div className="form-field">
                                <label>SAHAND CARRIER PORT (ENGINE 1)</label>
                                <input
                                  type="number"
                                  disabled={role === "agent"}
                                  value={draft.listen_port}
                                  onChange={(e) =>
                                    updateDraftTunnel(selectedServer.id, {
                                      ...draft,
                                      listen_port: Number(e.target.value) || 28026,
                                    })
                                  }
                                />
                              </div>

                              <div className="form-field">
                                <label>FORWARDING PORTS (CSV — ENGINE 2)</label>
                                <input
                                  disabled={role === "agent"}
                                  value={draft.forward_ports}
                                  onChange={(e) =>
                                    updateDraftTunnel(selectedServer.id, {
                                      ...draft,
                                      forward_ports: e.target.value,
                                    })
                                  }
                                  placeholder="32026"
                                />
                              </div>

                              <div className="form-field">
                                <label>SPEED LIMIT (MB/S, 0=UNLIMITED)</label>
                                <input
                                  disabled={role === "agent"}
                                  value={draft.speed_limit_mbps ?? "0"}
                                  onChange={(e) =>
                                    updateDraftTunnel(selectedServer.id, {
                                      ...draft,
                                      speed_limit_mbps: e.target.value,
                                    })
                                  }
                                />
                              </div>

                              <div className="form-field">
                                <label>THIS SERVER'S WG PUBLIC KEY</label>
                                <input
                                  readOnly
                                  value={swgDraft.wg_pub_key || "Generated automatically"}
                                />
                              </div>

                              <div className="form-field">
                                <label>PEER WG PUBLIC KEY</label>
                                <input
                                  disabled={role === "agent"}
                                  value={swgDraft.wg_peer_pub || ""}
                                  onChange={(e) =>
                                    updateSWGDraft({ wg_peer_pub: e.target.value })
                                  }
                                  placeholder="Auto-filled via Bundle"
                                />
                              </div>
                            </div>

                            {/* SECTION 3: ONE-STRING BUNDLE EXCHANGE (spf1_...) */}
                            <div className="settings-title" style={{ marginTop: "18px" }}>
                              <Copy size={15} />
                              <span>3. Spoof + WireGuard Bundle Exchange (spf1_...)</span>
                            </div>

                            <div
                              style={{
                                display: "flex",
                                flexDirection: "column",
                                gap: "10px",
                                marginTop: "8px",
                                padding: "12px",
                                borderRadius: "10px",
                                border: "1px solid rgba(148, 163, 184, 0.22)",
                              }}
                            >
                              <div
                                style={{
                                  display: "flex",
                                  gap: "8px",
                                  alignItems: "center",
                                  flexWrap: "wrap",
                                }}
                              >
                                <button
                                  type="button"
                                  className="next-method-btn"
                                  disabled={spoofActionBusy !== null}
                                  onClick={() =>
                                    handleSpoofWGAction(
                                      selectedServer.id,
                                      "bundle",
                                      draft
                                    )
                                  }
                                >
                                  <Plus size={13} />
                                  <span>
                                    {spoofActionBusy === "bundle"
                                      ? "Generating..."
                                      : "Generate Bundle (Iran Side)"}
                                  </span>
                                </button>

                                {swgDraft.last_bundle && (
                                  <button
                                    type="button"
                                    className="next-method-btn"
                                    style={
                                      copiedBundle
                                        ? {
                                            borderColor: "#10b981",
                                            color: "#10b981",
                                          }
                                        : undefined
                                    }
                                    onClick={() =>
                                      copySpoofBundleText(swgDraft.last_bundle || "")
                                    }
                                  >
                                    {copiedBundle ? (
                                      <Check size={13} />
                                    ) : (
                                      <Copy size={13} />
                                    )}
                                    <span>
                                      {copiedBundle
                                        ? "✓ Bundle Copied!"
                                        : "Copy Bundle"}
                                    </span>
                                  </button>
                                )}
                              </div>

                              {swgDraft.last_bundle && (
                                <input
                                  readOnly
                                  value={swgDraft.last_bundle}
                                  style={{ fontSize: "12px", fontFamily: "monospace" }}
                                />
                              )}

                              <div
                                style={{
                                  display: "grid",
                                  gridTemplateColumns: "1fr auto",
                                  gap: "8px",
                                  alignItems: "center",
                                }}
                              >
                                <input
                                  value={spoofBundleInput}
                                  onChange={(e) => setSpoofBundleInput(e.target.value)}
                                  placeholder="Paste spf1_... bundle here to import on Foreign server"
                                />
                                <button
                                  type="button"
                                  className="next-method-btn"
                                  disabled={
                                    spoofActionBusy !== null ||
                                    !spoofBundleInput.trim()
                                  }
                                  onClick={() =>
                                    handleSpoofWGAction(
                                      selectedServer.id,
                                      "import",
                                      draft
                                    )
                                  }
                                >
                                  <span>
                                    {spoofActionBusy === "import"
                                      ? "Importing..."
                                      : "Import Bundle"}
                                  </span>
                                </button>
                              </div>
                            </div>

                            {/* SECTION 4: LIVE HEALTH, BINARY INSTALLER & SERVICE MANAGEMENT */}
                            <div
                              style={{
                                marginTop: "18px",
                                padding: "12px 14px",
                                borderRadius: "10px",
                                border: "1px solid rgba(56, 189, 248, 0.25)",
                                background: "rgba(15, 23, 42, 0.35)",
                              }}
                            >
                              <div
                                style={{
                                  display: "flex",
                                  justifyContent: "space-between",
                                  alignItems: "center",
                                  flexWrap: "wrap",
                                  gap: "8px",
                                  marginBottom: "10px",
                                }}
                              >
                                <span style={{ fontWeight: 700, fontSize: "13px" }}>
                                  4. Live Spoof + WireGuard Health & Binary Controls
                                </span>
                                <div style={{ display: "flex", gap: "6px", flexWrap: "wrap" }}>
                                  <button
                                    type="button"
                                    className="next-method-btn"
                                    disabled={spoofActionBusy !== null}
                                    onClick={() =>
                                      handleSpoofWGAction(
                                        selectedServer.id,
                                        "install_binary",
                                        draft
                                      )
                                    }
                                  >
                                    <ArrowDown size={12} />
                                    <span>
                                      {spoofActionBusy === "install_binary"
                                        ? "Installing Binary..."
                                        : liveHealth?.binary_installed
                                        ? "Re-Verify Spoof Binary"
                                        : "Install Spoof Binary (v3.0.2)"}
                                    </span>
                                  </button>

                                  <button
                                    type="button"
                                    className="next-method-btn"
                                    disabled={spoofActionBusy !== null}
                                    onClick={() =>
                                      handleSpoofWGAction(
                                        selectedServer.id,
                                        "up",
                                        draft
                                      )
                                    }
                                  >
                                    <Play size={12} />
                                    <span>Apply & Start</span>
                                  </button>

                                  <button
                                    type="button"
                                    className="next-method-btn"
                                    disabled={spoofActionBusy !== null}
                                    onClick={() =>
                                      handleSpoofWGAction(
                                        selectedServer.id,
                                        "down",
                                        draft
                                      )
                                    }
                                  >
                                    <Pause size={12} />
                                    <span>Stop Services</span>
                                  </button>

                                  <button
                                    type="button"
                                    className="next-method-btn"
                                    disabled={spoofActionBusy !== null}
                                    onClick={() =>
                                      handleSpoofWGAction(
                                        selectedServer.id,
                                        "restart",
                                        draft
                                      )
                                    }
                                  >
                                    <RefreshCw size={12} />
                                    <span>Restart Carrier</span>
                                  </button>
                                </div>
                              </div>

                              {spoofActionNotice && (
                                <div
                                  style={{
                                    fontSize: "12px",
                                    color: "#38bdf8",
                                    marginBottom: "8px",
                                  }}
                                >
                                  {spoofActionNotice}
                                </div>
                              )}

                              <div
                                style={{
                                  display: "grid",
                                  gridTemplateColumns: "repeat(auto-fit, minmax(175px, 1fr))",
                                  gap: "8px",
                                  fontSize: "12px",
                                }}
                              >
                                <div>
                                  <span style={{ opacity: 0.7 }}>SPOOF ENGINE: </span>
                                  <strong
                                    style={{
                                      color: liveHealth?.real_spoof_active
                                        ? "#10b981"
                                        : "#f59e0b",
                                    }}
                                  >
                                    {liveHealth?.real_spoof_active
                                      ? "REAL SPOOFING"
                                      : "FALLBACK (UNSPOOFED)"}
                                  </strong>
                                </div>
                                <div>
                                  <span style={{ opacity: 0.7 }}>SPOOF BINARY: </span>
                                  <strong
                                    style={{
                                      color: liveHealth?.binary_installed
                                        ? "#10b981"
                                        : "#ef4444",
                                    }}
                                  >
                                    {liveHealth?.binary_installed
                                      ? `INSTALLED (${
                                          liveHealth.binary_version || "v3.0.2"
                                        }${
                                          liveHealth.binary_sha256_ok ? " ✓ SHA256" : ""
                                        })`
                                      : "MISSING (NOT INSTALLED)"}
                                  </strong>
                                </div>
                                <div>
                                  <span style={{ opacity: 0.7 }}>WIREGUARD TOOLS: </span>
                                  <strong>
                                    {liveHealth?.wg_tools_present
                                      ? "INSTALLED"
                                      : "MISSING"}
                                  </strong>
                                </div>
                                <div>
                                  <span style={{ opacity: 0.7 }}>SPOOF-CORE SVC: </span>
                                  <strong>
                                    {liveHealth?.core_active ? "ACTIVE" : "STANDBY"}
                                  </strong>
                                </div>
                                <div>
                                  <span style={{ opacity: 0.7 }}>WG-SPOOF SVC: </span>
                                  <strong>
                                    {liveHealth?.wg_active ? "ACTIVE" : "STANDBY"}
                                  </strong>
                                </div>
                                <div>
                                  <span style={{ opacity: 0.7 }}>WG HANDSHAKE: </span>
                                  <strong>
                                    {liveHealth?.handshake ||
                                      (liveHealth?.peer_ping ? "FRESH" : "STANDBY")}
                                  </strong>
                                </div>
                              </div>
                            </div>

                            {/* SECTION 5: SPOOF IP TESTER */}
                            <div
                              style={{
                                marginTop: "18px",
                                padding: "12px 14px",
                                borderRadius: "10px",
                                border: "1px solid rgba(148, 163, 184, 0.22)",
                              }}
                            >
                              <div
                                style={{
                                  display: "flex",
                                  justifyContent: "space-between",
                                  alignItems: "center",
                                  flexWrap: "wrap",
                                  gap: "8px",
                                  marginBottom: "10px",
                                }}
                              >
                                <span style={{ fontWeight: 700, fontSize: "13px" }}>
                                  5. Spoof IP Tester (Find Whitelisted Source IPs That Cross the Firewall)
                                </span>
                                <div style={{ display: "flex", gap: "6px", flexWrap: "wrap" }}>
                                  <button
                                    type="button"
                                    className="next-method-btn"
                                    disabled={
                                      spoofActionBusy !== null ||
                                      liveTester?.status === "running"
                                    }
                                    onClick={() =>
                                      handleSpoofWGAction(
                                        selectedServer.id,
                                        "tester_start",
                                        draft
                                      )
                                    }
                                  >
                                    <Play size={12} />
                                    <span>
                                      {liveTester?.status === "running"
                                        ? `Running (${liveTester.progress || 0}%)...`
                                        : "Start Tester"}
                                    </span>
                                  </button>

                                  {liveTester?.status === "running" && (
                                    <button
                                      type="button"
                                      className="next-method-btn"
                                      disabled={spoofActionBusy !== null}
                                      onClick={() =>
                                        handleSpoofWGAction(
                                          selectedServer.id,
                                          "tester_stop",
                                          draft
                                        )
                                      }
                                    >
                                      <Pause size={12} />
                                      <span>Stop Tester</span>
                                    </button>
                                  )}

                                  {liveTester?.passed &&
                                    liveTester.passed.length > 0 && (
                                      <button
                                        type="button"
                                        className="next-method-btn"
                                        style={{
                                          borderColor: "#10b981",
                                          color: "#10b981",
                                        }}
                                        onClick={() => {
                                          const ips = liveTester.passed.map(
                                            (p) => p.ip
                                          );
                                          setSpoofIPsRawDraft((prev) => ({
                                            ...prev,
                                            [tunnelKey]: ips.join(", "),
                                          }));
                                          updateSWGDraft({ spoof_ips: ips });
                                        }}
                                      >
                                        <Check size={12} />
                                        <span>
                                          Use {liveTester.passed.length} Passing IP(s)
                                        </span>
                                      </button>
                                    )}
                                </div>
                              </div>

                              <div className="settings-grid">
                                <div className="form-field">
                                  <label>TESTER MODE</label>
                                  <select
                                    className="server-select"
                                    value={testerMode}
                                    onChange={(e) =>
                                      setTesterMode(
                                        e.target.value as "receiver" | "sender"
                                      )
                                    }
                                    style={{ width: "100%", padding: "10px 12px" }}
                                  >
                                    <option value="receiver">
                                      Receiver (Run First on Receiving Server)
                                    </option>
                                    <option value="sender">
                                      Sender (Run Second on Sending Server)
                                    </option>
                                  </select>
                                </div>

                                <div className="form-field">
                                  <label>PROBE PROTOCOL</label>
                                  <select
                                    className="server-select"
                                    value={testerProto}
                                    onChange={(e) =>
                                      setTesterProto(
                                        e.target.value as "icmp" | "tcp"
                                      )
                                    }
                                    style={{ width: "100%", padding: "10px 12px" }}
                                  >
                                    <option value="icmp">ICMP</option>
                                    <option value="tcp">TCP</option>
                                  </select>
                                </div>

                                {testerMode === "sender" && (
                                  <>
                                    <div className="form-field">
                                      <label>RECEIVER SERVER PUBLIC IPV4</label>
                                      <input
                                        value={
                                          testerDstIP ||
                                          swgDraft.peer_public_ip ||
                                          selectedServer.ip
                                        }
                                        onChange={(e) =>
                                          setTesterDstIP(e.target.value)
                                        }
                                        placeholder={selectedServer.ip}
                                      />
                                    </div>

                                    <div className="form-field">
                                      <label>DESTINATION PORT (TCP MODE)</label>
                                      <input
                                        type="number"
                                        value={testerDstPort}
                                        onChange={(e) =>
                                          setTesterDstPort(
                                            Number(e.target.value) || 80
                                          )
                                        }
                                      />
                                    </div>
                                  </>
                                )}

                                <div className="form-field">
                                  <label>TIMEOUT (SEC) / PACKETS PER IP / MAX LOSS %</label>
                                  <div style={{ display: "flex", gap: "6px" }}>
                                    <input
                                      type="number"
                                      value={testerTimeout}
                                      title="Receiver Timeout (seconds)"
                                      onChange={(e) =>
                                        setTesterTimeout(
                                          Number(e.target.value) || 30
                                        )
                                      }
                                    />
                                    <input
                                      type="number"
                                      value={testerPacketCount}
                                      title="Packets per source IP"
                                      onChange={(e) =>
                                        setTesterPacketCount(
                                          Number(e.target.value) || 10
                                        )
                                      }
                                    />
                                    <input
                                      type="number"
                                      value={testerMaxLoss}
                                      title="Max accepted packet loss %"
                                      onChange={(e) =>
                                        setTesterMaxLoss(
                                          Number(e.target.value) || 0
                                        )
                                      }
                                    />
                                  </div>
                                </div>

                                <div className="form-field" style={{ gridColumn: "1 / -1" }}>
                                  <label>
                                    SOURCE IPS / RANGES / CIDRS TO TEST (COMMA OR NEWLINE SEPARATED)
                                  </label>
                                  <input
                                    value={testerSourcesRaw}
                                    onChange={(e) =>
                                      setTesterSourcesRaw(e.target.value)
                                    }
                                    placeholder="8.8.8.8, 1.1.1.1, 9.9.9.9, 198.51.100.0/24"
                                  />
                                </div>
                              </div>

                              {liveTester && liveTester.status !== "idle" && (
                                <div
                                  style={{
                                    marginTop: "10px",
                                    fontSize: "12px",
                                    display: "flex",
                                    flexDirection: "column",
                                    gap: "6px",
                                  }}
                                >
                                  <div>
                                    <span>
                                      Tester Status:{" "}
                                      <strong>
                                        {liveTester.status.toUpperCase()}
                                      </strong>{" "}
                                      ({liveTester.mode} /{" "}
                                      {liveTester.protocol?.toUpperCase()})
                                    </span>
                                    {liveTester.error && (
                                      <span
                                        style={{
                                          color: "#ef4444",
                                          marginLeft: "8px",
                                        }}
                                      >
                                        — {liveTester.error}
                                      </span>
                                    )}
                                  </div>

                                  {liveTester.passed &&
                                    liveTester.passed.length > 0 && (
                                      <div
                                        style={{
                                          display: "flex",
                                          flexWrap: "wrap",
                                          gap: "6px",
                                        }}
                                      >
                                        {liveTester.passed.map((item, idx) => (
                                          <span
                                            key={idx}
                                            className="disc-pill disc-ok"
                                          >
                                            {item.ip} ({item.received}/
                                            {item.sent} • {item.loss_pct}% loss)
                                          </span>
                                        ))}
                                      </div>
                                    )}
                                </div>
                              )}
                            </div>

                            {errBanner && (
                              <div className="form-error-banner" style={{ marginTop: "10px" }}>
                                {errBanner}
                              </div>
                            )}

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
                                  <span>
                                    {isSaving
                                      ? "Saving..."
                                      : "Save Spoof + WireGuard Settings"}
                                  </span>
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

                        {/* ==========================================================
                            METHOD 27: INDEPENDENT NATIVE SPOOF ENGINE UI
                           ========================================================== */}
                        {expanded && tunnel.id === 27 && snDraft && (
                          <div className="tunnel-settings">
                            {/* TOP PRE-FLIGHT CAPABILITY CHECK BOX */}
                            {renderSpoofCapabilityPrecheckBox(
                              selectedServer.id,
                              spoofIPsInputValue,
                              (ips) => {
                                setSpoofIPsRawDraft((prev) => ({
                                  ...prev,
                                  [tunnelKey]: ips.join(", "),
                                }));
                                updateSNDraft({ spoof_ips: ips });
                              }
                            )}

                            {/* STATUS & STRICT MODE BANNER */}
                            <div
                              style={{
                                marginBottom: "16px",
                                padding: "12px 14px",
                                borderRadius: "10px",
                                border:
                                  m27Health?.connection_state === "REAL SPOOF ACTIVE"
                                    ? "1px solid rgba(16, 185, 129, 0.45)"
                                    : m27Health?.connection_state === "SPOOF FAILED"
                                    ? "1px solid rgba(239, 68, 68, 0.55)"
                                    : "1px solid rgba(245, 158, 11, 0.55)",
                                background:
                                  m27Health?.connection_state === "REAL SPOOF ACTIVE"
                                    ? "rgba(16, 185, 129, 0.12)"
                                    : m27Health?.connection_state === "SPOOF FAILED"
                                    ? "rgba(239, 68, 68, 0.12)"
                                    : "rgba(245, 158, 11, 0.12)",
                                display: "flex",
                                flexDirection: "column",
                                gap: "6px",
                              }}
                            >
                              <div
                                style={{
                                  display: "flex",
                                  alignItems: "center",
                                  justifyContent: "space-between",
                                  flexWrap: "wrap",
                                  gap: "8px",
                                }}
                              >
                                <strong
                                  style={{
                                    fontSize: "13px",
                                    color:
                                      m27Health?.connection_state === "REAL SPOOF ACTIVE"
                                        ? "#10b981"
                                        : m27Health?.connection_state === "SPOOF FAILED"
                                        ? "#ef4444"
                                        : "#f59e0b",
                                  }}
                                >
                                  STATUS: {m27Health?.status_badge || "DISCONNECTED"}
                                </strong>

                                <label
                                  style={{
                                    display: "flex",
                                    alignItems: "center",
                                    gap: "6px",
                                    fontSize: "12px",
                                    cursor: "pointer",
                                  }}
                                  title="When enabled, no direct fallback is permitted. If the real Spoof Pipe fails, the tunnel remains disconnected."
                                >
                                  <input
                                    type="checkbox"
                                    disabled={role === "agent"}
                                    checked={Boolean(snDraft.strict_real_spoof)}
                                    onChange={(e) =>
                                      updateSNDraft({
                                        strict_real_spoof: e.target.checked,
                                      })
                                    }
                                  />
                                  <span>Strict Real Spoof (No Direct Fallback)</span>
                                </label>
                              </div>

                              {m27Health?.warning_banner && (
                                <div style={{ fontSize: "12px", opacity: 0.92 }}>
                                  {m27Health.warning_banner}
                                </div>
                              )}

                              {snDraft.mode === "pure" && (
                                <div
                                  style={{
                                    fontSize: "11.5px",
                                    opacity: 0.85,
                                    borderTop: "1px solid rgba(148,163,184,0.2)",
                                    paddingTop: "6px",
                                  }}
                                >
                                  <strong>Security Note (Pure Spoof):</strong> Pure Spoof
                                  transports raw datagrams over the native Spoof UDP pipe
                                  without WireGuard or TLS encryption overhead. Ensure your
                                  forwarded inbound traffic (e.g. TLS / Xray / SSH) is
                                  already encrypted, or select Spoof + WireGuard / QUIC /
                                  Noise below.
                                </div>
                              )}
                            </div>

                            {/* SECTION 1: PROTOCOL / SECURITY ADAPTER SELECTOR & SPOOF CORE */}
                            <div className="settings-title">
                              <Settings2 size={15} />
                              <span>
                                1. Method 27 Architecture: Transport Adapter & Spoof Core (/etc/spoof-m27)
                              </span>
                            </div>

                            <div className="settings-grid">
                              <div className="form-field">
                                <label>TRANSPORT / SECURITY ADAPTER</label>
                                <select
                                  className="server-select"
                                  disabled={role === "agent"}
                                  value={snDraft.mode || "pure"}
                                  onChange={(e) =>
                                    updateSNDraft({ mode: e.target.value })
                                  }
                                  style={{ width: "100%", padding: "10px 12px" }}
                                >
                                  <option value="pure">
                                    1. Pure Spoof (Native UDP Pipe — No WG/TLS)
                                  </option>
                                  <option value="wireguard">
                                    2. Spoof + WireGuard (Isolated wg-spoof27)
                                  </option>
                                  <option value="quic">
                                    3. Spoof + QUIC (TLS 1.3 Multiplexed over Spoof Pipe)
                                  </option>
                                  <option value="noise">
                                    4. Spoof + Noise (Noise_IKpsk2 ChaCha20-Poly1305)
                                  </option>
                                </select>
                              </div>

                              <div className="form-field">
                                <label>SPOOF NODE ROLE</label>
                                <select
                                  className="server-select"
                                  disabled={role === "agent"}
                                  value={snDraft.role || "local"}
                                  onChange={(e) => {
                                    const newRole = e.target.value;
                                    updateSNDraft({
                                      role: newRole,
                                      wg_local_ip:
                                        newRole === "local" ? "10.27.0.1" : "10.27.0.2",
                                      wg_peer_ip:
                                        newRole === "local" ? "10.27.0.2" : "10.27.0.1",
                                      spoof_port:
                                        newRole === "local"
                                          ? 443
                                          : snDraft.spoof_listen_port || 8091,
                                    });
                                  }}
                                  style={{ width: "100%", padding: "10px 12px" }}
                                >
                                  <option value="local">Local (Master / Iran)</option>
                                  <option value="remote">Remote (Agent / Foreign)</option>
                                </select>
                              </div>

                              <div className="form-field">
                                <label>PEER PUBLIC IPV4 ADDRESS</label>
                                <input
                                  disabled={role === "agent"}
                                  value={snDraft.peer_public_ip || selectedServer.ip}
                                  onChange={(e) =>
                                    updateSNDraft({ peer_public_ip: e.target.value })
                                  }
                                  placeholder="198.51.100.12"
                                />
                              </div>

                              <div className="form-field">
                                <label>THIS SERVER'S PUBLIC IPV4 (FOR BUNDLE)</label>
                                <input
                                  disabled={role === "agent"}
                                  value={snDraft.local_public_ip || ""}
                                  onChange={(e) =>
                                    updateSNDraft({ local_public_ip: e.target.value })
                                  }
                                  placeholder="Auto-detect or enter Master IPv4"
                                />
                              </div>

                              <div className="form-field">
                                <label>SEND TRANSPORT CARRIER</label>
                                <select
                                  className="server-select"
                                  disabled={role === "agent"}
                                  value={snDraft.send_transport || "tcp"}
                                  onChange={(e) =>
                                    updateSNDraft({ send_transport: e.target.value })
                                  }
                                  style={{ width: "100%", padding: "10px 12px" }}
                                >
                                  <option value="tcp">TCP</option>
                                  <option value="udp">UDP</option>
                                  <option value="icmp">ICMP</option>
                                  <option value="icmpv6">ICMPv6</option>
                                </select>
                              </div>

                              <div className="form-field">
                                <label>RECEIVE TRANSPORT CARRIER</label>
                                <select
                                  className="server-select"
                                  disabled={role === "agent"}
                                  value={snDraft.recv_transport || "udp"}
                                  onChange={(e) =>
                                    updateSNDraft({ recv_transport: e.target.value })
                                  }
                                  style={{ width: "100%", padding: "10px 12px" }}
                                >
                                  <option value="udp">UDP</option>
                                  <option value="tcp">TCP</option>
                                  <option value="icmp">ICMP</option>
                                  <option value="icmpv6">ICMPv6</option>
                                </select>
                              </div>

                              <div className="form-field">
                                <label>REMOTE LISTEN PORT (DEFAULT 8091)</label>
                                <input
                                  type="number"
                                  disabled={role === "agent"}
                                  value={snDraft.spoof_listen_port}
                                  onChange={(e) =>
                                    updateSNDraft({
                                      spoof_listen_port: Number(e.target.value) || 8091,
                                    })
                                  }
                                />
                              </div>

                              <div className="form-field">
                                <label>LOCAL RECV / CLIENT PORT (DEFAULT 5011)</label>
                                <input
                                  type="number"
                                  disabled={role === "agent"}
                                  value={snDraft.recv_port}
                                  onChange={(e) =>
                                    updateSNDraft({
                                      recv_port: Number(e.target.value) || 5011,
                                    })
                                  }
                                />
                              </div>

                              <div className="form-field">
                                <label>OUTGOING SPOOF PORT (DEFAULT 443)</label>
                                <input
                                  type="number"
                                  disabled={role === "agent"}
                                  value={snDraft.spoof_port}
                                  onChange={(e) =>
                                    updateSNDraft({
                                      spoof_port: Number(e.target.value) || 443,
                                    })
                                  }
                                />
                              </div>

                              <div className="form-field">
                                <label>LOCAL CORE UDP PORT (DEFAULT 5010)</label>
                                <input
                                  type="number"
                                  disabled={role === "agent"}
                                  value={snDraft.core_port}
                                  onChange={(e) =>
                                    updateSNDraft({
                                      core_port: Number(e.target.value) || 5010,
                                    })
                                  }
                                />
                              </div>

                              <div className="form-field">
                                <label>REMOTE ADAPTER UDP PORT (DEFAULT 51827)</label>
                                <input
                                  type="number"
                                  disabled={role === "agent"}
                                  value={snDraft.adapter_port}
                                  onChange={(e) =>
                                    updateSNDraft({
                                      adapter_port: Number(e.target.value) || 51827,
                                    })
                                  }
                                />
                              </div>

                              <div className="form-field">
                                <label>MTU / KEEPALIVE (SEC)</label>
                                <div style={{ display: "flex", gap: "6px" }}>
                                  <input
                                    type="number"
                                    disabled={role === "agent"}
                                    value={snDraft.mtu || 1280}
                                    title="MTU"
                                    onChange={(e) =>
                                      updateSNDraft({
                                        mtu: Number(e.target.value) || 1280,
                                      })
                                    }
                                  />
                                  <input
                                    type="number"
                                    disabled={role === "agent"}
                                    value={snDraft.keepalive_sec || 25}
                                    title="Keepalive Seconds"
                                    onChange={(e) =>
                                      updateSNDraft({
                                        keepalive_sec: Number(e.target.value) || 25,
                                      })
                                    }
                                  />
                                </div>
                              </div>

                              <div className="form-field" style={{ gridColumn: "1 / -1" }}>
                                <label>
                                  CANDIDATE / WORKING SPOOF SOURCE IPV4 ADDRESSES (CSV — ROUND-ROBIN WHEN MULTIPLE)
                                </label>
                                <input
                                  disabled={role === "agent"}
                                  value={spoofIPsInputValue}
                                  onChange={(e) => {
                                    const raw = e.target.value;
                                    setSpoofIPsRawDraft((prev) => ({
                                      ...prev,
                                      [tunnelKey]: raw,
                                    }));
                                    updateSNDraft({
                                      spoof_ips: parseSpoofIPsCSV(raw),
                                    });
                                  }}
                                  placeholder="Enter verified Spoof IPs (e.g. 8.8.8.8, 1.1.1.1) or run the Tester below"
                                />
                              </div>
                            </div>

                            {/* SECTION 2: MODE-SPECIFIC ADAPTER & FORWARDING FIELDS */}
                            <div className="settings-title" style={{ marginTop: "18px" }}>
                              <Shield size={15} />
                              <span>
                                2. Adapter Parameters ({(snDraft.mode || "pure").toUpperCase()}) & Port Forwarding
                              </span>
                            </div>

                            <div className="settings-grid">
                              <div className="form-field">
                                <label>ENGINE 1 ADAPTER PORT (DEFAULT 28027)</label>
                                <input
                                  type="number"
                                  disabled={role === "agent"}
                                  value={draft.listen_port}
                                  onChange={(e) =>
                                    updateDraftTunnel(selectedServer.id, {
                                      ...draft,
                                      listen_port: Number(e.target.value) || 28027,
                                    })
                                  }
                                />
                              </div>

                              <div className="form-field">
                                <label>FORWARDING PORTS (CSV — ENGINE 2)</label>
                                <input
                                  disabled={role === "agent"}
                                  value={draft.forward_ports}
                                  onChange={(e) =>
                                    updateDraftTunnel(selectedServer.id, {
                                      ...draft,
                                      forward_ports: e.target.value,
                                    })
                                  }
                                  placeholder="32027"
                                />
                              </div>

                              <div className="form-field">
                                <label>SPEED LIMIT (MB/S, 0=UNLIMITED)</label>
                                <input
                                  disabled={role === "agent"}
                                  value={draft.speed_limit_mbps ?? "0"}
                                  onChange={(e) =>
                                    updateDraftTunnel(selectedServer.id, {
                                      ...draft,
                                      speed_limit_mbps: e.target.value,
                                    })
                                  }
                                />
                              </div>

                              {snDraft.mode === "wireguard" && (
                                <>
                                  <div className="form-field">
                                    <label>WG INTERFACE (ISOLATED)</label>
                                    <input
                                      disabled={role === "agent"}
                                      value={snDraft.wg_interface || "wg-spoof27"}
                                      onChange={(e) =>
                                        updateSNDraft({ wg_interface: e.target.value })
                                      }
                                    />
                                  </div>

                                  <div className="form-field">
                                    <label>LOCAL WG IP (/24)</label>
                                    <input
                                      disabled={role === "agent"}
                                      value={snDraft.wg_local_ip || "10.27.0.1"}
                                      onChange={(e) =>
                                        updateSNDraft({ wg_local_ip: e.target.value })
                                      }
                                    />
                                  </div>

                                  <div className="form-field">
                                    <label>PEER WG IP (/32)</label>
                                    <input
                                      disabled={role === "agent"}
                                      value={snDraft.wg_peer_ip || "10.27.0.2"}
                                      onChange={(e) =>
                                        updateSNDraft({ wg_peer_ip: e.target.value })
                                      }
                                    />
                                  </div>

                                  <div className="form-field">
                                    <label>THIS SERVER'S WG PUBLIC KEY</label>
                                    <input
                                      readOnly
                                      value={snDraft.wg_pub_key || "Auto-generated"}
                                    />
                                  </div>

                                  <div className="form-field">
                                    <label>PEER WG PUBLIC KEY</label>
                                    <input
                                      disabled={role === "agent"}
                                      value={snDraft.wg_peer_pub || ""}
                                      onChange={(e) =>
                                        updateSNDraft({ wg_peer_pub: e.target.value })
                                      }
                                      placeholder="Auto-filled via Bundle"
                                    />
                                  </div>
                                </>
                              )}

                              {snDraft.mode === "noise" && (
                                <>
                                  <div className="form-field">
                                    <label>THIS SERVER'S NOISE X25519 PUBLIC KEY</label>
                                    <input
                                      readOnly
                                      value={snDraft.noise_pub_key || "Auto-generated"}
                                    />
                                  </div>

                                  <div className="form-field">
                                    <label>PEER NOISE X25519 PUBLIC KEY</label>
                                    <input
                                      disabled={role === "agent"}
                                      value={snDraft.noise_peer_pub || ""}
                                      onChange={(e) =>
                                        updateSNDraft({
                                          noise_peer_pub: e.target.value,
                                        })
                                      }
                                      placeholder="Auto-filled via Bundle"
                                    />
                                  </div>
                                </>
                              )}
                            </div>

                            {/* SECTION 3: INDEPENDENT METHOD 27 BUNDLE (m27spf1_...) */}
                            <div className="settings-title" style={{ marginTop: "18px" }}>
                              <Copy size={15} />
                              <span>3. Method 27 Configuration Export / Import (m27spf1_...)</span>
                            </div>

                            <div
                              style={{
                                display: "flex",
                                flexDirection: "column",
                                gap: "10px",
                                marginTop: "8px",
                                padding: "12px",
                                borderRadius: "10px",
                                border: "1px solid rgba(148, 163, 184, 0.22)",
                              }}
                            >
                              <div
                                style={{
                                  display: "flex",
                                  gap: "8px",
                                  alignItems: "center",
                                  flexWrap: "wrap",
                                }}
                              >
                                <button
                                  type="button"
                                  className="next-method-btn"
                                  disabled={m27ActionBusy !== null}
                                  onClick={() =>
                                    handleSpoofNativeAction(
                                      selectedServer.id,
                                      "bundle",
                                      draft
                                    )
                                  }
                                >
                                  <Plus size={13} />
                                  <span>
                                    {m27ActionBusy === "bundle"
                                      ? "Generating..."
                                      : "Generate Method 27 Bundle (Master)"}
                                  </span>
                                </button>

                                {snDraft.last_bundle && (
                                  <button
                                    type="button"
                                    className="next-method-btn"
                                    style={
                                      copiedM27Bundle
                                        ? {
                                            borderColor: "#10b981",
                                            color: "#10b981",
                                          }
                                        : undefined
                                    }
                                    onClick={() =>
                                      copyM27BundleText(snDraft.last_bundle || "")
                                    }
                                  >
                                    {copiedM27Bundle ? (
                                      <Check size={13} />
                                    ) : (
                                      <Copy size={13} />
                                    )}
                                    <span>
                                      {copiedM27Bundle
                                        ? "✓ Bundle Copied!"
                                        : "Copy Bundle"}
                                    </span>
                                  </button>
                                )}
                              </div>

                              {snDraft.last_bundle && (
                                <input
                                  readOnly
                                  value={snDraft.last_bundle}
                                  style={{ fontSize: "12px", fontFamily: "monospace" }}
                                />
                              )}

                              <div
                                style={{
                                  display: "grid",
                                  gridTemplateColumns: "1fr auto",
                                  gap: "8px",
                                  alignItems: "center",
                                }}
                              >
                                <input
                                  value={m27BundleInput}
                                  onChange={(e) => setM27BundleInput(e.target.value)}
                                  placeholder="Paste m27spf1_... bundle here to import on Agent server"
                                />
                                <button
                                  type="button"
                                  className="next-method-btn"
                                  disabled={
                                    m27ActionBusy !== null ||
                                    !m27BundleInput.trim()
                                  }
                                  onClick={() =>
                                    handleSpoofNativeAction(
                                      selectedServer.id,
                                      "import",
                                      draft
                                    )
                                  }
                                >
                                  <span>
                                    {m27ActionBusy === "import"
                                      ? "Importing..."
                                      : "Import Bundle"}
                                  </span>
                                </button>
                              </div>
                            </div>

                            {/* SECTION 4: LIVE HEALTH, END-TO-END VERIFICATION & SERVICE CONTROLS */}
                            <div
                              style={{
                                marginTop: "18px",
                                padding: "12px 14px",
                                borderRadius: "10px",
                                border: "1px solid rgba(56, 189, 248, 0.25)",
                                background: "rgba(15, 23, 42, 0.35)",
                              }}
                            >
                              <div
                                style={{
                                  display: "flex",
                                  justifyContent: "space-between",
                                  alignItems: "center",
                                  flexWrap: "wrap",
                                  gap: "8px",
                                  marginBottom: "10px",
                                }}
                              >
                                <span style={{ fontWeight: 700, fontSize: "13px" }}>
                                  4. Method 27 Service Controls & End-to-End Pipe Verification
                                </span>
                                <div style={{ display: "flex", gap: "6px", flexWrap: "wrap" }}>
                                  <button
                                    type="button"
                                    className="next-method-btn"
                                    disabled={m27ActionBusy !== null}
                                    onClick={() =>
                                      handleSpoofNativeAction(
                                        selectedServer.id,
                                        "install_binary",
                                        draft
                                      )
                                    }
                                  >
                                    <ArrowDown size={12} />
                                    <span>
                                      {m27ActionBusy === "install_binary"
                                        ? "Installing..."
                                        : m27Health?.binary_installed
                                        ? "Verify Spoof Binary"
                                        : "Install Spoof v3.0.2"}
                                    </span>
                                  </button>

                                  <button
                                    type="button"
                                    className="next-method-btn"
                                    disabled={m27ActionBusy !== null}
                                    onClick={() =>
                                      handleSpoofNativeAction(
                                        selectedServer.id,
                                        "up",
                                        draft
                                      )
                                    }
                                  >
                                    <Play size={12} />
                                    <span>Apply & Start (spoof-core-m27)</span>
                                  </button>

                                  <button
                                    type="button"
                                    className="next-method-btn"
                                    disabled={m27ActionBusy !== null}
                                    onClick={() =>
                                      handleSpoofNativeAction(
                                        selectedServer.id,
                                        "verify_pipe",
                                        draft
                                      )
                                    }
                                  >
                                    <Activity size={12} />
                                    <span>Verify Spoof Pipe</span>
                                  </button>

                                  <button
                                    type="button"
                                    className="next-method-btn"
                                    disabled={m27ActionBusy !== null}
                                    onClick={() =>
                                      handleSpoofNativeAction(
                                        selectedServer.id,
                                        "down",
                                        draft
                                      )
                                    }
                                  >
                                    <Pause size={12} />
                                    <span>Stop Services</span>
                                  </button>
                                </div>
                              </div>

                              {m27ActionNotice && (
                                <div
                                  style={{
                                    fontSize: "12px",
                                    color: "#38bdf8",
                                    marginBottom: "8px",
                                  }}
                                >
                                  {m27ActionNotice}
                                </div>
                              )}

                              <div
                                style={{
                                  display: "grid",
                                  gridTemplateColumns: "repeat(auto-fit, minmax(175px, 1fr))",
                                  gap: "8px",
                                  fontSize: "12px",
                                }}
                              >
                                <div>
                                  <span style={{ opacity: 0.7 }}>CONNECTION STATE: </span>
                                  <strong
                                    style={{
                                      color:
                                        m27Health?.connection_state ===
                                        "REAL SPOOF ACTIVE"
                                          ? "#10b981"
                                          : "#f59e0b",
                                    }}
                                  >
                                    {m27Health?.connection_state || "DISCONNECTED"}
                                  </strong>
                                </div>
                                <div>
                                  <span style={{ opacity: 0.7 }}>ACTIVE ADAPTER: </span>
                                  <strong>
                                    {(m27Health?.active_adapter || snDraft.mode).toUpperCase()}
                                  </strong>
                                </div>
                                <div>
                                  <span style={{ opacity: 0.7 }}>SPOOF BINARY: </span>
                                  <strong>
                                    {m27Health?.binary_installed
                                      ? `v3.0.2${
                                          m27Health.binary_sha256_ok ? " ✓ SHA256" : ""
                                        }`
                                      : "MISSING"}
                                  </strong>
                                </div>
                                <div>
                                  <span style={{ opacity: 0.7 }}>SPOOF-CORE-M27: </span>
                                  <strong>
                                    {m27Health?.core_active ? "ACTIVE" : "STANDBY"}
                                  </strong>
                                </div>
                                <div>
                                  <span style={{ opacity: 0.7 }}>E2E PIPE VERIFIED: </span>
                                  <strong>
                                    {m27Health?.end_to_end_verified
                                      ? `YES (${m27Health.last_rtt_ms || 1}ms)`
                                      : "NO"}
                                  </strong>
                                </div>
                                <div>
                                  <span style={{ opacity: 0.7 }}>VERIFIED PATH: </span>
                                  <strong>{m27Health?.active_path || "NONE"}</strong>
                                </div>
                              </div>
                            </div>

                            {/* SECTION 5: INDEPENDENT METHOD 27 SPOOF IP TESTER */}
                            <div
                              style={{
                                marginTop: "18px",
                                padding: "12px 14px",
                                borderRadius: "10px",
                                border: "1px solid rgba(148, 163, 184, 0.22)",
                              }}
                            >
                              <div
                                style={{
                                  display: "flex",
                                  justifyContent: "space-between",
                                  alignItems: "center",
                                  flexWrap: "wrap",
                                  gap: "8px",
                                  marginBottom: "10px",
                                }}
                              >
                                <span style={{ fontWeight: 700, fontSize: "13px" }}>
                                  5. Method 27 Candidate Spoof IP Tester (/etc/spoof-m27)
                                </span>
                                <div style={{ display: "flex", gap: "6px", flexWrap: "wrap" }}>
                                  <button
                                    type="button"
                                    className="next-method-btn"
                                    disabled={
                                      m27ActionBusy !== null ||
                                      m27Tester?.status === "running"
                                    }
                                    onClick={() =>
                                      handleSpoofNativeAction(
                                        selectedServer.id,
                                        "tester_start",
                                        draft
                                      )
                                    }
                                  >
                                    <Play size={12} />
                                    <span>
                                      {m27Tester?.status === "running"
                                        ? `Testing (${m27Tester.progress || 0}%)...`
                                        : "Start IP Tester"}
                                    </span>
                                  </button>

                                  {m27Tester?.status === "running" && (
                                    <button
                                      type="button"
                                      className="next-method-btn"
                                      disabled={m27ActionBusy !== null}
                                      onClick={() =>
                                        handleSpoofNativeAction(
                                          selectedServer.id,
                                          "tester_stop",
                                          draft
                                        )
                                      }
                                    >
                                      <Pause size={12} />
                                      <span>Stop</span>
                                    </button>
                                  )}

                                  {m27Tester?.passed &&
                                    m27Tester.passed.length > 0 && (
                                      <button
                                        type="button"
                                        className="next-method-btn"
                                        style={{
                                          borderColor: "#10b981",
                                          color: "#10b981",
                                        }}
                                        onClick={() => {
                                          const ips = m27Tester.passed.map(
                                            (p) => p.ip
                                          );
                                          setSpoofIPsRawDraft((prev) => ({
                                            ...prev,
                                            [tunnelKey]: ips.join(", "),
                                          }));
                                          updateSNDraft({ spoof_ips: ips });
                                        }}
                                      >
                                        <Check size={12} />
                                        <span>
                                          Select {m27Tester.passed.length} Working IP(s)
                                        </span>
                                      </button>
                                    )}
                                </div>
                              </div>

                              <div className="settings-grid">
                                <div className="form-field">
                                  <label>TESTER ROLE</label>
                                  <select
                                    className="server-select"
                                    value={m27TesterMode}
                                    onChange={(e) =>
                                      setM27TesterMode(
                                        e.target.value as "receiver" | "sender"
                                      )
                                    }
                                    style={{ width: "100%", padding: "10px 12px" }}
                                  >
                                    <option value="receiver">
                                      Receiver (Start First on Receiving Node)
                                    </option>
                                    <option value="sender">
                                      Sender (Start Second on Sending Node)
                                    </option>
                                  </select>
                                </div>

                                <div className="form-field">
                                  <label>TEST CARRIER</label>
                                  <select
                                    className="server-select"
                                    value={m27TesterProto}
                                    onChange={(e) =>
                                      setM27TesterProto(
                                        e.target.value as "icmp" | "tcp"
                                      )
                                    }
                                    style={{ width: "100%", padding: "10px 12px" }}
                                  >
                                    <option value="icmp">ICMP</option>
                                    <option value="tcp">TCP</option>
                                  </select>
                                </div>

                                {m27TesterMode === "sender" && (
                                  <>
                                    <div className="form-field">
                                      <label>RECEIVER PUBLIC IPV4</label>
                                      <input
                                        value={
                                          m27TesterDstIP ||
                                          snDraft.peer_public_ip ||
                                          selectedServer.ip
                                        }
                                        onChange={(e) =>
                                          setM27TesterDstIP(e.target.value)
                                        }
                                        placeholder={selectedServer.ip}
                                      />
                                    </div>

                                    <div className="form-field">
                                      <label>DESTINATION PORT (TCP)</label>
                                      <input
                                        type="number"
                                        value={m27TesterDstPort}
                                        onChange={(e) =>
                                          setM27TesterDstPort(
                                            Number(e.target.value) || 80
                                          )
                                        }
                                      />
                                    </div>
                                  </>
                                )}

                                <div className="form-field">
                                  <label>TIMEOUT (SEC) / PACKET COUNT / MAX LOSS %</label>
                                  <div style={{ display: "flex", gap: "6px" }}>
                                    <input
                                      type="number"
                                      value={snDraft.timeout_sec || 30}
                                      onChange={(e) =>
                                        updateSNDraft({
                                          timeout_sec: Number(e.target.value) || 30,
                                        })
                                      }
                                    />
                                    <input
                                      type="number"
                                      value={snDraft.packet_count || 10}
                                      onChange={(e) =>
                                        updateSNDraft({
                                          packet_count: Number(e.target.value) || 10,
                                        })
                                      }
                                    />
                                    <input
                                      type="number"
                                      value={snDraft.max_loss_pct ?? 20}
                                      onChange={(e) =>
                                        updateSNDraft({
                                          max_loss_pct: Number(e.target.value) || 0,
                                        })
                                      }
                                    />
                                  </div>
                                </div>

                                <div className="form-field" style={{ gridColumn: "1 / -1" }}>
                                  <label>CANDIDATE SOURCE IPS / CIDRS TO TEST</label>
                                  <input
                                    value={m27TesterSourcesRaw}
                                    onChange={(e) =>
                                      setM27TesterSourcesRaw(e.target.value)
                                    }
                                    placeholder="8.8.8.8, 1.1.1.1, 9.9.9.9, 198.51.100.0/24"
                                  />
                                </div>
                              </div>

                              {m27Tester && m27Tester.status !== "idle" && (
                                <div
                                  style={{
                                    marginTop: "10px",
                                    fontSize: "12px",
                                    display: "flex",
                                    flexDirection: "column",
                                    gap: "6px",
                                  }}
                                >
                                  <div>
                                    <span>
                                      Tester Status:{" "}
                                      <strong>
                                        {m27Tester.status.toUpperCase()}
                                      </strong>{" "}
                                      ({m27Tester.mode} /{" "}
                                      {m27Tester.protocol?.toUpperCase()})
                                    </span>
                                    {m27Tester.error && (
                                      <span
                                        style={{
                                          color: "#ef4444",
                                          marginLeft: "8px",
                                        }}
                                      >
                                        — {m27Tester.error}
                                      </span>
                                    )}
                                  </div>

                                  {m27Tester.passed &&
                                    m27Tester.passed.length > 0 && (
                                      <div
                                        style={{
                                          display: "flex",
                                          flexWrap: "wrap",
                                          gap: "6px",
                                        }}
                                      >
                                        {m27Tester.passed.map((item, idx) => (
                                          <span
                                            key={idx}
                                            className="disc-pill disc-ok"
                                          >
                                            {item.ip} ({item.received}/
                                            {item.sent} • {item.loss_pct}% loss)
                                          </span>
                                        ))}
                                      </div>
                                    )}
                                </div>
                              )}
                            </div>

                            {errBanner && (
                              <div className="form-error-banner" style={{ marginTop: "10px" }}>
                                {errBanner}
                              </div>
                            )}

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
                                  <span>
                                    {isSaving
                                      ? "Saving..."
                                      : "Save Method 27 Settings"}
                                  </span>
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
