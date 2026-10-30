import { useEffect, useState } from "react";
import {
  Activity,
  ArrowDownToLine,
  ArrowUpFromLine,
  Cable,
  Check,
  ChevronRight,
  CircleHelp,
  Cpu,
  Globe,
  LayoutDashboard,
  LogOut,
  Moon,
  Network,
  Play,
  Server,
  Settings2,
  ShieldCheck,
  Sun,
  Wifi,
} from "lucide-react";

type NodeInfo = {
  app_version: string;
  role: "master" | "agent";
  node_id: string;
  status: string;
  panel_url: string;
};

type Tab = "servers" | "tunnels" | "analytics";

export default function App() {
  const [tab, setTab] = useState<Tab>("servers");
  const [node, setNode] = useState<NodeInfo | null>(null);
  const [loading, setLoading] = useState(true);
  const [lightMode, setLightMode] = useState(false);

  useEffect(() => {
    fetch("/api/v1/node", { credentials: "same-origin" })
      .then((response) => {
        if (!response.ok) throw new Error("Unable to load node information");
        return response.json();
      })
      .then((data: NodeInfo) => setNode(data))
      .catch(() => setNode(null))
      .finally(() => setLoading(false));
  }, []);

  const role = node?.role?.toUpperCase() ?? "UNKNOWN";

  return (
    <div className={lightMode ? "app light" : "app"}>
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-icon"><Network size={21} /></div>
          <div>
            <div className="brand-name">SAHAND</div>
            <div className="brand-subtitle">TUNNEL</div>
          </div>
        </div>

        <div className="nav-label">WORKSPACE</div>
        <nav className="navigation">
          <button
            className={tab === "servers" ? "nav-item active" : "nav-item"}
            onClick={() => setTab("servers")}
          >
            <Server size={18} />
            <span>Servers</span>
            {tab === "servers" && <ChevronRight size={15} />}
          </button>

          <button
            className={tab === "tunnels" ? "nav-item active" : "nav-item"}
            onClick={() => setTab("tunnels")}
          >
            <Cable size={18} />
            <span>Tunnels</span>
            {tab === "tunnels" && <ChevronRight size={15} />}
          </button>

          <button
            className={tab === "analytics" ? "nav-item active" : "nav-item"}
            onClick={() => setTab("analytics")}
          >
            <Activity size={18} />
            <span>Analytics</span>
            {tab === "analytics" && <ChevronRight size={15} />}
          </button>
        </nav>

        <div className="sidebar-bottom">
          <div className="security-note">
            <ShieldCheck size={18} />
            <div>
              <strong>Secure connection</strong>
              <span>Session protected</span>
            </div>
          </div>
          <button className="theme-button" onClick={() => setLightMode(!lightMode)}>
            {lightMode ? <Moon size={17} /> : <Sun size={17} />}
            <span>{lightMode ? "Dark appearance" : "Light appearance"}</span>
          </button>
          <form action="/logout" method="post">
            <button className="logout-button" type="submit">
              <LogOut size={17} />
              <span>Sign out</span>
            </button>
          </form>
          <div className="sidebar-version">
            Sahand Tunnel · {node?.app_version ?? "—"}
          </div>
        </div>
      </aside>

      <main className="main">
        <header className="topbar">
          <div className="breadcrumb">
            <span>Workspace</span>
            <ChevronRight size={14} />
            <strong>
              {tab === "servers" ? "Servers" : tab === "tunnels" ? "Tunnels" : "Analytics"}
            </strong>
          </div>
          <div className="topbar-right">
            <span className="role-badge">{role}</span>
            <div className="user-avatar">S</div>
          </div>
        </header>

        <div className="content">
          {tab === "servers" && (
            <ServersPage node={node} loading={loading} />
          )}
          {tab === "tunnels" && <TunnelsPage />}
          {tab === "analytics" && <AnalyticsPage />}
        </div>
      </main>
    </div>
  );
}

function PageHeading({
  eyebrow,
  title,
  description,
}: {
  eyebrow: string;
  title: string;
  description: string;
}) {
  return (
    <div className="page-heading">
      <div className="eyebrow">{eyebrow}</div>
      <h1>{title}</h1>
      <p>{description}</p>
    </div>
  );
}

function ServersPage({
  node,
  loading,
}: {
  node: NodeInfo | null;
  loading: boolean;
}) {
  return (
    <>
      <PageHeading
        eyebrow="INFRASTRUCTURE"
        title="Servers"
        description="Manage your Sahand Tunnel nodes and connections."
      />

      <div className="overview-grid">
        <div className="panel overview-card">
          <div className="card-top">
            <div className="icon-box blue"><Server size={19} /></div>
            <span className="muted-label">NODE STATUS</span>
          </div>
          <div className="metric">
            {loading ? "Loading" : node ? "Online" : "Unavailable"}
          </div>
          <div className="metric-foot">
            <span className={node ? "status-dot green" : "status-dot gray"} />
            {node ? "Application is responding" : "Node information unavailable"}
          </div>
        </div>

        <div className="panel overview-card">
          <div className="card-top">
            <div className="icon-box violet"><Network size={19} /></div>
            <span className="muted-label">SERVER ROLE</span>
          </div>
          <div className="metric">{loading ? "—" : node?.role?.toUpperCase() ?? "—"}</div>
          <div className="metric-foot">Configured node role</div>
        </div>

        <div className="panel overview-card">
          <div className="card-top">
            <div className="icon-box green"><Cpu size={19} /></div>
            <span className="muted-label">APP VERSION</span>
          </div>
          <div className="metric">{node?.app_version ?? "—"}</div>
          <div className="metric-foot">Installed application version</div>
        </div>
      </div>

      <section className="section">
        <div className="section-heading">
          <div>
            <h2>This server</h2>
            <p>Identity and configuration information for this node.</p>
          </div>
          <span className="section-tag">LOCAL NODE</span>
        </div>

        <div className="panel details-panel">
          <DetailRow label="Node ID" value={node?.node_id ?? "Not available"} />
          <DetailRow label="Role" value={node?.role?.toUpperCase() ?? "Not available"} />
          <DetailRow label="Version" value={node?.app_version ?? "Not available"} />
          <DetailRow label="Panel URL" value={node?.panel_url || "Not configured"} />
        </div>
      </section>

      <section className="section">
        <div className="section-heading">
          <div>
            <h2>Node pairing</h2>
            <p>Master and Agent registration will be managed here.</p>
          </div>
        </div>
        <div className="panel empty-panel">
          <div className="empty-icon"><Globe size={22} /></div>
          <h3>Pairing interface not connected</h3>
          <p>
            Registration, token generation and peer discovery will appear here
            after the backend pairing API is implemented.
          </p>
          <span className="coming-label">BACKEND INTEGRATION PENDING</span>
        </div>
      </section>
    </>
  );
}

function DetailRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="detail-row">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function TunnelsPage() {
  return (
    <>
      <PageHeading
        eyebrow="TRAFFIC MANAGEMENT"
        title="Tunnels"
        description="Configure traffic forwarding methods independently from connection discovery."
      />

      <div className="notice-panel">
        <div className="notice-icon"><CircleHelp size={19} /></div>
        <div>
          <strong>Traffic engine is not connected yet</strong>
          <p>
            The forwarding controls will become active when the tunnel engine
            and its driver APIs are implemented. No traffic is being forwarded
            by this dashboard yet.
          </p>
        </div>
      </div>

      <div className="overview-grid two">
        <div className="panel overview-card">
          <div className="card-top">
            <div className="icon-box blue"><Wifi size={19} /></div>
            <span className="muted-label">DISCOVERY METHODS</span>
          </div>
          <div className="metric">30 planned</div>
          <div className="metric-foot">Each method will be tested independently</div>
        </div>
        <div className="panel overview-card">
          <div className="card-top">
            <div className="icon-box violet"><Play size={19} /></div>
            <span className="muted-label">TRAFFIC FORWARDING</span>
          </div>
          <div className="metric">Not active</div>
          <div className="metric-foot">Waiting for engine integration</div>
        </div>
      </div>

      <section className="section">
        <div className="section-heading">
          <div>
            <h2>Connection methods</h2>
            <p>Method-specific configuration and TCP/UDP capabilities.</p>
          </div>
          <span className="section-tag">PLANNED</span>
        </div>
        <div className="panel empty-panel">
          <div className="empty-icon"><Settings2 size={22} /></div>
          <h3>Driver catalog pending</h3>
          <p>
            The 30 method names, supported protocols, port settings and
            independent traffic switches will be added after the driver
            specifications are finalized.
          </p>
          <span className="coming-label">NOT YET CONFIGURABLE</span>
        </div>
      </section>
    </>
  );
}

function AnalyticsPage() {
  return (
    <>
      <PageHeading
        eyebrow="NETWORK INSIGHTS"
        title="Analytics"
        description="Monitor traffic usage on this server."
      />

      <div className="overview-grid two">
        <div className="panel overview-card">
          <div className="card-top">
            <div className="icon-box blue"><ArrowDownToLine size={19} /></div>
            <span className="muted-label">INCOMING TRAFFIC</span>
          </div>
          <div className="metric">—</div>
          <div className="metric-foot">Download · Data not available</div>
        </div>
        <div className="panel overview-card">
          <div className="card-top">
            <div className="icon-box violet"><ArrowUpFromLine size={19} /></div>
            <span className="muted-label">OUTGOING TRAFFIC</span>
          </div>
          <div className="metric">—</div>
          <div className="metric-foot">Upload · Data not available</div>
        </div>
      </div>

      <section className="section">
        <div className="section-heading">
          <div>
            <h2>Traffic history</h2>
            <p>Usage history for this host only.</p>
          </div>
          <span className="section-tag">LOCAL NODE</span>
        </div>
        <div className="panel empty-panel chart-placeholder">
          <div className="empty-icon"><Activity size={22} /></div>
          <h3>No traffic history available</h3>
          <p>
            Real network measurements will be displayed after the traffic
            accounting service is implemented. No sample or fabricated
            statistics are shown.
          </p>
          <span className="coming-label">ANALYTICS ENGINE PENDING</span>
        </div>
      </section>
    </>
  );
}
