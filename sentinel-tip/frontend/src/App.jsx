import React, { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import ForceGraph2D from "react-force-graph-2d";
import {
  Shield,
  Activity,
  Layers,
  Cpu,
  Network,
  FileCode,
  Share2,
  TrendingUp,
  CreditCard,
  Lock,
  LogOut,
  RefreshCw,
  Search,
  CheckCircle2,
  AlertTriangle,
  Server,
  Zap,
  Clock,
  Terminal,
} from "lucide-react";

const API_BASE = "http://127.0.0.1:8000/api/v1";

export default function App() {
  const [token, setToken] = useState(localStorage.getItem("threatops_token") || "");
  const [user, setUser] = useState(null);
  const [activeTab, setActiveTab] = useState("pipeline"); // pipeline, ensemble, graph, rules, siem, impact, pricing

  // Live IOC feed & metrics state
  const [iocs, setIocs] = useState([]);
  const [filterType, setFilterType] = useState("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [refreshing, setRefreshing] = useState(false);

  // Scanner state
  const [scanIoc, setScanIoc] = useState("http://194.55.186.21:54321/Mozi.a");
  const [scanResult, setScanResult] = useState(null);
  const [scanning, setScanning] = useState(false);

  // Graph state (Neo4j)
  const [graphData, setGraphData] = useState({ nodes: [], links: [] });

  // Rule Generator state (Sigma, YARA, Suricata, Snort)
  const [ruleIoc, setRuleIoc] = useState("185.220.101.45");
  const [rules, setRules] = useState(null);
  const [selectedRuleFmt, setSelectedRuleFmt] = useState("sigma");

  // Parallel Enrichment state (VirusTotal, AbuseIPDB, Shodan, AlienVault OTX)
  const [enrichIoc, setEnrichIoc] = useState("91.215.85.142");
  const [enrichment, setEnrichment] = useState(null);
  const [enriching, setEnriching] = useState(false);

  // SIEM/SOAR/EDR Export state
  const [selectedSiem, setSelectedSiem] = useState("splunk");
  const [exportData, setExportData] = useState(null);

  // Check URL params for Easebuzz payment return
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    if (params.get("success") === "true") {
      localStorage.setItem("threatops_subscribed", "true");
      window.history.replaceState({}, document.title, window.location.pathname);
      if (user) setUser({ ...user, subscription_status: "active" });
    }
  }, [user]);

  // Auth profile bootstrap
  useEffect(() => {
    if (token) {
      fetch(`${API_BASE}/auth/me`, {
        headers: { Authorization: `Bearer ${token}` },
      })
        .then((res) => {
          if (res.ok) return res.json();
          throw new Error("Session invalid");
        })
        .then((data) => {
          setUser(data);
          loadDashboardData();
        })
        .catch(() => {
          setToken("");
          localStorage.removeItem("threatops_token");
        });
    }
  }, [token]);

  const loadDashboardData = async () => {
    try {
      const res = await fetch(`${API_BASE}/iocs?limit=40`);
      if (res.ok) setIocs(await res.json());
    } catch (e) {
      console.warn("Could not load IOCs:", e);
    }
  };

  const handleSsoAuthenticate = async () => {
    try {
      const res = await fetch(`${API_BASE}/auth/sso`, { method: "POST" });
      const data = await res.json();
      if (res.ok && data.access_token) {
        localStorage.setItem("threatops_token", data.access_token);
        setToken(data.access_token);
        setUser({
          email: data.email,
          full_name: data.full_name,
          subscription_status: data.subscription_status,
        });
        loadDashboardData();
      }
    } catch (err) {
      console.error("SSO handshake error:", err);
    }
  };

  const handleScanIndicator = async () => {
    setScanning(true);
    try {
      const res = await fetch(`${API_BASE}/scan/ioc`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ioc_value: scanIoc }),
      });
      if (res.ok) setScanResult(await res.json());
    } finally {
      setScanning(false);
    }
  };

  const handleFetchGraph = async () => {
    const res = await fetch(`${API_BASE}/org/graph-correlations`);
    if (res.ok) setGraphData(await res.json());
  };

  const handleGenerateRules = async () => {
    const res = await fetch(`${API_BASE}/rules/generate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ioc_value: ruleIoc }),
    });
    if (res.ok) setRules(await res.json());
  };

  const handleExecuteEnrichment = async () => {
    setEnriching(true);
    try {
      const res = await fetch(`${API_BASE}/enrich/parallel`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ioc_value: enrichIoc }),
      });
      if (res.ok) setEnrichment(await res.json());
    } finally {
      setEnriching(false);
    }
  };

  const handleExportSiem = async (platform) => {
    setSelectedSiem(platform);
    const res = await fetch(`${API_BASE}/export/${platform}`);
    if (res.ok) setExportData(await res.json());
  };

  const handleEasebuzzSubscribe = async (tier) => {
    const res = await fetch(`${API_BASE}/auth/create-checkout-session`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ tier }),
    });
    const data = await res.json();
    if (data.checkout_url) window.location.href = data.checkout_url;
  };

  // --- 1. ENTERPRISE AUTHENTICATION SCREEN ---
  if (!token || !user) {
    return (
      <div className="app-shell" style={{ justifyContent: "center", alignItems: "center" }}>
        <div className="threatops-bg-canvas" />
        <div className="threatops-grid-pattern" />

        <motion.div initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} className="threat-panel" style={{ width: 480, textAlign: "center", padding: 36 }}>
          <div style={{ display: "inline-flex", padding: 14, background: "rgba(0, 242, 254, 0.12)", borderRadius: 14, marginBottom: 18 }}>
            <Shield size={44} color="#00f2fe" />
          </div>
          <h1 className="brand-name" style={{ fontSize: "2rem", marginBottom: 6 }}>ThreatOps</h1>
          <p style={{ color: "var(--text-secondary)", fontSize: "0.88rem", marginBottom: 8 }}>
            Enterprise Threat Intelligence Platform
          </p>
          <p style={{ color: "var(--text-muted)", fontSize: "0.78rem", marginBottom: 28 }}>
            Automated IOC Analysis · ML-Powered Detection · Graph Correlation
          </p>

          <button className="btn-cyber-primary" style={{ width: "100%", justifyContent: "center", padding: "12px 20px" }} onClick={handleSsoAuthenticate}>
            <Lock size={16} /> Authenticate via OAuth 2.0 / SAML[cite: 1]
          </button>

          <div style={{ marginTop: 24, paddingTop: 18, borderTop: "1px solid var(--border-color)", display: "flex", justifyContent: "space-around", fontSize: "0.75rem", color: "var(--text-muted)" }}>
            <span>96.2% Accuracy[cite: 1]</span>
            <span>&lt; 13s Triage[cite: 1]</span>
            <span>SOC 2 Type II[cite: 1]</span>
          </div>
        </motion.div>
      </div>
    );
  }

  // --- 2. EASEBUZZ SUBSCRIPTION PAYWALL (IF INACTIVE) ---
  const isSubscribed = user.subscription_status === "active" || localStorage.getItem("threatops_subscribed") === "true";
  if (!isSubscribed) {
    return (
      <div className="app-shell" style={{ justifyContent: "center", alignItems: "center", padding: 24 }}>
        <div className="threatops-bg-canvas" />
        <div className="threatops-grid-pattern" />

        <div style={{ maxWidth: 1100, width: "100%" }}>
          <div style={{ textAlign: "center", marginBottom: 36 }}>
            <h2 style={{ fontSize: "2.2rem", fontWeight: 800 }}>Transparent Pricing[cite: 1]</h2>
            <p style={{ color: "var(--text-secondary)", marginTop: 6 }}>
              Flexible tiers for teams of every size — start in 1 day (Secured by Easebuzz)[cite: 1]
            </p>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(310px, 1fr))", gap: 20 }}>
            {/* Starter Plan (Slide 9) */}
            <div className="threat-panel" style={{ textAlign: "center" }}>
              <h3 style={{ fontSize: "1.3rem" }}>Starter[cite: 1]</h3>
              <div style={{ fontSize: "2.2rem", fontWeight: 800, color: "var(--brand-cyan)", margin: "14px 0" }}>$2,499<span style={{ fontSize: "0.9rem", color: "var(--text-muted)" }}>/mo[cite: 1]</span></div>
              <ul style={{ textAlign: "left", color: "var(--text-secondary)", fontSize: "0.85rem", listStyle: "none", padding: 0, display: "flex", flexDirection: "column", gap: 10 }}>
                <li><CheckCircle2 size={16} color="#10b981" style={{ verticalAlign: "middle", marginRight: 8 }} />1,000 IOCs/day[cite: 1]</li>
                <li><CheckCircle2 size={16} color="#10b981" style={{ verticalAlign: "middle", marginRight: 8 }} />5 users[cite: 1]</li>
                <li><CheckCircle2 size={16} color="#10b981" style={{ verticalAlign: "middle", marginRight: 8 }} />Email support[cite: 1]</li>
                <li><CheckCircle2 size={16} color="#10b981" style={{ verticalAlign: "middle", marginRight: 8 }} />Full feature access[cite: 1]</li>
              </ul>
              <button className="btn-cyber-outline" style={{ width: "100%", justifyContent: "center", marginTop: 24 }} onClick={() => handleEasebuzzSubscribe("starter")}>
                Select Starter (Easebuzz)[cite: 1]
              </button>
            </div>

            {/* Professional Plan (Slide 9 - Most Popular) */}
            <div className="threat-panel" style={{ textAlign: "center", borderColor: "var(--brand-cyan)", position: "relative" }}>
              <div style={{ position: "absolute", top: -12, left: "50%", transform: "translateX(-50%)", background: "var(--brand-cyan)", color: "#000", fontSize: "0.7rem", fontWeight: 800, padding: "2px 10px", borderRadius: 999 }}>
                MOST POPULAR[cite: 1]
              </div>
              <h3 style={{ fontSize: "1.3rem" }}>Professional[cite: 1]</h3>
              <div style={{ fontSize: "2.2rem", fontWeight: 800, color: "var(--brand-cyan)", margin: "14px 0" }}>$5,999<span style={{ fontSize: "0.9rem", color: "var(--text-muted)" }}>/mo[cite: 1]</span></div>
              <ul style={{ textAlign: "left", color: "var(--text-secondary)", fontSize: "0.85rem", listStyle: "none", padding: 0, display: "flex", flexDirection: "column", gap: 10 }}>
                <li><CheckCircle2 size={16} color="#10b981" style={{ verticalAlign: "middle", marginRight: 8 }} />10,000 IOCs/day[cite: 1]</li>
                <li><CheckCircle2 size={16} color="#10b981" style={{ verticalAlign: "middle", marginRight: 8 }} />20 users[cite: 1]</li>
                <li><CheckCircle2 size={16} color="#10b981" style={{ verticalAlign: "middle", marginRight: 8 }} />24/7 Phone[cite: 1]</li>
                <li><CheckCircle2 size={16} color="#10b981" style={{ verticalAlign: "middle", marginRight: 8 }} />Priority onboarding[cite: 1]</li>
              </ul>
              <button className="btn-cyber-primary" style={{ width: "100%", justifyContent: "center", marginTop: 24 }} onClick={() => handleEasebuzzSubscribe("professional")}>
                Select Professional (Easebuzz)[cite: 1]
              </button>
            </div>

            {/* Enterprise Plan (Slide 9) */}
            <div className="threat-panel" style={{ textAlign: "center" }}>
              <h3 style={{ fontSize: "1.3rem" }}>Enterprise[cite: 1]</h3>
              <div style={{ fontSize: "2.2rem", fontWeight: 800, color: "var(--brand-cyan)", margin: "14px 0" }}>$14,999<span style={{ fontSize: "0.9rem", color: "var(--text-muted)" }}>/mo[cite: 1]</span></div>
              <ul style={{ textAlign: "left", color: "var(--text-secondary)", fontSize: "0.85rem", listStyle: "none", padding: 0, display: "flex", flexDirection: "column", gap: 10 }}>
                <li><CheckCircle2 size={16} color="#10b981" style={{ verticalAlign: "middle", marginRight: 8 }} />Unlimited IOCs[cite: 1]</li>
                <li><CheckCircle2 size={16} color="#10b981" style={{ verticalAlign: "middle", marginRight: 8 }} />Unlimited users[cite: 1]</li>
                <li><CheckCircle2 size={16} color="#10b981" style={{ verticalAlign: "middle", marginRight: 8 }} />Dedicated CSM[cite: 1]</li>
                <li><CheckCircle2 size={16} color="#10b981" style={{ verticalAlign: "middle", marginRight: 8 }} />Custom integrations[cite: 1]</li>
              </ul>
              <button className="btn-cyber-outline" style={{ width: "100%", justifyContent: "center", marginTop: 24 }} onClick={() => handleEasebuzzSubscribe("enterprise")}>
                Select Enterprise (Easebuzz)[cite: 1]
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  }

  // --- 3. MAIN DASHBOARD WITH NON-OVERLAPPING STICKY TOP NAVBAR ---
  return (
    <div className="app-shell">
      <div className="threatops-bg-canvas" />
      <div className="threatops-grid-pattern" />

      {/* TOP NAVIGATION BAR (DOES NOT OVERLAP MAIN VIEWPORT) */}
      <header className="top-navbar">
        <div className="brand-wrapper">
          <Shield size={28} color="#00f2fe" />
          <div>
            <span className="brand-name">ThreatOps</span>
            <span className="brand-badge" style={{ marginLeft: 8 }}>ENTERPRISE[cite: 1]</span>
          </div>
        </div>

        <nav className="nav-links-row">
          <button className={`nav-pill-btn ${activeTab === "pipeline" ? "active" : ""}`} onClick={() => setActiveTab("pipeline")}>
            <Activity size={15} /> 13s Pipeline[cite: 1]
          </button>
          <button className={`nav-pill-btn ${activeTab === "ensemble" ? "active" : ""}`} onClick={() => setActiveTab("ensemble")}>
            <Cpu size={15} /> 96.2% ML Engine[cite: 1]
          </button>
          <button className={`nav-pill-btn ${activeTab === "graph" ? "active" : ""}`} onClick={() => { setActiveTab("graph"); handleFetchGraph(); }}>
            <Network size={15} /> Neo4j Graph[cite: 1]
          </button>
          <button className={`nav-pill-btn ${activeTab === "rules" ? "active" : ""}`} onClick={() => { setActiveTab("rules"); handleGenerateRules(); }}>
            <FileCode size={15} /> Detection Rules[cite: 1]
          </button>
          <button className={`nav-pill-btn ${activeTab === "enrich" ? "active" : ""}`} onClick={() => { setActiveTab("enrich"); handleExecuteEnrichment(); }}>
            <Zap size={15} /> 6-Source Enricher[cite: 1]
          </button>
          <button className={`nav-pill-btn ${activeTab === "siem" ? "active" : ""}`} onClick={() => { setActiveTab("siem"); handleExportSiem("splunk"); }}>
            <Share2 size={15} /> SIEM / SOAR[cite: 1]
          </button>
          <button className={`nav-pill-btn ${activeTab === "impact" ? "active" : ""}`} onClick={() => setActiveTab("impact")}>
            <TrendingUp size={15} /> ROI & Impact[cite: 1]
          </button>
        </nav>

        <div className="user-status-group">
          <span style={{ fontSize: "0.8rem", color: "var(--text-secondary)" }}>{user.email}</span>
          <button className="btn-cyber-outline" style={{ padding: "6px 10px" }} onClick={() => { setToken(""); setUser(null); }} title="Sign Out">
            <LogOut size={14} />
          </button>
        </div>
      </header>

      {/* SECONDARY LIVE TELEMETRY TICKER (SLIDE 1 METRICS) */}
      <aside className="live-telemetry-strip" aria-label="Platform Telemetry">
        <div className="telemetry-chip">
          <span style={{ color: "var(--text-muted)" }}>ML ACCURACY:</span>
          <span className="telemetry-val">96.2%[cite: 1]</span>
        </div>
        <div className="telemetry-chip">
          <span style={{ color: "var(--text-muted)" }}>PROCESSING RATE:</span>
          <span className="telemetry-val">90,000+ IOCs / Day[cite: 1]</span>
        </div>
        <div className="telemetry-chip">
          <span style={{ color: "var(--text-muted)" }}>AVG. RESPONSE:</span>
          <span className="telemetry-val" style={{ color: "#a855f7" }}>13 sec (vs 24-48 hrs)[cite: 1]</span>
        </div>
        <div className="telemetry-chip">
          <span style={{ color: "var(--text-muted)" }}>ANALYST TIME SAVED:</span>
          <span className="telemetry-val" style={{ color: "#10b981" }}>70%[cite: 1]</span>
        </div>
        <div className="telemetry-chip">
          <span style={{ color: "var(--text-muted)" }}>FALSE POSITIVES:</span>
          <span className="telemetry-val">&lt; 1.8% (down from 40%)[cite: 1]</span>
        </div>
      </aside>

      {/* MAIN VIEWPORT (NEVER OVERLAPPED) */}
      <main className="main-viewport">
        <AnimatePresence mode="wait">
          
          {/* TAB 1: 13-SECOND PROCESSING PIPELINE (SLIDE 4) */}
          {activeTab === "pipeline" && (
            <motion.div key="pipeline" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -10 }}>
              <div style={{ marginBottom: 20 }}>
                <h2 style={{ fontSize: "1.5rem", fontWeight: 800 }}>How It Works: 13-Second Triage Pipeline[cite: 1]</h2>
                <p style={{ color: "var(--text-secondary)", fontSize: "0.85rem" }}>
                  From raw indicator to actionable detection — in under 13 seconds (vs. 24–48 hours manually)[cite: 1]
                </p>
              </div>

              {/* 6-Stage Workflow Cards (Slide 4) */}
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(210px, 1fr))", gap: 14, marginBottom: 26 }}>
                {[
                  { step: "1", title: "Ingest", desc: "OSINT + Commercial Feeds[cite: 1]" },
                  { step: "2", title: "Enrich", desc: "6 Parallel Analyzers (<5s)[cite: 1]" },
                  { step: "3", title: "Classify", desc: "ML Ensemble (RF/XGB/NN)[cite: 1]" },
                  { step: "4", title: "Correlate", desc: "Neo4j Graph Engine[cite: 1]" },
                  { step: "5", title: "Detect", desc: "Auto Rule Generation (<30s)[cite: 1]" },
                  { step: "6", title: "Deploy", desc: "SIEM / EDR / SOAR Push[cite: 1]" },
                ].map((s) => (
                  <div key={s.step} className="hero-kpi-card" style={{ padding: "16px 18px" }}>
                    <div style={{ display: "flex", justifyContent: "space-between", color: "var(--brand-cyan)", fontWeight: 800, fontSize: "0.8rem" }}>
                      <span>STAGE {s.step}</span>
                      <Clock size={14} />
                    </div>
                    <div style={{ fontWeight: 700, fontSize: "1.05rem", marginTop: 6 }}>{s.title}</div>
                    <div style={{ fontSize: "0.78rem", color: "var(--text-muted)", marginTop: 4 }}>{s.desc}</div>
                  </div>
                ))}
              </div>

              {/* On-Demand Real-Time Indicator Scanner */}
              <div className="threat-panel">
                <h3 style={{ fontSize: "1.1rem", marginBottom: 12 }}>Test Indicator Through 13-Second Pipeline[cite: 1]</h3>
                <div style={{ display: "flex", gap: 12, marginBottom: 16, flexWrap: "wrap" }}>
                  <input
                    type="text"
                    className="threat-input"
                    style={{ flex: 1, minWidth: 280 }}
                    value={scanIoc}
                    onChange={(e) => setScanIoc(e.target.value)}
                    placeholder="Enter URL, Domain, or IPv4..."
                  />
                  <button className="btn-cyber-primary" onClick={handleScanIndicator} disabled={scanning}>
                    <Terminal size={15} /> {scanning ? "Running 13s Pipeline..." : "Analyze Indicator"}
                  </button>
                </div>

                {scanResult && (
                  <div style={{ background: "rgba(3, 7, 18, 0.7)", border: "1px solid var(--border-color)", borderRadius: 10, padding: 18 }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12, flexWrap: "wrap", gap: 10 }}>
                      <div>
                        <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>VERDICT</span>
                        <div style={{ fontSize: "1.2rem", fontWeight: 800, color: scanResult.risk_score >= 70 ? "var(--status-critical)" : "var(--status-good)" }}>
                          {scanResult.verdict} (Score: {scanResult.risk_score}/100)
                        </div>
                      </div>
                      <div style={{ display: "flex", gap: 10 }}>
                        <span className="badge-critical">P(Malicious): {(scanResult.ml_malicious_probability * 100).toFixed(1)}%</span>
                        {scanResult.is_anomaly && <span className="badge-critical" style={{ background: "rgba(168, 85, 247, 0.2)", color: "#c084fc", borderColor: "#a855f7" }}>ISOLATION FOREST OUTLIER</span>}
                      </div>
                    </div>

                    <div style={{ fontSize: "0.85rem", color: "var(--text-secondary)", marginBottom: 10 }}>
                      <strong>Explainable AI Factors:</strong> {scanResult.reasons.join(" • ")}
                    </div>
                  </div>
                )}
              </div>

              {/* Active Threat Feed Table */}
              <div className="threat-panel">
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16, flexWrap: "wrap", gap: 12 }}>
                  <h3 style={{ fontSize: "1.1rem" }}>Active OSINT Ingestion Feed ({iocs.length} Indicators)</h3>
                  <button className="btn-cyber-outline" onClick={loadDashboardData}>
                    <RefreshCw size={14} /> Refresh Ingestion
                  </button>
                </div>
                <div style={{ overflowX: "auto" }}>
                  <table className="threat-table">
                    <thead>
                      <tr>
                        <th>Indicator (IOC)</th>
                        <th>Type</th>
                        <th>Classification</th>
                        <th>Malware Tags</th>
                        <th>Ensemble Prob</th>
                        <th>Risk Score</th>
                      </tr>
                    </thead>
                    <tbody>
                      {iocs.map((item) => (
                        <tr key={item.id}>
                          <td className="mono-cell" style={{ maxWidth: 360 }}>{item.ioc_value}</td>
                          <td><span className="badge-tag">{item.ioc_type.toUpperCase()}</span></td>
                          <td>{item.threat_type}</td>
                          <td>{item.tags.slice(0, 3).map((t, i) => (<span key={i} className="badge-tag">{t}</span>))}</td>
                          <td>{item.ml_malicious_prob ? `${(item.ml_malicious_prob * 100).toFixed(1)}%` : "N/A"}</td>
                          <td><span className={item.risk_score >= 70 ? "badge-critical" : "badge-tag"}>{item.risk_score}/100</span></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </motion.div>
          )}

          {/* TAB 2: 96.2% ML ENSEMBLE ENGINE (SLIDE 5) */}
          {activeTab === "ensemble" && (
            <motion.div key="ensemble" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -10 }}>
              <div style={{ marginBottom: 20 }}>
                <h2 style={{ fontSize: "1.5rem", fontWeight: 800 }}>ML Classification Engine[cite: 1]</h2>
                <p style={{ color: "var(--text-secondary)", fontSize: "0.85rem" }}>
                  Ensemble model with 96.2% precision and &lt;2% false positive rate across 150 Input Features[cite: 1]
                </p>
              </div>

              {/* Exact Slide 5 Metrics Grid */}
              <div className="hero-kpi-grid">
                <div className="hero-kpi-card">
                  <div className="kpi-title"><span>Precision</span><CheckCircle2 size={16} color="#00f2fe" /></div>
                  <div className="kpi-metric-number" style={{ color: "#00f2fe" }}>96.2%[cite: 1]</div>
                  <div className="kpi-subtext">Voting Classifier Verdict[cite: 1]</div>
                </div>
                <div className="hero-kpi-card">
                  <div className="kpi-title"><span>Recall</span><CheckCircle2 size={16} color="#4facfe" /></div>
                  <div className="kpi-metric-number" style={{ color: "#4facfe" }}>94.8%[cite: 1]</div>
                  <div className="kpi-subtext">True threat capture rate[cite: 1]</div>
                </div>
                <div className="hero-kpi-card">
                  <div className="kpi-title"><span>F1-Score</span><CheckCircle2 size={16} color="#8b5cf6" /></div>
                  <div className="kpi-metric-number" style={{ color: "#8b5cf6" }}>95.5%[cite: 1]</div>
                  <div className="kpi-subtext">Harmonic balance[cite: 1]</div>
                </div>
                <div className="hero-kpi-card">
                  <div className="kpi-title"><span>False Positive Rate</span><AlertTriangle size={16} color="#10b981" /></div>
                  <div className="kpi-metric-number" style={{ color: "#10b981" }}>&lt; 2%[cite: 1]</div>
                  <div className="kpi-subtext">Prevents alert fatigue[cite: 1]</div>
                </div>
              </div>

              {/* Voting Classifier Ensemble Architecture (Slide 5) */}
              <div className="threat-panel">
                <h3 style={{ fontSize: "1.1rem", marginBottom: 16 }}>Voting Classifier Ensemble Weights[cite: 1]</h3>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))", gap: 16 }}>
                  <div style={{ background: "rgba(3, 7, 18, 0.7)", padding: 18, borderRadius: 10, border: "1px solid var(--border-color)" }}>
                    <div style={{ color: "var(--brand-cyan)", fontWeight: 700, fontSize: "1.4rem" }}>40%[cite: 1]</div>
                    <div style={{ fontWeight: 700, marginTop: 4 }}>Random Forest[cite: 1]</div>
                    <div style={{ color: "var(--text-muted)", fontSize: "0.8rem", marginTop: 4 }}>100 decision estimators evaluating non-linear feature splits[cite: 1]</div>
                  </div>
                  <div style={{ background: "rgba(3, 7, 18, 0.7)", padding: 18, borderRadius: 10, border: "1px solid var(--border-color)" }}>
                    <div style={{ color: "#4facfe", fontWeight: 700, fontSize: "1.4rem" }}>35%[cite: 1]</div>
                    <div style={{ fontWeight: 700, marginTop: 4 }}>XGBoost[cite: 1]</div>
                    <div style={{ color: "var(--text-muted)", fontSize: "0.8rem", marginTop: 4 }}>Gradient-boosted decision trees for high-precision boundary learning[cite: 1]</div>
                  </div>
                  <div style={{ background: "rgba(3, 7, 18, 0.7)", padding: 18, borderRadius: 10, border: "1px solid var(--border-color)" }}>
                    <div style={{ color: "#8b5cf6", fontWeight: 700, fontSize: "1.4rem" }}>25%[cite: 1]</div>
                    <div style={{ fontWeight: 700, marginTop: 4 }}>Neural Network[cite: 1]</div>
                    <div style={{ color: "var(--text-muted)", fontSize: "0.8rem", marginTop: 4 }}>Multi-layer perceptron capturing latent lexical embeddings[cite: 1]</div>
                  </div>
                </div>

                <div style={{ marginTop: 20, padding: 16, background: "rgba(139, 92, 246, 0.1)", border: "1px solid rgba(139, 92, 246, 0.3)", borderRadius: 10 }}>
                  <strong style={{ color: "#c084fc" }}>Anomaly Detection Engine (Isolation Forest):</strong> Runs in parallel with ensemble classification to identify zero-day threats and novel attack patterns not seen in training data[cite: 1].
                </div>
              </div>
            </motion.div>
          )}

          {/* TAB 3: NEO4J GRAPH CORRELATION (SLIDE 3 & 4) */}
          {activeTab === "graph" && (
            <motion.div key="graph" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -10 }}>
              <div style={{ marginBottom: 20 }}>
                <h2 style={{ fontSize: "1.5rem", fontWeight: 800 }}>Neo4j Threat Knowledge Graph[cite: 1]</h2>
                <p style={{ color: "var(--text-secondary)", fontSize: "0.85rem" }}>
                  Links IOCs, actors, campaigns, and infrastructure in an interactive correlation topology[cite: 1]
                </p>
              </div>

              <div className="threat-panel" style={{ height: 620, padding: 0, overflow: "hidden", position: "relative" }}>
                <ForceGraph2D
                  graphData={graphData}
                  nodeLabel="id"
                  nodeColor={(n) => (n.group === "actor" ? "#ef4444" : n.group === "campaign" ? "#8b5cf6" : "#00f2fe")}
                  nodeRelSize={7}
                  linkColor={() => "rgba(255,255,255,0.2)"}
                  backgroundColor="transparent"
                />
              </div>
            </motion.div>
          )}

          {/* TAB 4: AUTO DETECTION RULE GENERATOR (SLIDE 3 & 4) */}
          {activeTab === "rules" && (
            <motion.div key="rules" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -10 }}>
              <div style={{ marginBottom: 20 }}>
                <h2 style={{ fontSize: "1.5rem", fontWeight: 800 }}>Auto Rule Generation[cite: 1]</h2>
                <p style={{ color: "var(--text-secondary)", fontSize: "0.85rem" }}>
                  Sigma, YARA, Suricata & Snort rules in seconds, not hours (30 sec vs 2 hours manually)[cite: 1]
                </p>
              </div>

              <div className="threat-panel">
                <div style={{ display: "flex", gap: 12, marginBottom: 18, flexWrap: "wrap" }}>
                  <input
                    type="text"
                    className="threat-input"
                    style={{ flex: 1, minWidth: 280 }}
                    value={ruleIoc}
                    onChange={(e) => setRuleIoc(e.target.value)}
                  />
                  <button className="btn-cyber-primary" onClick={handleGenerateRules}>
                    Generate Detection Rules[cite: 1]
                  </button>
                </div>

                {rules && (
                  <div>
                    <div style={{ display: "flex", gap: 10, borderBottom: "1px solid var(--border-color)", paddingBottom: 12, marginBottom: 16 }}>
                      {["sigma", "yara", "suricata", "snort"].map((fmt) => (
                        <button
                          key={fmt}
                          className={`nav-pill-btn ${selectedRuleFmt === fmt ? "active" : ""}`}
                          onClick={() => setSelectedRuleFmt(fmt)}
                        >
                          {fmt.toUpperCase()} RULE[cite: 1]
                        </button>
                      ))}
                    </div>
                    <pre style={{ background: "#030712", padding: 20, borderRadius: 8, color: "var(--brand-cyan)", fontFamily: "JetBrains Mono", overflowX: "auto", fontSize: "0.85rem" }}>
                      {rules[selectedRuleFmt]}
                    </pre>
                  </div>
                )}
              </div>
            </motion.div>
          )}

          {/* TAB 5: 6-SOURCE ENRICHMENT ENGINE (SLIDE 3 & 7) */}
          {activeTab === "enrich" && (
            <motion.div key="enrich" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -10 }}>
              <div style={{ marginBottom: 20 }}>
                <h2 style={{ fontSize: "1.5rem", fontWeight: 800 }}>6-Source Parallel Enrichment[cite: 1]</h2>
                <p style={{ color: "var(--text-secondary)", fontSize: "0.85rem" }}>
                  VirusTotal, AbuseIPDB, Shodan, AlienVault OTX, and Cortex Analyzers queried concurrently under 5 seconds[cite: 1]
                </p>
              </div>

              <div className="threat-panel">
                <div style={{ display: "flex", gap: 12, marginBottom: 20, flexWrap: "wrap" }}>
                  <input
                    type="text"
                    className="threat-input"
                    style={{ flex: 1, minWidth: 280 }}
                    value={enrichIoc}
                    onChange={(e) => setEnrichIoc(e.target.value)}
                  />
                  <button className="btn-cyber-primary" onClick={handleExecuteEnrichment} disabled={enriching}>
                    <Zap size={15} /> {enriching ? "Enriching in <5s..." : "Execute 6-Source Enrichment"}
                  </button>
                </div>

                {enrichment && (
                  <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))", gap: 16 }}>
                    {Object.entries(enrichment.sources).map(([src, d]) => (
                      <div key={src} style={{ background: "rgba(3, 7, 18, 0.75)", border: "1px solid var(--border-color)", padding: 18, borderRadius: 10 }}>
                        <div style={{ color: "var(--brand-cyan)", fontWeight: 700, marginBottom: 8 }}>{src.replace("_", " ")}[cite: 1]</div>
                        <pre style={{ fontSize: "0.78rem", color: "var(--text-secondary)", margin: 0, overflowX: "auto" }}>
                          {JSON.stringify(d, null, 2)}
                        </pre>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </motion.div>
          )}

          {/* TAB 6: SIEM / SOAR / EDR ONE-CLICK EXPORT (SLIDE 3 & 7) */}
          {activeTab === "siem" && (
            <motion.div key="siem" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -10 }}>
              <div style={{ marginBottom: 20 }}>
                <h2 style={{ fontSize: "1.5rem", fontWeight: 800 }}>SIEM / SOAR / EDR Integrations[cite: 1]</h2>
                <p style={{ color: "var(--text-secondary)", fontSize: "0.85rem" }}>
                  Plug into your existing security stack with one-click export (No rip-and-replace)[cite: 1]
                </p>
              </div>

              <div className="threat-panel">
                <div style={{ display: "flex", gap: 10, marginBottom: 20, flexWrap: "wrap" }}>
                  {[
                    { id: "splunk", label: "Splunk (SPL)[cite: 1]" },
                    { id: "sentinel", label: "Microsoft Sentinel (KQL)[cite: 1]" },
                    { id: "qradar", label: "IBM QRadar (AQL)[cite: 1]" },
                    { id: "crowdstrike", label: "CrowdStrike Falcon (CSV)[cite: 1]" },
                    { id: "stix", label: "STIX / TAXII 2.1[cite: 1]" },
                  ].map((p) => (
                    <button
                      key={p.id}
                      className={`nav-pill-btn ${selectedSiem === p.id ? "active" : ""}`}
                      onClick={() => handleExportSiem(p.id)}
                    >
                      {p.label}
                    </button>
                  ))}
                </div>

                {exportData && (
                  <div>
                    <h4 style={{ color: "var(--brand-cyan)", marginBottom: 10 }}>Generated Artifact for {exportData.platform}[cite: 1]</h4>
                    <pre style={{ background: "#030712", padding: 20, borderRadius: 8, color: "#fff", fontFamily: "JetBrains Mono", fontSize: "0.85rem", overflowX: "auto" }}>
                      {exportData.export_query || exportData.payload || JSON.stringify(exportData, null, 2)}
                    </pre>
                  </div>
                )}
              </div>
            </motion.div>
          )}

          {/* TAB 7: QUANTIFIABLE BUSINESS IMPACT & ROI (SLIDE 6) */}
          {activeTab === "impact" && (
            <motion.div key="impact" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -10 }}>
              <div style={{ marginBottom: 20 }}>
                <h2 style={{ fontSize: "1.5rem", fontWeight: 800 }}>Business Impact & ROI Metrics[cite: 1]</h2>
                <p style={{ color: "var(--text-secondary)", fontSize: "0.85rem" }}>
                  Quantifiable improvements across every key SOC metric[cite: 1]
                </p>
              </div>

              {/* Exact Slide 6 Table */}
              <div className="threat-panel" style={{ padding: 0, overflow: "hidden", marginBottom: 24 }}>
                <table className="threat-table">
                  <thead>
                    <tr>
                      <th>Metric[cite: 1]</th>
                      <th>Before ThreatOps[cite: 1]</th>
                      <th>After ThreatOps[cite: 1]</th>
                      <th>Improvement[cite: 1]</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr>
                      <td style={{ fontWeight: 600 }}>Time to Analyze IOC[cite: 1]</td>
                      <td>30 min[cite: 1]</td>
                      <td>5 sec[cite: 1]</td>
                      <td><span className="badge-critical" style={{ background: "rgba(16, 185, 129, 0.2)", color: "#34d399", borderColor: "#10b981" }}>99.7%[cite: 1]</span></td>
                    </tr>
                    <tr>
                      <td style={{ fontWeight: 600 }}>False Positive Rate[cite: 1]</td>
                      <td>40%[cite: 1]</td>
                      <td>1.8%[cite: 1]</td>
                      <td><span className="badge-critical" style={{ background: "rgba(16, 185, 129, 0.2)", color: "#34d399", borderColor: "#10b981" }}>95.5%[cite: 1]</span></td>
                    </tr>
                    <tr>
                      <td style={{ fontWeight: 600 }}>IOCs Processed / Analyst[cite: 1]</td>
                      <td>100 / day[cite: 1]</td>
                      <td>1,000+[cite: 1]</td>
                      <td><span className="badge-critical" style={{ background: "rgba(16, 185, 129, 0.2)", color: "#34d399", borderColor: "#10b981" }}>10×[cite: 1]</span></td>
                    </tr>
                    <tr>
                      <td style={{ fontWeight: 600 }}>Detection Rule Creation[cite: 1]</td>
                      <td>2 hours[cite: 1]</td>
                      <td>30 sec[cite: 1]</td>
                      <td><span className="badge-critical" style={{ background: "rgba(16, 185, 129, 0.2)", color: "#34d399", borderColor: "#10b981" }}>99.6%[cite: 1]</span></td>
                    </tr>
                    <tr>
                      <td style={{ fontWeight: 600 }}>Mean Time to Detect (MTTD)[cite: 1]</td>
                      <td>24 hours[cite: 1]</td>
                      <td>5 min[cite: 1]</td>
                      <td><span className="badge-critical" style={{ background: "rgba(16, 185, 129, 0.2)", color: "#34d399", borderColor: "#10b981" }}>99.7%[cite: 1]</span></td>
                    </tr>
                  </tbody>
                </table>
              </div>

              {/* Exact Slide 6 Callout Banner */}
              <div style={{ background: "linear-gradient(135deg, rgba(16, 185, 129, 0.15) 0%, rgba(0, 242, 254, 0.15) 100%)", border: "1px solid rgba(16, 185, 129, 0.4)", borderRadius: 12, padding: 22, display: "flex", justifyContent: "space-around", flexWrap: "wrap", gap: 16 }}>
                <div>💰 <strong>Estimated ROI:</strong> <span style={{ color: "#34d399", fontWeight: 800 }}>600%[cite: 1]</span></div>
                <div>💵 <strong>Net Annual Savings:</strong> <span style={{ color: "#34d399", fontWeight: 800 }}>$300K (5-analyst SOC)[cite: 1]</span></div>
                <div>⏱ <strong>Payback Period:</strong> <span style={{ color: "#00f2fe", fontWeight: 800 }}>4-month[cite: 1]</span></div>
              </div>
            </motion.div>
          )}

        </AnimatePresence>
      </main>
    </div>
  );
}