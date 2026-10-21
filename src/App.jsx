import React, { useState, useEffect, useCallback } from "react";
import ForceGraph2D from "react-force-graph-2d";
import {
  Activity,
  Cpu,
  Network,
  FileCode,
  Share2,
  TrendingUp,
  RefreshCw,
  CheckCircle2,
  AlertTriangle,
  Zap,
  Terminal,
  ArrowLeft,
  X,
  FileText,
} from "lucide-react";

const API_BASE = "/api/v1";
const VIDEO_URL =
  "https://d8j0ntlcm91z4.cloudfront.net/user_38xzZboKViGWJOttwIXH07lWA1P/hf_20260808_112712_da9d53df-6d27-4b12-bdf6-aa9dc2622bdf.mp4";

function BrandMarkSvg({ idSuffix = "" }) {
  const gradId = `bg1${idSuffix}`;
  return (
    <svg viewBox="0 0 31.5 48.5" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
      <defs>
        <linearGradient id={gradId} x1="8" y1="0" x2="34.1" y2="28.9" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#9e9e9e" />
          <stop offset="0.28" stopColor="#a6a6a6" />
          <stop offset="0.34" stopColor="#a3a3a3" />
          <stop offset="0.40" stopColor="#3a3a3a" />
          <stop offset="0.55" stopColor="#414141" />
          <stop offset="0.60" stopColor="#7a7a7a" />
          <stop offset="0.68" stopColor="#8e8e8e" />
          <stop offset="0.80" stopColor="#a9a9a9" />
          <stop offset="0.95" stopColor="#c4c4c4" />
          <stop offset="1" stopColor="#cccccc" />
        </linearGradient>
      </defs>
      <path
        d="M21.5 0 L21.5 19.5 L31.5 19.5 L31.5 29 L10 48.5 L10 28.5 L0.5 28.5 L0.5 18.5 Z"
        fill={`url(#${gradId})`}
      />
      <rect x="0.5" y="18.5" width="9" height="10" fill="#fdfdfd" />
      <rect x="22" y="19.5" width="9.5" height="9.5" fill="#fdfdfd" />
    </svg>
  );
}

export default function App() {
  // Stage vs Console state
  const [viewMode, setViewMode] = useState("stage"); // "stage" | "console"
  const [menuOpen, setMenuOpen] = useState(false);
  const [stageDrawer, setStageDrawer] = useState(null); // null | "about" | "features" | "faq" | "contact"

  // Auth & Console state
  const [token, setToken] = useState(localStorage.getItem("threatops_token") || "");
  const [user, setUser] = useState(null);
  const [activeTab, setActiveTab] = useState("pipeline"); // pipeline, ensemble, graph, rules, enrich, siem, impact

  // Live IOC feed & metrics state
  const [iocs, setIocs] = useState([]);
  const [filterType, setFilterType] = useState("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [refreshing, setRefreshing] = useState(false);

  // Scanner state
  const [scanIoc, setScanIoc] = useState("http://194.55.186.21:54321/Mozi.a");
  const [scanResult, setScanResult] = useState(null);
  const [scanning, setScanning] = useState(false);

  // NLP Report Extractor state
  const [reportText, setReportText] = useState(
    "Adversaries exploited CVE-2024-3400 using a spearphishing lure to deploy a second-stage dropper via powershell. The script executed wget against hxxp://185.220.101[.]45:8080/bin.sh and established a Cobalt Strike C2 beacon to 91.215.85[.]142."
  );
  const [reportResult, setReportResult] = useState(null);
  const [extractingReport, setExtractingReport] = useState(false);

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

  // Custom Org Log Ingestion (in Contact drawer)
  const [orgName, setOrgName] = useState("Sentinel-Core-SOC");
  const [orgLogs, setOrgLogs] = useState(
    "2026-10-20T14:22:01Z DENY TCP 10.0.4.15 -> 185.220.101.45:3389\n2026-10-20T14:22:09Z ALERT GET http://115.55.236.110:45921/Mozi.m"
  );
  const [orgIngestStatus, setOrgIngestStatus] = useState(null);

  // Toggle body overflow class when switching between locked stage and scrollable console
  useEffect(() => {
    if (viewMode === "console") {
      document.body.classList.add("console-active");
    } else {
      document.body.classList.remove("console-active");
    }
  }, [viewMode]);

  // Escape & resize > 1.1 aspect listeners for Stage menu & drawers
  useEffect(() => {
    const onKeyDown = (e) => {
      if (e.key === "Escape") {
        setMenuOpen(false);
        setStageDrawer(null);
      }
    };
    const onResize = () => {
      if (window.innerWidth / Math.max(window.innerHeight, 1) > 1.1) {
        setMenuOpen(false);
      }
    };
    window.addEventListener("keydown", onKeyDown);
    window.addEventListener("resize", onResize);
    return () => {
      window.removeEventListener("keydown", onKeyDown);
      window.removeEventListener("resize", onResize);
    };
  }, []);

  const loadDashboardData = useCallback(async (typeFilter = filterType, query = searchQuery) => {
    try {
      const params = new URLSearchParams({ limit: "40" });
      if (typeFilter && typeFilter !== "all") params.set("ioc_type", typeFilter);
      if (query && query.trim()) params.set("search", query.trim());
      const res = await fetch(`${API_BASE}/iocs?${params.toString()}`);
      if (res.ok) setIocs(await res.json());
    } catch (e) {
      console.warn("Could not load IOCs:", e);
    }
  }, [filterType, searchQuery]);

  // Bootstrap session if token exists
  useEffect(() => {
    if (token) {
      fetch(`${API_BASE}/auth/me`, {
        headers: { Authorization: `Bearer ${token}` },
      })
        .then((res) => (res.ok ? res.json() : Promise.reject()))
        .then((data) => {
          setUser(data);
          loadDashboardData();
        })
        .catch(() => {
          setToken("");
          localStorage.removeItem("threatops_token");
        });
    }
  }, [token, loadDashboardData]);

  const enterThreatOpsConsole = async (targetTab = "pipeline") => {
    setMenuOpen(false);
    setStageDrawer(null);
    setActiveTab(targetTab);

    if (!token || !user) {
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
        }
      } catch (err) {
        console.error("SSO authentication error:", err);
      }
    }

    await loadDashboardData();
    if (targetTab === "graph") handleFetchGraph();
    if (targetTab === "rules") handleGenerateRules();
    if (targetTab === "enrich") handleExecuteEnrichment();
    if (targetTab === "siem") handleExportSiem("splunk");
    setViewMode("console");
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

  const handleExtractReport = async () => {
    setExtractingReport(true);
    try {
      const res = await fetch(`${API_BASE}/extract/report`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text: reportText }),
      });
      if (res.ok) setReportResult(await res.json());
    } finally {
      setExtractingReport(false);
    }
  };

  const handleRefreshFeeds = async () => {
    setRefreshing(true);
    try {
      await fetch(`${API_BASE}/feeds/refresh`, { method: "POST" });
      await loadDashboardData();
    } finally {
      setRefreshing(false);
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

  const handleIngestOrgFeed = async (e) => {
    e.preventDefault();
    const lines = orgLogs
      .split("\n")
      .map((l) => l.trim())
      .filter(Boolean);
    const res = await fetch(`${API_BASE}/org/ingest-feed`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        organization_name: orgName,
        log_type: "firewall",
        raw_logs: lines,
      }),
    });
    if (res.ok) {
      setOrgIngestStatus(await res.json());
      loadDashboardData();
    }
  };

  const openNavDrawer = (e, section) => {
    e.preventDefault();
    setMenuOpen(false);
    setStageDrawer(section);
  };

  // ════════════════════════════════════════════════════════════════════════
  // VIEW 1: PIXEL-FAITHFUL DARK CINEMATIC LANDING STAGE (1487 × 1058 SPEC)
  // ════════════════════════════════════════════════════════════════════════
  if (viewMode === "stage") {
    return (
      <div className={`stage${menuOpen ? " is-open" : ""}`}>
        {/* Full-bleed CloudFront looping video plate */}
        <div className="plate">
          <video
            className="plate-video"
            autoPlay
            muted
            loop
            playsInline
            preload="auto"
            aria-hidden="true"
          >
            <source src={VIDEO_URL} type="video/mp4" />
          </video>
        </div>

        {/* Topbar: Brand SVG + Centered Primary Links + White Pill CTA + Mobile Burger */}
        <header className="topbar">
          <a
            href="#top"
            className="brand"
            aria-label="Home"
            onClick={(e) => {
              e.preventDefault();
              setMenuOpen(false);
              setStageDrawer(null);
            }}
          >
            <BrandMarkSvg />
          </a>

          <nav className="links" aria-label="Primary">
            <a href="#about" onClick={(e) => openNavDrawer(e, "about")}>
              About
            </a>
            <a href="#features" onClick={(e) => openNavDrawer(e, "features")}>
              Features
            </a>
            <a href="#faq" onClick={(e) => openNavDrawer(e, "faq")}>
              FAQ
            </a>
            <a href="#contact" onClick={(e) => openNavDrawer(e, "contact")}>
              Contact
            </a>
          </nav>

          <a
            href="#console"
            className="pill pill-nav"
            onClick={(e) => {
              e.preventDefault();
              enterThreatOpsConsole("pipeline");
            }}
          >
            <span>Get Started</span>
          </a>

          <button
            type="button"
            className="burger"
            id="burger"
            aria-label={menuOpen ? "Close menu" : "Open menu"}
            aria-expanded={menuOpen}
            aria-controls="menu"
            onClick={() => setMenuOpen((prev) => !prev)}
          >
            <i />
            <i />
          </button>
        </header>

        {/* Mobile Overlay Menu */}
        <nav className="menu" id="menu" aria-hidden={!menuOpen}>
          <div className="menu-inner">
            <p className="menu-eyebrow">Menu</p>
            <ul className="menu-list">
              <li>
                <a href="#about" onClick={(e) => openNavDrawer(e, "about")}>
                  About
                </a>
              </li>
              <li>
                <a href="#features" onClick={(e) => openNavDrawer(e, "features")}>
                  Features
                </a>
              </li>
              <li>
                <a href="#faq" onClick={(e) => openNavDrawer(e, "faq")}>
                  FAQ
                </a>
              </li>
              <li>
                <a href="#contact" onClick={(e) => openNavDrawer(e, "contact")}>
                  Contact
                </a>
              </li>
            </ul>
            <div className="menu-foot">
              <a
                href="#console"
                className="pill"
                onClick={(e) => {
                  e.preventDefault();
                  enterThreatOpsConsole("pipeline");
                }}
              >
                <span>Get Started</span>
              </a>
              <a
                href="#architecture"
                className="ghost"
                onClick={(e) => {
                  e.preventDefault();
                  enterThreatOpsConsole("ensemble");
                }}
              >
                View Architecture
              </a>
            </div>
          </div>
        </nav>

        {/* Hero Typography & Dual Actions */}
        <main className="hero">
          <h1 className="headline">
            <span>The Next Layer</span>
            <span>of Intelligence</span>
          </h1>
          <p className="sub">
            <span>A unified infrastructure platform to help teams build,</span>
            <span>ship, and scale AI systems with confidence.</span>
          </p>
          <div className="actions">
            <a
              href="#console"
              className="pill pill-cta"
              onClick={(e) => {
                e.preventDefault();
                enterThreatOpsConsole("pipeline");
              }}
            >
              <span>Get Started</span>
            </a>
            <a
              href="#architecture"
              className="ghost"
              onClick={(e) => {
                e.preventDefault();
                enterThreatOpsConsole("ensemble");
              }}
            >
              View Architecture
            </a>
          </div>
        </main>

        {/* Four Partner Logo Marks sitting in the bottom fade */}
        <div className="logos" aria-label="Partner ecosystems">
          {/* lg1: 30.5 x 31 — square frame with circular bite + circle path */}
          <div className="lg lg1">
            <svg viewBox="0 0 30 31" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
              <defs>
                <mask id="lg1-bite">
                  <rect width="30" height="31" fill="white" />
                  <circle cx="19.5" cy="10.5" r="5.1" fill="black" />
                </mask>
              </defs>
              <rect
                x="2"
                y="2.5"
                width="26"
                height="26"
                rx="5"
                fill="currentColor"
                mask="url(#lg1-bite)"
              />
              <circle cx="19.5" cy="10.5" r="2.4" fill="#050505" />
            </svg>
            <span className="word">logoipsum</span>
          </div>

          {/* lg2: 24.5 x 30 — vertical bar + circle yin-yang mask split + raised dot */}
          <div className="lg lg2">
            <svg viewBox="0 0 25 30" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
              <rect x="0.5" y="2" width="5.2" height="26" rx="2.6" fill="currentColor" />
              <path
                d="M15 4.5C20.2467 4.5 24.5 8.97715 24.5 14.5C24.5 20.0228 20.2467 24.5 15 24.5C9.75329 24.5 5.5 20.0228 5.5 14.5C5.5 8.97715 9.75329 4.5 15 4.5ZM15 8.8C11.9624 8.8 9.5 11.352 9.5 14.5C9.5 17.648 11.9624 20.2 15 20.2V8.8Z"
                fill="currentColor"
              />
            </svg>
            <span className="word">
              logoipsum<span className="dot" />
            </span>
          </div>

          {/* lg3: 28.5 x 28 — circle stroke r12.35 sw 3.1 + two curved swirl paths */}
          <div className="lg lg3">
            <svg viewBox="0 0 28 28" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
              <circle cx="14" cy="14" r="12.35" stroke="currentColor" strokeWidth="3.1" />
              <path
                d="M5.5 17.5C9.5 11.5 15.5 10.5 22.5 14.5"
                stroke="currentColor"
                strokeWidth="3.1"
                strokeLinecap="round"
              />
              <path
                d="M7.5 22C12 16.8 17 16.2 21.8 19.2"
                stroke="currentColor"
                strokeWidth="2.8"
                strokeLinecap="round"
              />
            </svg>
            <span className="word">logoipsum</span>
          </div>

          {/* lg4: 28.5 x 25.5 — filled wavy mound path + two stroked wave lines beneath */}
          <div className="lg lg4">
            <svg viewBox="0 0 28 25.5" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
              <path
                d="M2 13.2C5.2 13.2 7.4 3.5 14 3.5C20.6 3.5 22.8 13.2 26 13.2H2Z"
                fill="currentColor"
              />
              <path
                d="M2 18.2C6.5 18.2 9.5 15.8 14 15.8C18.5 15.8 21.5 18.2 26 18.2"
                stroke="currentColor"
                strokeWidth="3.05"
                strokeLinecap="round"
              />
              <path
                d="M4.5 23.2C8.2 23.2 10.6 21.2 14 21.2C17.4 21.2 19.8 23.2 23.5 23.2"
                stroke="currentColor"
                strokeWidth="3.05"
                strokeLinecap="round"
              />
            </svg>
            <span className="word">logoipsum</span>
          </div>
        </div>

        {/* ThreatOps Platform Overlay Drawer for Header Links (About, Features, FAQ, Contact) */}
        {stageDrawer && (
          <div
            className="stage-drawer-backdrop"
            onClick={() => setStageDrawer(null)}
            role="dialog"
            aria-modal="true"
          >
            <div className="stage-drawer" onClick={(e) => e.stopPropagation()}>
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  marginBottom: 20,
                  paddingBottom: 16,
                  borderBottom: "1px solid rgba(255,255,255,0.1)",
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                  <div style={{ width: 20, height: 30 }}>
                    <BrandMarkSvg idSuffix="-drawer" />
                  </div>
                  <span style={{ fontSize: "1.1rem", fontWeight: 600 }}>
                    ThreatOps ·{" "}
                    {stageDrawer === "about"
                      ? "Platform Overview"
                      : stageDrawer === "features"
                      ? "Core Capabilities"
                      : stageDrawer === "faq"
                      ? "Architecture FAQ"
                      : "Enterprise Telemetry & Contact"}
                  </span>
                </div>
                <button
                  type="button"
                  className="console-btn-ghost"
                  style={{ padding: "6px 10px" }}
                  onClick={() => setStageDrawer(null)}
                  aria-label="Close modal"
                >
                  <X size={16} />
                </button>
              </div>

              {stageDrawer === "about" && (
                <div>
                  <h3 style={{ fontSize: "1.5rem", fontWeight: 500, marginBottom: 12 }}>
                    Autonomous 13-Second Threat Intelligence Infrastructure
                  </h3>
                  <p style={{ color: "var(--muted)", lineHeight: 1.6, marginBottom: 20 }}>
                    ThreatOps unifies live OSINT ingestion (Abuse.ch URLHaus, FeodoTracker, AlienVault OTX),
                    6-source parallel enrichment, a 96.2% precision Voting Classifier ensemble (Random Forest,
                    XGBoost, and Multi-Layer Perceptron) paired with an unsupervised Isolation Forest anomaly
                    detector, and Neo4j graph correlation into a single 13-second automated pipeline.
                  </p>
                  <div
                    style={{
                      display: "grid",
                      gridTemplateColumns: "repeat(3, 1fr)",
                      gap: 12,
                      marginBottom: 24,
                    }}
                  >
                    <div className="console-kpi-card">
                      <div style={{ fontSize: "0.78rem", color: "var(--muted)" }}>Ensemble Precision</div>
                      <div className="mono-num" style={{ fontSize: "1.6rem", fontWeight: 700, marginTop: 4 }}>
                        96.2%
                      </div>
                    </div>
                    <div className="console-kpi-card">
                      <div style={{ fontSize: "0.78rem", color: "var(--muted)" }}>Mean Triage Latency</div>
                      <div className="mono-num" style={{ fontSize: "1.6rem", fontWeight: 700, marginTop: 4 }}>
                        &lt; 13s
                      </div>
                    </div>
                    <div className="console-kpi-card">
                      <div style={{ fontSize: "0.78rem", color: "var(--muted)" }}>False Positive Rate</div>
                      <div className="mono-num" style={{ fontSize: "1.6rem", fontWeight: 700, marginTop: 4 }}>
                        1.8%
                      </div>
                    </div>
                  </div>
                  <div style={{ display: "flex", gap: 12 }}>
                    <button
                      type="button"
                      className="console-btn-pill"
                      onClick={() => enterThreatOpsConsole("pipeline")}
                    >
                      Launch Live ThreatOps Console
                    </button>
                    <button
                      type="button"
                      className="console-btn-ghost"
                      onClick={() => enterThreatOpsConsole("impact")}
                    >
                      View SOC ROI Benchmarks
                    </button>
                  </div>
                </div>
              )}

              {stageDrawer === "features" && (
                <div>
                  <p style={{ color: "var(--muted)", marginBottom: 18 }}>
                    Select any ThreatOps engine below to open the live interactive workspace:
                  </p>
                  <div
                    style={{
                      display: "grid",
                      gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))",
                      gap: 12,
                      marginBottom: 22,
                    }}
                  >
                    {[
                      {
                        id: "pipeline",
                        title: "01. 13-Second IOC Triage",
                        desc: "Real-time feature extraction, live OSINT feed correlation, and explainable risk scoring.",
                      },
                      {
                        id: "ensemble",
                        title: "02. 96.2% ML Ensemble + NLP",
                        desc: "40% Random Forest, 35% XGBoost, 25% Neural Net + MITRE ATT&CK advisory extractor.",
                      },
                      {
                        id: "graph",
                        title: "03. Neo4j Threat Graph",
                        desc: "Interactive 2D force-directed topology linking APT campaigns, actors, and IOCs.",
                      },
                      {
                        id: "rules",
                        title: "04. Auto Rule Generator",
                        desc: "Instant Sigma, YARA, Suricata, and Snort detection signatures in under 30 seconds.",
                      },
                      {
                        id: "enrich",
                        title: "05. 6-Source Parallel Enricher",
                        desc: "Concurrent VirusTotal, AbuseIPDB, Shodan, and AlienVault OTX reputation telemetry.",
                      },
                      {
                        id: "siem",
                        title: "06. SIEM / SOAR / EDR Export",
                        desc: "One-click Splunk SPL, Sentinel KQL, QRadar AQL, CrowdStrike CSV, and STIX 2.1 bundles.",
                      },
                    ].map((f) => (
                      <div
                        key={f.id}
                        className="console-kpi-card"
                        style={{ cursor: "pointer" }}
                        onClick={() => enterThreatOpsConsole(f.id)}
                      >
                        <div style={{ fontWeight: 600, marginBottom: 6 }}>{f.title}</div>
                        <div style={{ fontSize: "0.82rem", color: "var(--muted)", lineHeight: 1.45 }}>
                          {f.desc}
                        </div>
                      </div>
                    ))}
                  </div>
                  <button
                    type="button"
                    className="console-btn-pill"
                    onClick={() => enterThreatOpsConsole("pipeline")}
                  >
                    Open Full Console
                  </button>
                </div>
              )}

              {stageDrawer === "faq" && (
                <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
                  <div>
                    <div style={{ fontWeight: 600, marginBottom: 4 }}>
                      How does the 96.2% ML Ensemble avoid alert fatigue?
                    </div>
                    <p style={{ fontSize: "0.86rem", color: "var(--muted)", lineHeight: 1.5 }}>
                      Each indicator is decomposed into 14 structural and lexical features (Shannon entropy,
                      digit ratio, raw IPv4 host detection, non-standard port usage, TLD abuse reputation,
                      and payload keywords) and evaluated by a soft-voting ensemble combined with an
                      Isolation Forest zero-day detector, reducing false positives from 40% to 1.8%.
                    </p>
                  </div>
                  <div>
                    <div style={{ fontWeight: 600, marginBottom: 4 }}>
                      Which SIEM and EDR platforms are supported out of the box?
                    </div>
                    <p style={{ fontSize: "0.86rem", color: "var(--muted)", lineHeight: 1.5 }}>
                      ThreatOps generates native queries and blocklists for Splunk (SPL), Microsoft Sentinel
                      (KQL), IBM QRadar (AQL), CrowdStrike Falcon (CSV), and STIX/TAXII 2.1 JSON bundles, plus
                      Sigma, YARA, Suricata, and Snort rules.
                    </p>
                  </div>
                  <div style={{ marginTop: 8 }}>
                    <button
                      type="button"
                      className="console-btn-pill"
                      onClick={() => enterThreatOpsConsole("rules")}
                    >
                      Test Live Rule Generator
                    </button>
                  </div>
                </div>
              )}

              {stageDrawer === "contact" && (
                <form onSubmit={handleIngestOrgFeed}>
                  <p style={{ color: "var(--muted)", fontSize: "0.88rem", marginBottom: 16 }}>
                    Stream raw firewall or EDR telemetry lines directly into the ThreatOps ingestion pipeline
                    to isolate high-risk indicators:
                  </p>
                  <div style={{ marginBottom: 12 }}>
                    <label style={{ display: "block", fontSize: "0.8rem", color: "var(--muted)", marginBottom: 6 }}>
                      Organization Identifier
                    </label>
                    <input
                      type="text"
                      className="console-input"
                      style={{ width: "100%", borderRadius: 10 }}
                      value={orgName}
                      onChange={(e) => setOrgName(e.target.value)}
                    />
                  </div>
                  <div style={{ marginBottom: 16 }}>
                    <label style={{ display: "block", fontSize: "0.8rem", color: "var(--muted)", marginBottom: 6 }}>
                      Raw Telemetry Batch
                    </label>
                    <textarea
                      rows={4}
                      className="console-input mono-num"
                      style={{ width: "100%", borderRadius: 10 }}
                      value={orgLogs}
                      onChange={(e) => setOrgLogs(e.target.value)}
                    />
                  </div>
                  {orgIngestStatus && (
                    <div
                      style={{
                        padding: 12,
                        borderRadius: 10,
                        background: "rgba(255,255,255,0.05)",
                        border: "1px solid rgba(255,255,255,0.14)",
                        fontSize: "0.84rem",
                        marginBottom: 16,
                      }}
                    >
                      Parsed <strong>{orgIngestStatus.indicators_parsed}</strong> candidate tokens · Isolated{" "}
                      <strong>{orgIngestStatus.critical_threats_isolated}</strong> new high-risk threats.
                    </div>
                  )}
                  <div style={{ display: "flex", gap: 12 }}>
                    <button type="submit" className="console-btn-pill">
                      Ingest Telemetry Batch
                    </button>
                    <button
                      type="button"
                      className="console-btn-ghost"
                      onClick={() => enterThreatOpsConsole("pipeline")}
                    >
                      Open Live Feed Table
                    </button>
                  </div>
                </form>
              )}
            </div>
          </div>
        )}
      </div>
    );
  }

  // ════════════════════════════════════════════════════════════════════════
  // VIEW 2: THREATOPS ENTERPRISE CONSOLE (DARK MONOCHROME VOID EDITION)
  // ════════════════════════════════════════════════════════════════════════
  return (
    <div className="console-shell">
      <header className="console-topbar">
        <button
          type="button"
          className="console-brand-group"
          onClick={() => setViewMode("stage")}
          title="Return to Landing Stage"
        >
          <div style={{ width: 22, height: 34 }}>
            <BrandMarkSvg idSuffix="-console" />
          </div>
          <span style={{ fontSize: "1.15rem", fontWeight: 600, letterSpacing: "-0.02em" }}>
            ThreatOps
          </span>
        </button>

        <nav className="console-nav" aria-label="ThreatOps Modules">
          <button
            type="button"
            className={`console-tab ${activeTab === "pipeline" ? "active" : ""}`}
            onClick={() => setActiveTab("pipeline")}
          >
            <Activity size={14} /> 13s Pipeline
          </button>
          <button
            type="button"
            className={`console-tab ${activeTab === "ensemble" ? "active" : ""}`}
            onClick={() => setActiveTab("ensemble")}
          >
            <Cpu size={14} /> 96.2% ML Engine
          </button>
          <button
            type="button"
            className={`console-tab ${activeTab === "graph" ? "active" : ""}`}
            onClick={() => {
              setActiveTab("graph");
              handleFetchGraph();
            }}
          >
            <Network size={14} /> Neo4j Graph
          </button>
          <button
            type="button"
            className={`console-tab ${activeTab === "rules" ? "active" : ""}`}
            onClick={() => {
              setActiveTab("rules");
              handleGenerateRules();
            }}
          >
            <FileCode size={14} /> Detection Rules
          </button>
          <button
            type="button"
            className={`console-tab ${activeTab === "enrich" ? "active" : ""}`}
            onClick={() => {
              setActiveTab("enrich");
              handleExecuteEnrichment();
            }}
          >
            <Zap size={14} /> 6-Source Enricher
          </button>
          <button
            type="button"
            className={`console-tab ${activeTab === "siem" ? "active" : ""}`}
            onClick={() => {
              setActiveTab("siem");
              handleExportSiem("splunk");
            }}
          >
            <Share2 size={14} /> SIEM / SOAR
          </button>
          <button
            type="button"
            className={`console-tab ${activeTab === "impact" ? "active" : ""}`}
            onClick={() => setActiveTab("impact")}
          >
            <TrendingUp size={14} /> ROI & Pricing
          </button>
        </nav>

        <button
          type="button"
          className="console-btn-ghost"
          onClick={() => setViewMode("stage")}
        >
          <ArrowLeft size={14} /> Stage
        </button>
      </header>

      <main className="console-main">
        {/* TAB 1: 13-SECOND TRIAGE PIPELINE */}
        {activeTab === "pipeline" && (
          <div>
            <div style={{ marginBottom: 28 }}>
              <h1 style={{ fontSize: "2rem", fontWeight: 400, letterSpacing: "-0.01em" }}>
                13-Second Autonomous Triage Pipeline
              </h1>
              <p style={{ color: "var(--muted)", fontSize: "0.95rem", marginTop: 6 }}>
                From raw OSINT or telemetry indicator to actionable detection in under 13 seconds · 96.2% ML
                precision · &lt;1.8% false positives
              </p>
            </div>

            <div
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(auto-fit, minmax(195px, 1fr))",
                gap: 14,
                marginBottom: 24,
              }}
            >
              {[
                { step: "01. Ingest", desc: "OSINT + Commercial Feeds" },
                { step: "02. Enrich", desc: "6 Parallel Analyzers (<5s)" },
                { step: "03. Classify", desc: "ML Ensemble (RF/XGB/NN)" },
                { step: "04. Correlate", desc: "Neo4j Graph Engine" },
                { step: "05. Detect", desc: "Auto Rule Generation (<30s)" },
                { step: "06. Deploy", desc: "SIEM / EDR / SOAR Push" },
              ].map((s) => (
                <div key={s.step} className="console-kpi-card">
                  <div style={{ fontWeight: 600, fontSize: "0.96rem" }}>{s.step}</div>
                  <div style={{ fontSize: "0.82rem", color: "var(--muted)", marginTop: 6 }}>{s.desc}</div>
                </div>
              ))}
            </div>

            {/* Real-Time Indicator Scanner */}
            <div className="console-surface">
              <h2 style={{ fontSize: "1.15rem", fontWeight: 500, marginBottom: 14 }}>
                Live Indicator Inspection
              </h2>
              <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginBottom: 16 }}>
                <input
                  type="text"
                  className="console-input"
                  style={{ flex: 1, minWidth: 280 }}
                  value={scanIoc}
                  onChange={(e) => setScanIoc(e.target.value)}
                  placeholder="Enter URL, Domain, or IPv4 indicator..."
                />
                <button
                  type="button"
                  className="console-btn-pill"
                  onClick={handleScanIndicator}
                  disabled={scanning}
                >
                  <Terminal size={15} /> {scanning ? "Analyzing..." : "Analyze Indicator"}
                </button>
              </div>

              {scanResult && (
                <div
                  style={{
                    background: "#050505",
                    border: "1px solid rgba(255,255,255,0.12)",
                    borderRadius: 12,
                    padding: 20,
                  }}
                >
                  <div
                    style={{
                      display: "flex",
                      justifyContent: "space-between",
                      alignItems: "center",
                      flexWrap: "wrap",
                      gap: 12,
                      marginBottom: 12,
                    }}
                  >
                    <div>
                      <div style={{ fontSize: "0.75rem", color: "var(--muted)" }}>VERDICT</div>
                      <div className="mono-num" style={{ fontSize: "1.3rem", fontWeight: 700, marginTop: 2 }}>
                        {scanResult.verdict} · {scanResult.risk_score}/100
                      </div>
                    </div>
                    <div className="mono-num" style={{ color: "var(--muted)", fontSize: "0.85rem" }}>
                      P(Malicious): {(scanResult.ml_malicious_probability * 100).toFixed(1)}%
                      {scanResult.is_anomaly ? " · Isolation Forest Outlier" : ""}
                    </div>
                  </div>
                  <div style={{ fontSize: "0.88rem", color: "var(--muted)" }}>
                    <strong style={{ color: "var(--ink)" }}>Explainable Risk Drivers:</strong>{" "}
                    {scanResult.reasons.join(" · ")}
                  </div>
                </div>
              )}
            </div>

            {/* Active OSINT Threat Feed Table */}
            <div className="console-surface">
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  marginBottom: 18,
                  flexWrap: "wrap",
                  gap: 12,
                }}
              >
                <div>
                  <h2 style={{ fontSize: "1.15rem", fontWeight: 500 }}>
                    Active OSINT Threat Feed ({iocs.length} Indicators)
                  </h2>
                </div>
                <div style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "center" }}>
                  <input
                    type="text"
                    className="console-input"
                    style={{ padding: "8px 14px", fontSize: "0.84rem" }}
                    placeholder="Filter indicator..."
                    value={searchQuery}
                    onChange={(e) => {
                      setSearchQuery(e.target.value);
                      loadDashboardData(filterType, e.target.value);
                    }}
                  />
                  {["all", "url", "ipv4", "domain"].map((t) => (
                    <button
                      key={t}
                      type="button"
                      className={`console-tab ${filterType === t ? "active" : ""}`}
                      onClick={() => {
                        setFilterType(t);
                        loadDashboardData(t, searchQuery);
                      }}
                    >
                      {t === "all" ? "All" : t.toUpperCase()}
                    </button>
                  ))}
                  <button
                    type="button"
                    className="console-btn-ghost"
                    onClick={handleRefreshFeeds}
                    disabled={refreshing}
                  >
                    <RefreshCw size={14} /> {refreshing ? "Refreshing..." : "Refresh Feed"}
                  </button>
                </div>
              </div>

              <div style={{ overflowX: "auto" }}>
                <table className="console-table">
                  <thead>
                    <tr>
                      <th>Indicator (IOC)</th>
                      <th>Type</th>
                      <th>Classification</th>
                      <th>Tags</th>
                      <th>Ensemble Prob</th>
                      <th>Risk Score</th>
                    </tr>
                  </thead>
                  <tbody>
                    {iocs.map((item) => (
                      <tr key={item.id}>
                        <td className="mono-num" style={{ maxWidth: 380, wordBreak: "break-all" }}>
                          {item.ioc_value}
                        </td>
                        <td style={{ color: "var(--muted)" }}>{item.ioc_type.toUpperCase()}</td>
                        <td>{item.threat_type}</td>
                        <td style={{ color: "var(--muted)" }}>
                          {(item.tags || []).slice(0, 3).join(" · ") || "—"}
                        </td>
                        <td className="mono-num">
                          {item.ml_malicious_prob
                            ? `${(item.ml_malicious_prob * 100).toFixed(1)}%`
                            : "—"}
                        </td>
                        <td className="mono-num" style={{ fontWeight: 600 }}>
                          {item.risk_score}/100
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* TAB 2: 96.2% ML ENSEMBLE ENGINE & NLP ADVISORY EXTRACTOR */}
        {activeTab === "ensemble" && (
          <div>
            <div style={{ marginBottom: 28 }}>
              <h1 style={{ fontSize: "2rem", fontWeight: 400, letterSpacing: "-0.01em" }}>
                ML Classification & Advisory NLP Engine
              </h1>
              <p style={{ color: "var(--muted)", fontSize: "0.95rem", marginTop: 6 }}>
                Soft-voting ensemble (Random Forest, XGBoost, Neural Network) paired with unsupervised
                Isolation Forest and MITRE ATT&CK NLP extraction
              </p>
            </div>

            <div className="console-kpi-grid">
              <div className="console-kpi-card">
                <div style={{ fontSize: "0.8rem", color: "var(--muted)" }}>Precision</div>
                <div className="mono-num" style={{ fontSize: "2rem", fontWeight: 700, marginTop: 6 }}>
                  96.2%
                </div>
                <div style={{ fontSize: "0.78rem", color: "var(--muted)", marginTop: 4 }}>
                  Voting Classifier Verdict
                </div>
              </div>
              <div className="console-kpi-card">
                <div style={{ fontSize: "0.8rem", color: "var(--muted)" }}>Recall</div>
                <div className="mono-num" style={{ fontSize: "2rem", fontWeight: 700, marginTop: 6 }}>
                  94.8%
                </div>
                <div style={{ fontSize: "0.78rem", color: "var(--muted)", marginTop: 4 }}>
                  True Threat Capture Rate
                </div>
              </div>
              <div className="console-kpi-card">
                <div style={{ fontSize: "0.8rem", color: "var(--muted)" }}>F1-Score</div>
                <div className="mono-num" style={{ fontSize: "2rem", fontWeight: 700, marginTop: 6 }}>
                  95.5%
                </div>
                <div style={{ fontSize: "0.78rem", color: "var(--muted)", marginTop: 4 }}>
                  Harmonic Balance
                </div>
              </div>
              <div className="console-kpi-card">
                <div style={{ fontSize: "0.8rem", color: "var(--muted)" }}>False Positive Rate</div>
                <div className="mono-num" style={{ fontSize: "2rem", fontWeight: 700, marginTop: 6 }}>
                  &lt; 2%
                </div>
                <div style={{ fontSize: "0.78rem", color: "var(--muted)", marginTop: 4 }}>
                  Prevents SOC Alert Fatigue
                </div>
              </div>
            </div>

            <div className="console-surface">
              <h2 style={{ fontSize: "1.15rem", fontWeight: 500, marginBottom: 16 }}>
                Voting Classifier Ensemble Weights
              </h2>
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "repeat(auto-fit, minmax(250px, 1fr))",
                  gap: 16,
                }}
              >
                <div className="console-kpi-card">
                  <div className="mono-num" style={{ fontSize: "1.5rem", fontWeight: 700 }}>
                    40% · Random Forest
                  </div>
                  <p style={{ color: "var(--muted)", fontSize: "0.84rem", marginTop: 8, lineHeight: 1.5 }}>
                    100 decision estimators evaluating non-linear structural and lexical feature splits.
                  </p>
                </div>
                <div className="console-kpi-card">
                  <div className="mono-num" style={{ fontSize: "1.5rem", fontWeight: 700 }}>
                    35% · XGBoost
                  </div>
                  <p style={{ color: "var(--muted)", fontSize: "0.84rem", marginTop: 8, lineHeight: 1.5 }}>
                    Gradient-boosted decision trees tuned for high-precision decision boundary learning.
                  </p>
                </div>
                <div className="console-kpi-card">
                  <div className="mono-num" style={{ fontSize: "1.5rem", fontWeight: 700 }}>
                    25% · Neural Network
                  </div>
                  <p style={{ color: "var(--muted)", fontSize: "0.84rem", marginTop: 8, lineHeight: 1.5 }}>
                    Multi-layer perceptron (32×16) capturing latent character entropy and DGA patterns.
                  </p>
                </div>
              </div>
            </div>

            {/* Unstructured Threat Advisory NLP & MITRE ATT&CK Extractor */}
            <div className="console-surface">
              <h2 style={{ fontSize: "1.15rem", fontWeight: 500, marginBottom: 12 }}>
                Unstructured Threat Advisory NLP & MITRE ATT&CK Extractor
              </h2>
              <p style={{ color: "var(--muted)", fontSize: "0.86rem", marginBottom: 14 }}>
                Automatically refangs defanged indicators (`hxxp`, `[.]`), maps MITRE ATT&CK tactics, and
                scores extracted IOCs with the ML ensemble:
              </p>
              <textarea
                rows={4}
                className="console-input mono-num"
                style={{ width: "100%", borderRadius: 12, marginBottom: 14 }}
                value={reportText}
                onChange={(e) => setReportText(e.target.value)}
              />
              <button
                type="button"
                className="console-btn-pill"
                onClick={handleExtractReport}
                disabled={extractingReport}
              >
                <FileText size={15} />{" "}
                {extractingReport ? "Extracting Intelligence..." : "Extract IOCs & MITRE TTPs"}
              </button>

              {reportResult && (
                <div style={{ marginTop: 20, display: "grid", gap: 16 }}>
                  <div className="console-kpi-card">
                    <div style={{ fontWeight: 600, marginBottom: 8 }}>
                      Detected MITRE ATT&CK Techniques ({reportResult.mitre_attack_ttps.length})
                    </div>
                    <div style={{ display: "flex", flexWrap: "wrap", gap: 12, fontSize: "0.85rem" }}>
                      {reportResult.mitre_attack_ttps.map((t) => (
                        <span key={t.technique_id} style={{ color: "var(--muted)" }}>
                          <strong style={{ color: "var(--ink)" }}>{t.technique_id}</strong> · {t.name} (
                          {t.tactic})
                        </span>
                      ))}
                    </div>
                  </div>
                  {reportResult.ml_scored_indicators?.length > 0 && (
                    <div className="console-kpi-card">
                      <div style={{ fontWeight: 600, marginBottom: 10 }}>
                        Refanged & ML-Scored Indicators
                      </div>
                      <table className="console-table">
                        <thead>
                          <tr>
                            <th>Extracted Indicator</th>
                            <th>Verdict</th>
                            <th>ML Prob</th>
                            <th>Risk Score</th>
                          </tr>
                        </thead>
                        <tbody>
                          {reportResult.ml_scored_indicators.map((ind) => (
                            <tr key={ind.ioc_value}>
                              <td className="mono-num">{ind.ioc_value}</td>
                              <td>{ind.verdict}</td>
                              <td className="mono-num">
                                {(ind.ml_malicious_probability * 100).toFixed(1)}%
                              </td>
                              <td className="mono-num">{ind.risk_score}/100</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        )}

        {/* TAB 3: NEO4J THREAT KNOWLEDGE GRAPH */}
        {activeTab === "graph" && (
          <div>
            <div style={{ marginBottom: 24 }}>
              <h1 style={{ fontSize: "2rem", fontWeight: 400, letterSpacing: "-0.01em" }}>
                Neo4j Threat Knowledge Graph
              </h1>
              <p style={{ color: "var(--muted)", fontSize: "0.95rem", marginTop: 6 }}>
                Interactive correlation topology linking threat actors, campaigns, TTPs, and active IOCs
              </p>
            </div>

            <div
              className="console-surface"
              style={{ height: 600, padding: 0, overflow: "hidden", position: "relative" }}
            >
              <ForceGraph2D
                graphData={graphData}
                nodeLabel="id"
                nodeColor={(n) =>
                  n.group === "actor" ? "#ffffff" : n.group === "campaign" ? "#b6b5b5" : "#737373"
                }
                nodeRelSize={6}
                linkColor={() => "rgba(255,255,255,0.22)"}
                backgroundColor="#0b0b0b"
              />
            </div>
          </div>
        )}

        {/* TAB 4: AUTOMATED DETECTION RULE GENERATOR */}
        {activeTab === "rules" && (
          <div>
            <div style={{ marginBottom: 24 }}>
              <h1 style={{ fontSize: "2rem", fontWeight: 400, letterSpacing: "-0.01em" }}>
                Automated Detection Rule Generation
              </h1>
              <p style={{ color: "var(--muted)", fontSize: "0.95rem", marginTop: 6 }}>
                Compile Sigma, YARA, Suricata, and Snort signatures in seconds
              </p>
            </div>

            <div className="console-surface">
              <div style={{ display: "flex", gap: 12, marginBottom: 20, flexWrap: "wrap" }}>
                <input
                  type="text"
                  className="console-input"
                  style={{ flex: 1, minWidth: 280 }}
                  value={ruleIoc}
                  onChange={(e) => setRuleIoc(e.target.value)}
                />
                <button type="button" className="console-btn-pill" onClick={handleGenerateRules}>
                  Generate Detection Rules
                </button>
              </div>

              {rules && (
                <div>
                  <div
                    style={{
                      display: "flex",
                      gap: 8,
                      borderBottom: "1px solid rgba(255,255,255,0.1)",
                      paddingBottom: 14,
                      marginBottom: 16,
                      flexWrap: "wrap",
                    }}
                  >
                    {["sigma", "yara", "suricata", "snort"].map((fmt) => (
                      <button
                        key={fmt}
                        type="button"
                        className={`console-tab ${selectedRuleFmt === fmt ? "active" : ""}`}
                        onClick={() => setSelectedRuleFmt(fmt)}
                      >
                        {fmt.toUpperCase()}
                      </button>
                    ))}
                  </div>
                  <pre
                    className="mono-num"
                    style={{
                      background: "#050505",
                      border: "1px solid rgba(255,255,255,0.1)",
                      padding: 20,
                      borderRadius: 12,
                      color: "var(--ink)",
                      overflowX: "auto",
                      lineHeight: 1.55,
                    }}
                  >
                    {rules[selectedRuleFmt]}
                  </pre>
                </div>
              )}
            </div>
          </div>
        )}

        {/* TAB 5: 6-SOURCE PARALLEL ENRICHER */}
        {activeTab === "enrich" && (
          <div>
            <div style={{ marginBottom: 24 }}>
              <h1 style={{ fontSize: "2rem", fontWeight: 400, letterSpacing: "-0.01em" }}>
                6-Source Parallel Enrichment
              </h1>
              <p style={{ color: "var(--muted)", fontSize: "0.95rem", marginTop: 6 }}>
                VirusTotal, AbuseIPDB, Shodan, and AlienVault OTX queried concurrently in under 5 seconds
              </p>
            </div>

            <div className="console-surface">
              <div style={{ display: "flex", gap: 12, marginBottom: 22, flexWrap: "wrap" }}>
                <input
                  type="text"
                  className="console-input"
                  style={{ flex: 1, minWidth: 280 }}
                  value={enrichIoc}
                  onChange={(e) => setEnrichIoc(e.target.value)}
                />
                <button
                  type="button"
                  className="console-btn-pill"
                  onClick={handleExecuteEnrichment}
                  disabled={enriching}
                >
                  <Zap size={15} /> {enriching ? "Enriching..." : "Execute Parallel Enrichment"}
                </button>
              </div>

              {enrichment && (
                <div
                  style={{
                    display: "grid",
                    gridTemplateColumns: "repeat(auto-fit, minmax(250px, 1fr))",
                    gap: 16,
                  }}
                >
                  {Object.entries(enrichment.sources).map(([src, d]) => (
                    <div key={src} className="console-kpi-card">
                      <div style={{ fontWeight: 600, marginBottom: 10 }}>{src.replace("_", " ")}</div>
                      <pre
                        className="mono-num"
                        style={{
                          fontSize: "0.78rem",
                          color: "var(--muted)",
                          margin: 0,
                          overflowX: "auto",
                          lineHeight: 1.5,
                        }}
                      >
                        {JSON.stringify(d, null, 2)}
                      </pre>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {/* TAB 6: SIEM / SOAR / EDR EXPORT */}
        {activeTab === "siem" && (
          <div>
            <div style={{ marginBottom: 24 }}>
              <h1 style={{ fontSize: "2rem", fontWeight: 400, letterSpacing: "-0.01em" }}>
                SIEM / SOAR / EDR Integrations
              </h1>
              <p style={{ color: "var(--muted)", fontSize: "0.95rem", marginTop: 6 }}>
                One-click export into your existing security stack without rip-and-replace
              </p>
            </div>

            <div className="console-surface">
              <div style={{ display: "flex", gap: 8, marginBottom: 20, flexWrap: "wrap" }}>
                {[
                  { id: "splunk", label: "Splunk (SPL)" },
                  { id: "sentinel", label: "Microsoft Sentinel (KQL)" },
                  { id: "qradar", label: "IBM QRadar (AQL)" },
                  { id: "crowdstrike", label: "CrowdStrike Falcon (CSV)" },
                  { id: "stix", label: "STIX / TAXII 2.1" },
                ].map((p) => (
                  <button
                    key={p.id}
                    type="button"
                    className={`console-tab ${selectedSiem === p.id ? "active" : ""}`}
                    onClick={() => handleExportSiem(p.id)}
                  >
                    {p.label}
                  </button>
                ))}
              </div>

              {exportData && (
                <div>
                  <div style={{ fontSize: "0.85rem", color: "var(--muted)", marginBottom: 10 }}>
                    Generated Artifact for <strong style={{ color: "var(--ink)" }}>{exportData.platform}</strong>
                  </div>
                  <pre
                    className="mono-num"
                    style={{
                      background: "#050505",
                      border: "1px solid rgba(255,255,255,0.1)",
                      padding: 20,
                      borderRadius: 12,
                      color: "var(--ink)",
                      overflowX: "auto",
                      lineHeight: 1.55,
                    }}
                  >
                    {typeof exportData.export_query === "string"
                      ? exportData.export_query
                      : typeof exportData.payload === "string"
                      ? exportData.payload
                      : JSON.stringify(exportData.payload || exportData, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          </div>
        )}

        {/* TAB 7: QUANTIFIABLE BUSINESS IMPACT & ENTERPRISE TIERS */}
        {activeTab === "impact" && (
          <div>
            <div style={{ marginBottom: 24 }}>
              <h1 style={{ fontSize: "2rem", fontWeight: 400, letterSpacing: "-0.01em" }}>
                Business Impact & Enterprise Tiers
              </h1>
              <p style={{ color: "var(--muted)", fontSize: "0.95rem", marginTop: 6 }}>
                Quantifiable improvements across every core SOC metric · 600% estimated ROI · 4-month payback
              </p>
            </div>

            <div className="console-surface" style={{ padding: 0, overflow: "hidden" }}>
              <table className="console-table">
                <thead>
                  <tr>
                    <th>SOC Metric</th>
                    <th>Before ThreatOps</th>
                    <th>After ThreatOps</th>
                    <th>Measured Improvement</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td style={{ fontWeight: 500 }}>Time to Analyze IOC</td>
                    <td className="mono-num">30 min</td>
                    <td className="mono-num">5 sec</td>
                    <td className="mono-num" style={{ fontWeight: 700 }}>
                      99.7%
                    </td>
                  </tr>
                  <tr>
                    <td style={{ fontWeight: 500 }}>False Positive Rate</td>
                    <td className="mono-num">40%</td>
                    <td className="mono-num">1.8%</td>
                    <td className="mono-num" style={{ fontWeight: 700 }}>
                      95.5%
                    </td>
                  </tr>
                  <tr>
                    <td style={{ fontWeight: 500 }}>IOCs Processed / Analyst</td>
                    <td className="mono-num">100 / day</td>
                    <td className="mono-num">1,000+ / day</td>
                    <td className="mono-num" style={{ fontWeight: 700 }}>
                      10×
                    </td>
                  </tr>
                  <tr>
                    <td style={{ fontWeight: 500 }}>Detection Rule Creation</td>
                    <td className="mono-num">2 hours</td>
                    <td className="mono-num">30 sec</td>
                    <td className="mono-num" style={{ fontWeight: 700 }}>
                      99.6%
                    </td>
                  </tr>
                  <tr>
                    <td style={{ fontWeight: 500 }}>Mean Time to Detect (MTTD)</td>
                    <td className="mono-num">24 hours</td>
                    <td className="mono-num">5 min</td>
                    <td className="mono-num" style={{ fontWeight: 700 }}>
                      99.7%
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>

            <div
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))",
                gap: 16,
              }}
            >
              {[
                {
                  name: "Starter",
                  price: "$2,499",
                  specs: ["1,000 IOCs / day", "5 analyst seats", "Email support", "Full feature access"],
                },
                {
                  name: "Professional",
                  price: "$5,999",
                  specs: ["10,000 IOCs / day", "20 analyst seats", "24/7 priority support", "SIEM / EDR webhooks"],
                },
                {
                  name: "Enterprise",
                  price: "$14,999",
                  specs: ["Unlimited IOCs", "Unlimited seats", "Dedicated CSM", "Custom feed integrations"],
                },
              ].map((tier) => (
                <div key={tier.name} className="console-surface" style={{ marginBottom: 0 }}>
                  <div style={{ fontSize: "1.1rem", fontWeight: 500 }}>{tier.name}</div>
                  <div className="mono-num" style={{ fontSize: "2.1rem", fontWeight: 700, margin: "12px 0" }}>
                    {tier.price}
                    <span style={{ fontSize: "0.85rem", color: "var(--muted)", fontWeight: 400 }}>/mo</span>
                  </div>
                  <ul
                    style={{
                      listStyle: "none",
                      padding: 0,
                      margin: "0 0 22px",
                      display: "flex",
                      flexDirection: "column",
                      gap: 8,
                      color: "var(--muted)",
                      fontSize: "0.86rem",
                    }}
                  >
                    {tier.specs.map((s) => (
                      <li key={s}>{s}</li>
                    ))}
                  </ul>
                  <button
                    type="button"
                    className="console-btn-pill"
                    style={{ width: "100%", justifyContent: "center" }}
                    onClick={() => setActiveTab("pipeline")}
                  >
                    Active Plan · Launch Pipeline
                  </button>
                </div>
              ))}
            </div>
          </div>
        )}
      </main>
    </div>
  );
}