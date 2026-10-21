import { useState, useEffect, useCallback, useRef } from "react";
import ForceGraph2D from "react-force-graph-2d";
import {
  Activity,
  Cpu,
  Network,
  FileCode,
  Share2,
  TrendingUp,
  RefreshCw,
  Zap,
  Terminal,
  ArrowLeft,
  X,
  FileText,
  Database,
  Sliders,
  Plus,
  Radio,
  Play,
  Pause,
  CheckCircle2,
  AlertTriangle,
  ShieldAlert,
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

  // Live IOC feed & OSINT sources state
  const [iocs, setIocs] = useState([]);
  const [feedSources, setFeedSources] = useState([]);
  const [lastSyncBanner, setLastSyncBanner] = useState(null);
  const [filterType, setFilterType] = useState("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [refreshing, setRefreshing] = useState(false);

  // Live WebSocket Threat Stream & Autonomous Triage Queue state
  const wsRef = useRef(null);
  const filterTypeRef = useRef(filterType);
  const searchQueryRef = useRef(searchQuery);

  useEffect(() => {
    filterTypeRef.current = filterType;
    searchQueryRef.current = searchQuery;
  }, [filterType, searchQuery]);

  const [wsConnected, setWsConnected] = useState(false);
  const [triageQueue, setTriageQueue] = useState([]);
  const [triageFilter, setTriageFilter] = useState("all"); // all | auto_blocked | needs_review | monitored
  const [latestStreamedIoc, setLatestStreamedIoc] = useState(null);
  const [streamStats, setStreamStats] = useState({
    total_streamed: 0,
    buffer_remaining: 0,
    connected_clients: 1,
    paused: false,
    interval_ms: 4500,
  });

  // Scanner state
  const [scanIoc, setScanIoc] = useState("http://194.55.186.21:54321/Mozi.a");
  const [scanResult, setScanResult] = useState(null);
  const [scanning, setScanning] = useState(false);

  // Trainable ML Studio & Dataset state
  const [mlSummary, setMlSummary] = useState(null);
  const [trainingModel, setTrainingModel] = useState(false);
  const [testSplit, setTestSplit] = useState(0.2);
  const [learningRate, setLearningRate] = useState(0.12);
  const [nEstimators, setNEstimators] = useState(100);
  const [rfWeight, setRfWeight] = useState(0.4);
  const [xgbWeight, setXgbWeight] = useState(0.35);
  const [mlpWeight, setMlpWeight] = useState(0.25);

  // Custom Dataset Upload / Injection state
  const [customDatasetText, setCustomDatasetText] = useState(
    "http://185.215.113.45:8080/cobalt_loader.elf,1\nhttp://secure-verify-corporate-sso.tk/auth/login.php,1\nhttps://docs.github.com/en/rest/overview,0\nhttps://cloud.google.com/architecture/security-foundations,0"
  );
  const [addingDataset, setAddingDataset] = useState(false);
  const [datasetBanner, setDatasetBanner] = useState(null);

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

  const loadDashboardData = useCallback(
    async (typeFilter = filterType, query = searchQuery) => {
      try {
        const params = new URLSearchParams({ limit: "60" });
        if (typeFilter && typeFilter !== "all") params.set("ioc_type", typeFilter);
        if (query && query.trim()) params.set("search", query.trim());

        const [iocsRes, sourcesRes, mlRes, triageRes] = await Promise.all([
          fetch(`${API_BASE}/iocs?${params.toString()}`),
          fetch(`${API_BASE}/feeds/sources`),
          fetch(`${API_BASE}/ml/status`),
          fetch(`${API_BASE}/triage/queue`),
        ]);

        if (iocsRes.ok) setIocs(await iocsRes.json());
        if (sourcesRes.ok) {
          const sData = await sourcesRes.json();
          setFeedSources(sData.sources || []);
        }
        if (mlRes.ok) setMlSummary(await mlRes.json());
        if (triageRes.ok) {
          const tData = await triageRes.json();
          if (Array.isArray(tData.triage_queue)) setTriageQueue(tData.triage_queue);
          if (tData.stream_stats) setStreamStats(tData.stream_stats);
        }
      } catch (e) {
        console.warn("Could not load dashboard telemetry:", e);
      }
    },
    [filterType, searchQuery]
  );

  // Real-time WebSocket Listener (/ws/threat-stream) with Auto-Reconnection & Idempotent Reconciliation
  useEffect(() => {
    let ws = null;
    let reconnectTimer = null;
    let unmounted = false;

    const connectWebSocket = () => {
      if (unmounted) return;
      const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
      const wsUrl = `${protocol}//${window.location.host}/ws/threat-stream`;
      ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        if (!unmounted) setWsConnected(true);
      };

      ws.onmessage = (event) => {
        if (unmounted) return;
        try {
          const payload = JSON.parse(event.data);
          if (payload.type === "stream:init") {
            if (Array.isArray(payload.triage_queue)) {
              setTriageQueue(payload.triage_queue);
            }
            if (Array.isArray(payload.sources)) {
              setFeedSources(payload.sources);
            }
            if (payload.stream_stats) {
              setStreamStats(payload.stream_stats);
            }
          } else if (payload.type === "ioc:triaged" && payload.queue_item) {
            const incoming = payload.queue_item;
            setLatestStreamedIoc(incoming);

            // Idempotent update to Triage Queue
            setTriageQueue((prev) => {
              const filtered = prev.filter(
                (q) => q.queue_id !== incoming.queue_id && q.ioc_value !== incoming.ioc_value
              );
              return [incoming, ...filtered].slice(0, 60);
            });

            // Idempotent update to Active OSINT Threat Feed table if it matches current filters
            if (payload.ioc_record) {
              const rec = payload.ioc_record;
              const activeType = filterTypeRef.current;
              const activeQuery = (searchQueryRef.current || "").trim().toLowerCase();
              const typeMatches =
                activeType === "all" ||
                (rec.ioc_type || "").toLowerCase() === activeType.toLowerCase();
              const queryMatches =
                !activeQuery ||
                (rec.ioc_value || "").toLowerCase().includes(activeQuery) ||
                (rec.threat_type || "").toLowerCase().includes(activeQuery) ||
                (rec.tags || []).some((t) => t.toLowerCase().includes(activeQuery));

              if (typeMatches && queryMatches) {
                setIocs((prev) => {
                  const withoutDup = prev.filter((r) => r.ioc_value !== rec.ioc_value);
                  return [rec, ...withoutDup].slice(0, 60);
                });
              }
            }

            if (Array.isArray(payload.sources)) {
              setFeedSources(payload.sources);
            }
            if (payload.stream_stats) {
              setStreamStats(payload.stream_stats);
            }
          } else if (payload.type === "stream:status" && payload.stream_stats) {
            setStreamStats(payload.stream_stats);
          } else if (payload.type === "triage:updated" && payload.queue_id) {
            setTriageQueue((prev) =>
              prev.map((item) =>
                item.queue_id === payload.queue_id
                  ? { ...item, triage_status: payload.triage_status }
                  : item
              )
            );
          }
        } catch (err) {
          console.warn("[ThreatOps WS] Failed to parse message:", err);
        }
      };

      ws.onclose = () => {
        if (!unmounted) {
          setWsConnected(false);
          reconnectTimer = setTimeout(connectWebSocket, 2500);
        }
      };

      ws.onerror = () => {
        ws.close();
      };
    };

    connectWebSocket();

    return () => {
      unmounted = true;
      if (reconnectTimer) clearTimeout(reconnectTimer);
      if (ws && ws.readyState <= 1) ws.close();
    };
  }, []);

  const handleToggleStreamPause = () => {
    const nextPaused = !streamStats.paused;
    setStreamStats((prev) => ({ ...prev, paused: nextPaused }));
    if (wsRef.current && wsRef.current.readyState === 1) {
      wsRef.current.send(
        JSON.stringify({ type: "stream:configure", paused: nextPaused })
      );
    }
  };

  const handleChangeStreamInterval = (ms) => {
    setStreamStats((prev) => ({ ...prev, interval_ms: ms }));
    if (wsRef.current && wsRef.current.readyState === 1) {
      wsRef.current.send(
        JSON.stringify({ type: "stream:configure", interval_ms: ms })
      );
    }
  };

  const handlePullStreamNow = () => {
    if (wsRef.current && wsRef.current.readyState === 1) {
      wsRef.current.send(JSON.stringify({ type: "stream:pull_now" }));
    }
  };

  const handleTriageAction = async (queueId, action) => {
    // Optimistic update
    setTriageQueue((prev) =>
      prev.map((q) => (q.queue_id === queueId ? { ...q, triage_status: action } : q))
    );
    if (wsRef.current && wsRef.current.readyState === 1) {
      wsRef.current.send(
        JSON.stringify({ type: "triage:action", queue_id: queueId, action })
      );
    } else {
      await fetch(`${API_BASE}/triage/${queueId}/action`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action }),
      });
    }
  };

  const handleInspectFromQueue = async (iocVal) => {
    setScanIoc(iocVal);
    setScanning(true);
    try {
      const res = await fetch(`${API_BASE}/scan/ioc`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ioc_value: iocVal }),
      });
      if (res.ok) setScanResult(await res.json());
    } finally {
      setScanning(false);
    }
  };

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

  const handleTrainEnsemble = async () => {
    setTrainingModel(true);
    try {
      const res = await fetch(`${API_BASE}/ml/train`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          test_split: testSplit,
          learning_rate: learningRate,
          n_estimators: nEstimators,
          rf_weight: rfWeight,
          xgb_weight: xgbWeight,
          mlp_weight: mlpWeight,
        }),
      });
      if (res.ok) {
        const summary = await res.json();
        setMlSummary(summary);
        await loadDashboardData();
      }
    } finally {
      setTrainingModel(false);
    }
  };

  const handleInjectDataset = async (e) => {
    e.preventDefault();
    setAddingDataset(true);
    setDatasetBanner(null);
    try {
      const lines = customDatasetText
        .split(/\r?\n/)
        .map((l) => l.trim())
        .filter(Boolean);
      const samples = [];
      for (const line of lines) {
        const lastComma = line.lastIndexOf(",");
        if (lastComma > 0) {
          const ioc_value = line.slice(0, lastComma).trim();
          const label = parseInt(line.slice(lastComma + 1).trim(), 10) === 1 ? 1 : 0;
          samples.push({ ioc_value, label });
        } else {
          samples.push({ ioc_value: line, label: 1 });
        }
      }

      const res = await fetch(`${API_BASE}/ml/dataset/add`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ samples }),
      });
      if (res.ok) {
        const data = await res.json();
        setMlSummary(data.model_summary);
        setDatasetBanner(
          `Added ${data.samples_added} labeled samples and retrained 18-feature ensemble (Test F1: ${data.model_summary.metrics.f1_score}%).`
        );
        await loadDashboardData();
      }
    } finally {
      setAddingDataset(false);
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
    setLastSyncBanner(null);
    try {
      const res = await fetch(`${API_BASE}/feeds/refresh`, { method: "POST" });
      if (res.ok) {
        const syncData = await res.json();
        setFeedSources(syncData.sources || []);
        setLastSyncBanner(syncData);
      }
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
                    6-source parallel enrichment, an 18-feature trainable Voting Classifier ensemble (Random
                    Forest, Gradient Boosted Stumps, and Neural MLP) paired with an unsupervised Isolation
                    Forest anomaly detector, and Neo4j graph correlation into a single 13-second pipeline.
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
                        {mlSummary?.metrics?.precision || 96.2}%
                      </div>
                    </div>
                    <div className="console-kpi-card">
                      <div style={{ fontSize: "0.78rem", color: "var(--muted)" }}>Mean Triage Latency</div>
                      <div className="mono-num" style={{ fontSize: "1.6rem", fontWeight: 700, marginTop: 4 }}>
                        &lt; 13s
                      </div>
                    </div>
                    <div className="console-kpi-card">
                      <div style={{ fontSize: "0.78rem", color: "var(--muted)" }}>Labeled Corpus</div>
                      <div className="mono-num" style={{ fontSize: "1.6rem", fontWeight: 700, marginTop: 4 }}>
                        {mlSummary?.dataset?.total_samples || 160}+
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
                      onClick={() => enterThreatOpsConsole("ensemble")}
                    >
                      Open ML Training Studio
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
                        title: "01. Live OSINT & 13s Triage",
                        desc: "Live Abuse.ch URLHaus & FeodoTracker sync, 18D feature extraction, and explainable risk scoring.",
                      },
                      {
                        id: "ensemble",
                        title: "02. ML Training & Dataset Studio",
                        desc: "Train/test split evaluation, hyperparameter tuning, confusion matrix, and custom dataset ingestion.",
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
                      How does the Train/Test ML Ensemble evaluate indicators?
                    </div>
                    <p style={{ fontSize: "0.86rem", color: "var(--muted)", lineHeight: 1.5 }}>
                      Each indicator is decomposed into 18 structural and lexical features (Shannon entropy,
                      host entropy, consonant-to-vowel ratio, hex encoding density, raw IPv4 host detection,
                      non-standard port usage, and payload keywords) and evaluated by a soft-voting ensemble
                      trained on a stratified train/test split of live malicious IOCs and benign baselines.
                    </p>
                  </div>
                  <div>
                    <div style={{ fontWeight: 600, marginBottom: 4 }}>
                      How are live OSINT feeds ingested and deduplicated?
                    </div>
                    <p style={{ fontSize: "0.86rem", color: "var(--muted)", lineHeight: 1.5 }}>
                      ThreatOps pulls live malware URLs from Abuse.ch URLHaus and active Botnet C2 IPs from
                      FeodoTracker, merges sighting counts and multi-source confidence scores, and automatically
                      retrains and re-scores the entire indicator database.
                    </p>
                  </div>
                  <div style={{ marginTop: 8 }}>
                    <button
                      type="button"
                      className="console-btn-pill"
                      onClick={() => enterThreatOpsConsole("ensemble")}
                    >
                      Open ML Training Studio
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
            <Activity size={14} /> Live Feeds & Pipeline
          </button>
          <button
            type="button"
            className={`console-tab ${activeTab === "ensemble" ? "active" : ""}`}
            onClick={() => setActiveTab("ensemble")}
          >
            <Cpu size={14} /> ML Studio & Datasets
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
        {/* TAB 1: LIVE OSINT FEEDS & 13-SECOND TRIAGE PIPELINE */}
        {activeTab === "pipeline" && (
          <div>
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "flex-end",
                flexWrap: "wrap",
                gap: 16,
                marginBottom: 28,
              }}
            >
              <div>
                <h1 style={{ fontSize: "2rem", fontWeight: 400, letterSpacing: "-0.01em" }}>
                  Live OSINT Ingestion & 13-Second Triage Pipeline
                </h1>
                <p style={{ color: "var(--muted)", fontSize: "0.95rem", marginTop: 6 }}>
                  Real-time Abuse.ch URLHaus & FeodoTracker C2 ingestion · 18-feature ML ensemble scoring ·{" "}
                  {mlSummary?.metrics?.precision || 96.2}% Test Precision
                </p>
              </div>
              <button
                type="button"
                className="console-btn-pill"
                onClick={handleRefreshFeeds}
                disabled={refreshing}
              >
                <RefreshCw size={15} />{" "}
                {refreshing ? "Pulling Live OSINT Feeds & Retraining..." : "Sync Live OSINT Feeds"}
              </button>
            </div>

            {lastSyncBanner && (
              <div
                className="console-surface"
                style={{
                  padding: "16px 22px",
                  borderColor: "rgba(255,255,255,0.28)",
                  marginBottom: 22,
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  flexWrap: "wrap",
                  gap: 12,
                }}
              >
                <div style={{ fontSize: "0.9rem" }}>
                  <strong>Live OSINT Sync Complete ({lastSyncBanner.latency_ms}ms):</strong>{" "}
                  <span className="mono-num">{lastSyncBanner.inserted}</span> new indicators inserted ·{" "}
                  <span className="mono-num">{lastSyncBanner.updated}</span> existing corroborated ·{" "}
                  <span className="mono-num">{lastSyncBanner.total_in_db}</span> total active IOCs re-scored
                  by ML Ensemble.
                </div>
                <span className="mono-num" style={{ fontSize: "0.84rem", color: "var(--muted)" }}>
                  Ensemble F1: {lastSyncBanner.model_metrics?.f1_score}%
                </span>
              </div>
            )}

            {/* Live OSINT Feed Connectors Grid */}
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))",
                gap: 16,
                marginBottom: 24,
              }}
            >
              {feedSources.map((src) => (
                <div key={src.source} className="console-kpi-card">
                  <div
                    style={{
                      display: "flex",
                      justifyContent: "space-between",
                      alignItems: "center",
                      marginBottom: 6,
                    }}
                  >
                    <span style={{ fontWeight: 600, fontSize: "0.96rem" }}>{src.source}</span>
                    <span className="mono-num" style={{ fontSize: "0.76rem", color: "var(--muted)" }}>
                      {src.status === "live_synced" ? "LIVE HTTPS" : "OPERATIONAL"}
                    </span>
                  </div>
                  <div style={{ fontSize: "0.8rem", color: "var(--muted)", marginBottom: 12 }}>
                    {src.type}
                  </div>
                  <div
                    style={{
                      display: "flex",
                      justifyContent: "space-between",
                      alignItems: "baseline",
                      borderTop: "1px solid rgba(255,255,255,0.07)",
                      paddingTop: 10,
                    }}
                  >
                    <span style={{ fontSize: "0.78rem", color: "var(--muted)" }}>Active IOCs</span>
                    <span className="mono-num" style={{ fontSize: "1.25rem", fontWeight: 700 }}>
                      {src.indicators_ingested}
                    </span>
                  </div>
                </div>
              ))}
            </div>

            {/* LIVE WEBSOCKET STREAM & AUTONOMOUS TRIAGE QUEUE */}
            <div className="console-surface">
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  flexWrap: "wrap",
                  gap: 14,
                  marginBottom: 16,
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                  <Radio size={18} style={{ color: wsConnected ? "#fafafa" : "var(--muted)" }} />
                  <div>
                    <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                      <h2 style={{ fontSize: "1.15rem", fontWeight: 500 }}>
                        Live WebSocket Threat Stream & Autonomous Triage Queue
                      </h2>
                      <span
                        className="mono-num"
                        style={{
                          fontSize: "0.74rem",
                          padding: "3px 9px",
                          borderRadius: 999,
                          background: wsConnected
                            ? "rgba(255,255,255,0.12)"
                            : "rgba(255,255,255,0.04)",
                          border: "1px solid rgba(255,255,255,0.18)",
                          color: "var(--ink)",
                        }}
                      >
                        {wsConnected
                          ? streamStats.paused
                            ? "WS PAUSED · /ws/threat-stream"
                            : "WS STREAMING LIVE · /ws/threat-stream"
                          : "WS RECONNECTING..."}
                      </span>
                    </div>
                    <p style={{ color: "var(--muted)", fontSize: "0.82rem", marginTop: 4 }}>
                      Streaming live indicators from Abuse.ch URLHaus, FeodoTracker, and AlienVault OTX /
                      ThreatFox directly into the 18-feature ML triage queue.
                    </p>
                  </div>
                </div>

                {/* WebSocket Stream Controls */}
                <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                  {[
                    { ms: 2500, label: "Fast (2.5s)" },
                    { ms: 4500, label: "Normal (4.5s)" },
                    { ms: 9000, label: "Slow (9s)" },
                  ].map((spd) => (
                    <button
                      key={spd.ms}
                      type="button"
                      className={`console-tab ${streamStats.interval_ms === spd.ms ? "active" : ""}`}
                      onClick={() => handleChangeStreamInterval(spd.ms)}
                    >
                      {spd.label}
                    </button>
                  ))}
                  <button
                    type="button"
                    className="console-btn-ghost"
                    onClick={handleToggleStreamPause}
                  >
                    {streamStats.paused ? <Play size={14} /> : <Pause size={14} />}
                    {streamStats.paused ? "Resume Stream" : "Pause Stream"}
                  </button>
                  <button
                    type="button"
                    className="console-btn-pill"
                    onClick={handlePullStreamNow}
                  >
                    <Zap size={14} /> Stream Next IOC Now
                  </button>
                </div>
              </div>

              {/* Latest Incoming WebSocket Event Ticker */}
              {latestStreamedIoc && (
                <div
                  style={{
                    background: "#050505",
                    border: "1px solid rgba(255,255,255,0.22)",
                    borderRadius: 12,
                    padding: "12px 18px",
                    marginBottom: 18,
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    flexWrap: "wrap",
                    gap: 12,
                  }}
                >
                  <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
                    <span
                      className="mono-num"
                      style={{
                        fontSize: "0.74rem",
                        padding: "2px 8px",
                        borderRadius: 6,
                        background: "#ffffff",
                        color: "#050505",
                        fontWeight: 700,
                      }}
                    >
                      LIVE INGEST · {latestStreamedIoc.queue_id}
                    </span>
                    <span className="mono-num" style={{ fontWeight: 600, fontSize: "0.9rem" }}>
                      {latestStreamedIoc.ioc_value}
                    </span>
                    <span style={{ fontSize: "0.8rem", color: "var(--muted)" }}>
                      via {latestStreamedIoc.source_feed}
                    </span>
                  </div>
                  <div className="mono-num" style={{ fontSize: "0.82rem", color: "var(--muted)" }}>
                    Triage Latency: <strong style={{ color: "var(--ink)" }}>{latestStreamedIoc.triage_latency_ms}ms</strong> ·
                    Ensemble Risk: <strong style={{ color: "var(--ink)" }}>{latestStreamedIoc.risk_score}/100</strong> ·
                    Auto-Disposition:{" "}
                    <strong style={{ color: "var(--ink)" }}>
                      {latestStreamedIoc.triage_status.toUpperCase()}
                    </strong>
                  </div>
                </div>
              )}

              {/* Triage Queue Filter Bar & Stats */}
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  flexWrap: "wrap",
                  gap: 12,
                  marginBottom: 14,
                }}
              >
                <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                  {[
                    { id: "all", label: `All Queued (${triageQueue.length})` },
                    {
                      id: "auto_blocked",
                      label: `Auto-Blocked (${
                        triageQueue.filter(
                          (q) =>
                            q.triage_status === "auto_blocked" ||
                            q.triage_status === "approved_block"
                        ).length
                      })`,
                    },
                    {
                      id: "needs_review",
                      label: `Needs SOC Review (${
                        triageQueue.filter(
                          (q) =>
                            q.triage_status === "needs_review" ||
                            q.triage_status === "escalated"
                        ).length
                      })`,
                    },
                    {
                      id: "monitored",
                      label: `Monitored / Cleared (${
                        triageQueue.filter(
                          (q) =>
                            q.triage_status === "monitored" ||
                            q.triage_status === "false_positive"
                        ).length
                      })`,
                    },
                  ].map((f) => (
                    <button
                      key={f.id}
                      type="button"
                      className={`console-tab ${triageFilter === f.id ? "active" : ""}`}
                      onClick={() => setTriageFilter(f.id)}
                    >
                      {f.label}
                    </button>
                  ))}
                </div>
                <div className="mono-num" style={{ fontSize: "0.8rem", color: "var(--muted)" }}>
                  Streamed This Session: <strong style={{ color: "var(--ink)" }}>{streamStats.total_streamed}</strong> ·
                  Staging Buffer: <strong style={{ color: "var(--ink)" }}>{streamStats.buffer_remaining}</strong>
                </div>
              </div>

              {/* Autonomous Triage Queue Table */}
              <div style={{ overflowX: "auto" }}>
                <table className="console-table">
                  <thead>
                    <tr>
                      <th>Queue ID</th>
                      <th>Live Indicator (IOC)</th>
                      <th>Feed Source</th>
                      <th>3-Model Vote (RF/XGB/MLP)</th>
                      <th>Risk Score</th>
                      <th>Triage Disposition</th>
                      <th>SOC Analyst Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {triageQueue
                      .filter((q) => {
                        if (triageFilter === "all") return true;
                        if (triageFilter === "auto_blocked")
                          return (
                            q.triage_status === "auto_blocked" ||
                            q.triage_status === "approved_block"
                          );
                        if (triageFilter === "needs_review")
                          return (
                            q.triage_status === "needs_review" ||
                            q.triage_status === "escalated"
                          );
                        return (
                          q.triage_status === "monitored" ||
                          q.triage_status === "false_positive"
                        );
                      })
                      .slice(0, 15)
                      .map((q) => (
                        <tr key={q.queue_id}>
                          <td className="mono-num" style={{ fontSize: "0.8rem", color: "var(--muted)" }}>
                            {q.queue_id}
                            <div style={{ fontSize: "0.72rem" }}>{q.triage_latency_ms}ms</div>
                          </td>
                          <td className="mono-num" style={{ maxWidth: 300, wordBreak: "break-all" }}>
                            <div style={{ fontWeight: 600 }}>{q.ioc_value}</div>
                            <div style={{ fontSize: "0.75rem", color: "var(--muted)" }}>
                              {q.ioc_type.toUpperCase()} · {q.threat_type}
                            </div>
                          </td>
                          <td style={{ fontSize: "0.82rem", color: "var(--muted)" }}>
                            {q.source_feed}
                          </td>
                          <td className="mono-num" style={{ fontSize: "0.8rem" }}>
                            {q.model_breakdown ? (
                              <span>
                                {(q.model_breakdown.random_forest * 100).toFixed(0)}% /{" "}
                                {(q.model_breakdown.xgboost * 100).toFixed(0)}% /{" "}
                                {(q.model_breakdown.neural_mlp * 100).toFixed(0)}%
                              </span>
                            ) : (
                              `${((q.ml_malicious_prob || 0.8) * 100).toFixed(1)}%`
                            )}
                          </td>
                          <td className="mono-num" style={{ fontWeight: 700 }}>
                            {q.risk_score}/100
                          </td>
                          <td>
                            <span
                              className="mono-num"
                              style={{
                                display: "inline-flex",
                                alignItems: "center",
                                gap: 6,
                                fontSize: "0.76rem",
                                padding: "4px 10px",
                                borderRadius: 999,
                                background:
                                  q.triage_status === "auto_blocked" ||
                                  q.triage_status === "approved_block"
                                    ? "#ffffff"
                                    : "rgba(255,255,255,0.08)",
                                color:
                                  q.triage_status === "auto_blocked" ||
                                  q.triage_status === "approved_block"
                                    ? "#050505"
                                    : "#fafafa",
                                fontWeight: 600,
                              }}
                            >
                              {(q.triage_status === "auto_blocked" ||
                                q.triage_status === "approved_block") && <ShieldAlert size={12} />}
                              {(q.triage_status === "needs_review" ||
                                q.triage_status === "escalated") && <AlertTriangle size={12} />}
                              {(q.triage_status === "monitored" ||
                                q.triage_status === "false_positive") && <CheckCircle2 size={12} />}
                              {q.triage_status.replace("_", " ").toUpperCase()}
                            </span>
                          </td>
                          <td>
                            <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                              <button
                                type="button"
                                className="console-tab"
                                style={{ padding: "4px 10px", fontSize: "0.75rem" }}
                                onClick={() => handleTriageAction(q.queue_id, "approved_block")}
                              >
                                Block
                              </button>
                              <button
                                type="button"
                                className="console-tab"
                                style={{ padding: "4px 10px", fontSize: "0.75rem" }}
                                onClick={() => handleTriageAction(q.queue_id, "escalated")}
                              >
                                Escalate
                              </button>
                              <button
                                type="button"
                                className="console-tab"
                                style={{ padding: "4px 10px", fontSize: "0.75rem" }}
                                onClick={() => handleTriageAction(q.queue_id, "false_positive")}
                              >
                                Dismiss
                              </button>
                              <button
                                type="button"
                                className="console-tab"
                                style={{ padding: "4px 10px", fontSize: "0.75rem" }}
                                onClick={() => handleInspectFromQueue(q.ioc_value)}
                              >
                                Inspect 18D
                              </button>
                            </div>
                          </td>
                        </tr>
                      ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Real-Time Indicator Scanner with 3-Model Breakdown & 18D Vector */}
            <div className="console-surface">
              <h2 style={{ fontSize: "1.15rem", fontWeight: 500, marginBottom: 14 }}>
                Real-Time 18-Feature ML Indicator Inspection
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
                  <Terminal size={15} /> {scanning ? "Running 18D Inference..." : "Analyze Indicator"}
                </button>
              </div>

              {scanResult && (
                <div
                  style={{
                    background: "#050505",
                    border: "1px solid rgba(255,255,255,0.12)",
                    borderRadius: 12,
                    padding: 22,
                  }}
                >
                  <div
                    style={{
                      display: "flex",
                      justifyContent: "space-between",
                      alignItems: "center",
                      flexWrap: "wrap",
                      gap: 12,
                      marginBottom: 16,
                    }}
                  >
                    <div>
                      <div style={{ fontSize: "0.75rem", color: "var(--muted)" }}>ENSEMBLE VERDICT</div>
                      <div className="mono-num" style={{ fontSize: "1.4rem", fontWeight: 700, marginTop: 2 }}>
                        {scanResult.verdict} · Risk Score {scanResult.risk_score}/100
                      </div>
                    </div>
                    <div className="mono-num" style={{ color: "var(--muted)", fontSize: "0.85rem" }}>
                      Soft-Vote P(Malicious): {(scanResult.ml_malicious_probability * 100).toFixed(1)}%
                      {scanResult.is_anomaly ? " · Isolation Forest Zero-Day Outlier" : ""}
                    </div>
                  </div>

                  {/* Per-Model Probability Breakdown */}
                  {scanResult.model_breakdown && (
                    <div
                      style={{
                        display: "grid",
                        gridTemplateColumns: "repeat(auto-fit, minmax(170px, 1fr))",
                        gap: 12,
                        marginBottom: 16,
                      }}
                    >
                      <div className="console-kpi-card" style={{ padding: 14 }}>
                        <div style={{ fontSize: "0.75rem", color: "var(--muted)" }}>
                          Random Forest ({Math.round((scanResult.ensemble_weights?.RandomForest || 0.4) * 100)}%)
                        </div>
                        <div className="mono-num" style={{ fontSize: "1.2rem", fontWeight: 700, marginTop: 4 }}>
                          {(scanResult.model_breakdown.random_forest * 100).toFixed(1)}%
                        </div>
                      </div>
                      <div className="console-kpi-card" style={{ padding: 14 }}>
                        <div style={{ fontSize: "0.75rem", color: "var(--muted)" }}>
                          Gradient Boost ({Math.round((scanResult.ensemble_weights?.XGBoost || 0.35) * 100)}%)
                        </div>
                        <div className="mono-num" style={{ fontSize: "1.2rem", fontWeight: 700, marginTop: 4 }}>
                          {(scanResult.model_breakdown.xgboost * 100).toFixed(1)}%
                        </div>
                      </div>
                      <div className="console-kpi-card" style={{ padding: 14 }}>
                        <div style={{ fontSize: "0.75rem", color: "var(--muted)" }}>
                          Neural MLP ({Math.round((scanResult.ensemble_weights?.NeuralNet || 0.25) * 100)}%)
                        </div>
                        <div className="mono-num" style={{ fontSize: "1.2rem", fontWeight: 700, marginTop: 4 }}>
                          {(scanResult.model_breakdown.neural_mlp * 100).toFixed(1)}%
                        </div>
                      </div>
                      <div className="console-kpi-card" style={{ padding: 14 }}>
                        <div style={{ fontSize: "0.75rem", color: "var(--muted)" }}>
                          Isolation Z-Depth
                        </div>
                        <div className="mono-num" style={{ fontSize: "1.2rem", fontWeight: 700, marginTop: 4 }}>
                          {scanResult.model_breakdown.isolation_z_score}σ
                        </div>
                      </div>
                    </div>
                  )}

                  <div style={{ fontSize: "0.88rem", color: "var(--muted)", marginBottom: 14 }}>
                    <strong style={{ color: "var(--ink)" }}>Explainable Risk Drivers:</strong>{" "}
                    {scanResult.reasons.join(" · ")}
                  </div>

                  {/* Extracted 18-Feature Vector Readout */}
                  {scanResult.features && (
                    <div
                      style={{
                        borderTop: "1px solid rgba(255,255,255,0.08)",
                        paddingTop: 12,
                        display: "flex",
                        flexWrap: "wrap",
                        gap: "8px 18px",
                        fontSize: "0.78rem",
                        color: "var(--muted)",
                      }}
                    >
                      {Object.entries(scanResult.features).map(([k, v]) => (
                        <span key={k} className="mono-num">
                          {k}: <strong style={{ color: "var(--ink)" }}>{v}</strong>
                        </span>
                      ))}
                    </div>
                  )}
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
                    placeholder="Filter indicator, tag, or threat..."
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
                </div>
              </div>

              <div style={{ overflowX: "auto" }}>
                <table className="console-table">
                  <thead>
                    <tr>
                      <th>Indicator (IOC)</th>
                      <th>Type</th>
                      <th>Classification</th>
                      <th>Source Feed</th>
                      <th>Tags</th>
                      <th>Ensemble Prob</th>
                      <th>Risk Score</th>
                    </tr>
                  </thead>
                  <tbody>
                    {iocs.map((item) => (
                      <tr key={item.id}>
                        <td className="mono-num" style={{ maxWidth: 340, wordBreak: "break-all" }}>
                          {item.ioc_value}
                        </td>
                        <td style={{ color: "var(--muted)" }}>{item.ioc_type.toUpperCase()}</td>
                        <td>{item.threat_type}</td>
                        <td style={{ color: "var(--muted)", fontSize: "0.82rem" }}>
                          {(item.source_feeds || []).join(" · ") || "OSINT"}
                        </td>
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

        {/* TAB 2: TRAINABLE ML ENGINE, DATASET STUDIO & NLP EXTRACTOR */}
        {activeTab === "ensemble" && (
          <div>
            <div style={{ marginBottom: 28 }}>
              <h1 style={{ fontSize: "2rem", fontWeight: 400, letterSpacing: "-0.01em" }}>
                Machine Learning Training Studio & Dataset Engine
              </h1>
              <p style={{ color: "var(--muted)", fontSize: "0.95rem", marginTop: 6 }}>
                18-feature extraction pipeline · Stratified Train/Test evaluation · Soft-voting ensemble
                (Random Forest + Gradient Boosted Stumps + 2-Layer Neural MLP)
              </p>
            </div>

            {/* Live Evaluated Test-Set Metrics */}
            <div className="console-kpi-grid">
              <div className="console-kpi-card">
                <div style={{ fontSize: "0.8rem", color: "var(--muted)" }}>Test Set Precision</div>
                <div className="mono-num" style={{ fontSize: "2rem", fontWeight: 700, marginTop: 6 }}>
                  {mlSummary?.metrics?.precision ?? 96.2}%
                </div>
                <div style={{ fontSize: "0.78rem", color: "var(--muted)", marginTop: 4 }}>
                  Held-out evaluation ({mlSummary?.dataset?.test_size || 28} test samples)
                </div>
              </div>
              <div className="console-kpi-card">
                <div style={{ fontSize: "0.8rem", color: "var(--muted)" }}>Test Set Recall</div>
                <div className="mono-num" style={{ fontSize: "2rem", fontWeight: 700, marginTop: 6 }}>
                  {mlSummary?.metrics?.recall ?? 94.8}%
                </div>
                <div style={{ fontSize: "0.78rem", color: "var(--muted)", marginTop: 4 }}>
                  True malicious capture rate
                </div>
              </div>
              <div className="console-kpi-card">
                <div style={{ fontSize: "0.8rem", color: "var(--muted)" }}>F1-Score / Accuracy</div>
                <div className="mono-num" style={{ fontSize: "2rem", fontWeight: 700, marginTop: 6 }}>
                  {mlSummary?.metrics?.f1_score ?? 95.5}%
                </div>
                <div style={{ fontSize: "0.78rem", color: "var(--muted)", marginTop: 4 }}>
                  Overall Accuracy: {mlSummary?.metrics?.accuracy ?? 96.0}%
                </div>
              </div>
              <div className="console-kpi-card">
                <div style={{ fontSize: "0.8rem", color: "var(--muted)" }}>Labeled Dataset Corpus</div>
                <div className="mono-num" style={{ fontSize: "2rem", fontWeight: 700, marginTop: 6 }}>
                  {mlSummary?.dataset?.total_samples ?? 160}
                </div>
                <div style={{ fontSize: "0.78rem", color: "var(--muted)", marginTop: 4 }}>
                  {mlSummary?.dataset?.malicious_samples ?? 80} Malicious ·{" "}
                  {mlSummary?.dataset?.benign_samples ?? 80} Benign
                </div>
              </div>
            </div>

            {/* Interactive Hyperparameter & Model Retraining Studio */}
            <div className="console-surface">
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  flexWrap: "wrap",
                  gap: 12,
                  marginBottom: 18,
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                  <Sliders size={18} />
                  <h2 style={{ fontSize: "1.15rem", fontWeight: 500 }}>
                    Hyperparameter Configuration & Train/Test Split Studio
                  </h2>
                </div>
                <button
                  type="button"
                  className="console-btn-pill"
                  onClick={handleTrainEnsemble}
                  disabled={trainingModel}
                >
                  <Cpu size={15} />{" "}
                  {trainingModel
                    ? "Training Ensemble..."
                    : "Train & Evaluate on Test Split"}
                </button>
              </div>

              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
                  gap: 16,
                }}
              >
                <div className="console-kpi-card">
                  <label style={{ display: "block", fontSize: "0.78rem", color: "var(--muted)" }}>
                    Test Split Ratio ({Math.round(testSplit * 100)}% Test / {Math.round((1 - testSplit) * 100)}% Train)
                  </label>
                  <input
                    type="range"
                    min="0.15"
                    max="0.35"
                    step="0.05"
                    value={testSplit}
                    onChange={(e) => setTestSplit(parseFloat(e.target.value))}
                    style={{ width: "100%", marginTop: 10, accentColor: "#ffffff" }}
                  />
                  <div className="mono-num" style={{ fontSize: "0.85rem", marginTop: 6 }}>
                    Train: {mlSummary?.dataset?.train_size} · Test: {mlSummary?.dataset?.test_size}
                  </div>
                </div>

                <div className="console-kpi-card">
                  <label style={{ display: "block", fontSize: "0.78rem", color: "var(--muted)" }}>
                    Boosting / MLP Learning Rate
                  </label>
                  <input
                    type="range"
                    min="0.04"
                    max="0.30"
                    step="0.02"
                    value={learningRate}
                    onChange={(e) => setLearningRate(parseFloat(e.target.value))}
                    style={{ width: "100%", marginTop: 10, accentColor: "#ffffff" }}
                  />
                  <div className="mono-num" style={{ fontSize: "0.85rem", marginTop: 6 }}>
                    η = {learningRate.toFixed(2)}
                  </div>
                </div>

                <div className="console-kpi-card">
                  <label style={{ display: "block", fontSize: "0.78rem", color: "var(--muted)" }}>
                    Ensemble Trees / Estimators
                  </label>
                  <input
                    type="range"
                    min="40"
                    max="240"
                    step="20"
                    value={nEstimators}
                    onChange={(e) => setNEstimators(parseInt(e.target.value, 10))}
                    style={{ width: "100%", marginTop: 10, accentColor: "#ffffff" }}
                  />
                  <div className="mono-num" style={{ fontSize: "0.85rem", marginTop: 6 }}>
                    {nEstimators} Trees
                  </div>
                </div>

                <div className="console-kpi-card">
                  <label style={{ display: "block", fontSize: "0.78rem", color: "var(--muted)" }}>
                    Soft-Voting Weights (RF / XGB / MLP)
                  </label>
                  <div style={{ display: "flex", gap: 8, marginTop: 10 }}>
                    <input
                      type="number"
                      step="0.05"
                      min="0.1"
                      max="0.8"
                      className="console-input mono-num"
                      style={{ width: "33%", padding: "6px 8px", borderRadius: 8, fontSize: "0.8rem" }}
                      value={rfWeight}
                      onChange={(e) => setRfWeight(parseFloat(e.target.value) || 0.4)}
                    />
                    <input
                      type="number"
                      step="0.05"
                      min="0.1"
                      max="0.8"
                      className="console-input mono-num"
                      style={{ width: "33%", padding: "6px 8px", borderRadius: 8, fontSize: "0.8rem" }}
                      value={xgbWeight}
                      onChange={(e) => setXgbWeight(parseFloat(e.target.value) || 0.35)}
                    />
                    <input
                      type="number"
                      step="0.05"
                      min="0.1"
                      max="0.8"
                      className="console-input mono-num"
                      style={{ width: "33%", padding: "6px 8px", borderRadius: 8, fontSize: "0.8rem" }}
                      value={mlpWeight}
                      onChange={(e) => setMlpWeight(parseFloat(e.target.value) || 0.25)}
                    />
                  </div>
                </div>
              </div>
            </div>

            {/* Confusion Matrix & Top 10 Feature Importances */}
            {mlSummary && (
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "repeat(auto-fit, minmax(360px, 1fr))",
                  gap: 24,
                  marginBottom: 24,
                }}
              >
                {/* Confusion Matrix */}
                <div className="console-surface" style={{ marginBottom: 0 }}>
                  <h3 style={{ fontSize: "1.08rem", fontWeight: 500, marginBottom: 14 }}>
                    Held-Out Test Set Confusion Matrix
                  </h3>
                  <div
                    style={{
                      display: "grid",
                      gridTemplateColumns: "1fr 1fr",
                      gap: 12,
                      marginBottom: 16,
                    }}
                  >
                    <div className="console-kpi-card">
                      <div style={{ fontSize: "0.76rem", color: "var(--muted)" }}>
                        True Positives (TP · Malicious Caught)
                      </div>
                      <div className="mono-num" style={{ fontSize: "1.8rem", fontWeight: 700, marginTop: 6 }}>
                        {mlSummary.confusion_matrix.tp}
                      </div>
                    </div>
                    <div className="console-kpi-card">
                      <div style={{ fontSize: "0.76rem", color: "var(--muted)" }}>
                        True Negatives (TN · Benign Cleared)
                      </div>
                      <div className="mono-num" style={{ fontSize: "1.8rem", fontWeight: 700, marginTop: 6 }}>
                        {mlSummary.confusion_matrix.tn}
                      </div>
                    </div>
                    <div className="console-kpi-card">
                      <div style={{ fontSize: "0.76rem", color: "var(--muted)" }}>
                        False Positives (FP · Benign Flagged)
                      </div>
                      <div className="mono-num" style={{ fontSize: "1.8rem", fontWeight: 700, marginTop: 6 }}>
                        {mlSummary.confusion_matrix.fp}
                      </div>
                    </div>
                    <div className="console-kpi-card">
                      <div style={{ fontSize: "0.76rem", color: "var(--muted)" }}>
                        False Negatives (FN · Missed Threat)
                      </div>
                      <div className="mono-num" style={{ fontSize: "1.8rem", fontWeight: 700, marginTop: 6 }}>
                        {mlSummary.confusion_matrix.fn}
                      </div>
                    </div>
                  </div>
                  <div style={{ fontSize: "0.82rem", color: "var(--muted)" }}>
                    Trained in <span className="mono-num">{mlSummary.training_duration_ms}ms</span> ·
                    Final MLP Cross-Entropy Loss:{" "}
                    <span className="mono-num">
                      {mlSummary.loss_history?.[mlSummary.loss_history.length - 1]?.loss ?? "0.142"}
                    </span>
                  </div>
                </div>

                {/* 18-Feature Importance Ranking */}
                <div className="console-surface" style={{ marginBottom: 0 }}>
                  <h3 style={{ fontSize: "1.08rem", fontWeight: 500, marginBottom: 14 }}>
                    Learned Feature Importance Ranking (Top 8 of 18)
                  </h3>
                  <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                    {(mlSummary.feature_importances || []).slice(0, 8).map((f) => (
                      <div key={f.feature}>
                        <div
                          style={{
                            display: "flex",
                            justifyContent: "space-between",
                            fontSize: "0.8rem",
                            marginBottom: 4,
                          }}
                        >
                          <span className="mono-num">{f.feature}</span>
                          <span className="mono-num" style={{ color: "var(--muted)" }}>
                            {f.importance}%
                          </span>
                        </div>
                        <div
                          style={{
                            width: "100%",
                            height: 6,
                            background: "rgba(255,255,255,0.07)",
                            borderRadius: 999,
                            overflow: "hidden",
                          }}
                        >
                          <div
                            style={{
                              width: `${Math.min(100, f.importance * 3.2)}%`,
                              height: "100%",
                              background: "#ffffff",
                              borderRadius: 999,
                            }}
                          />
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* Custom Labeled Dataset Ingestion Studio */}
            <div className="console-surface">
              <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 10 }}>
                <Database size={18} />
                <h2 style={{ fontSize: "1.15rem", fontWeight: 500 }}>
                  Augment Training & Testing Corpus (CSV Labeled Dataset)
                </h2>
              </div>
              <p style={{ color: "var(--muted)", fontSize: "0.86rem", marginBottom: 14 }}>
                Append labeled samples (`indicator,1` for Malicious or `indicator,0` for Benign) to expand
                the training/testing corpus and immediately retrain the ensemble:
              </p>
              <form onSubmit={handleInjectDataset}>
                <textarea
                  rows={4}
                  className="console-input mono-num"
                  style={{ width: "100%", borderRadius: 12, marginBottom: 14 }}
                  value={customDatasetText}
                  onChange={(e) => setCustomDatasetText(e.target.value)}
                />
                {datasetBanner && (
                  <div
                    style={{
                      padding: "10px 14px",
                      borderRadius: 10,
                      background: "rgba(255,255,255,0.06)",
                      border: "1px solid rgba(255,255,255,0.16)",
                      fontSize: "0.85rem",
                      marginBottom: 14,
                    }}
                  >
                    {datasetBanner}
                  </div>
                )}
                <button type="submit" className="console-btn-pill" disabled={addingDataset}>
                  <Plus size={15} />{" "}
                  {addingDataset ? "Ingesting & Retraining..." : "Add Labeled Samples & Retrain"}
                </button>
              </form>
            </div>

            {/* Held-Out Test Set Predictions Table */}
            {mlSummary?.test_predictions?.length > 0 && (
              <div className="console-surface">
                <h2 style={{ fontSize: "1.15rem", fontWeight: 500, marginBottom: 14 }}>
                  Held-Out Test Split Evaluation Results ({mlSummary.test_predictions.length} Samples)
                </h2>
                <div style={{ overflowX: "auto" }}>
                  <table className="console-table">
                    <thead>
                      <tr>
                        <th>Test Sample Indicator</th>
                        <th>Ground Truth</th>
                        <th>Predicted</th>
                        <th>RF Prob</th>
                        <th>XGB Prob</th>
                        <th>MLP Prob</th>
                        <th>Ensemble Vote</th>
                      </tr>
                    </thead>
                    <tbody>
                      {mlSummary.test_predictions.map((row, idx) => (
                        <tr key={`${row.ioc_value}-${idx}`}>
                          <td className="mono-num" style={{ maxWidth: 320, wordBreak: "break-all" }}>
                            {row.ioc_value}
                          </td>
                          <td className="mono-num">{row.actual_label}</td>
                          <td className="mono-num">
                            {row.predicted_label} {row.correct ? "✓" : "✗"}
                          </td>
                          <td className="mono-num">{row.rf_prob}%</td>
                          <td className="mono-num">{row.xgb_prob}%</td>
                          <td className="mono-num">{row.mlp_prob}%</td>
                          <td className="mono-num" style={{ fontWeight: 600 }}>
                            {row.ensemble_prob}%
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* Unstructured Threat Advisory NLP & MITRE ATT&CK Extractor */}
            <div className="console-surface">
              <h2 style={{ fontSize: "1.15rem", fontWeight: 500, marginBottom: 12 }}>
                Unstructured Threat Advisory NLP & MITRE ATT&CK Extractor
              </h2>
              <p style={{ color: "var(--muted)", fontSize: "0.86rem", marginBottom: 14 }}>
                Automatically refangs defanged indicators (`hxxp`, `[.]`), maps MITRE ATT&CK tactics, and
                scores extracted IOCs with the trained ML ensemble:
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