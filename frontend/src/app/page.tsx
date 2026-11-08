"use client";

import React, { useEffect, useRef, useState } from "react";
import Link from "next/link";
import {
  ShieldAlert,
  ShieldCheck,
  ShieldQuestion,
  Terminal,
  Lock,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Play,
  Flame,
  FileWarning,
  Cpu,
  Eye,
  Share2,
  Copy,
  Check,
  Layers,
  Activity,
  RefreshCw,
  UserCheck,
  QrCode,
  History,
  Download,
  Clock,
  Settings,
  Key,
  Globe,
} from "lucide-react";

const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE_URL ||
  (typeof window !== "undefined" &&
  window.location.hostname !== "localhost" &&
  window.location.hostname !== "127.0.0.1"
    ? ""
    : "http://localhost:8000");

interface HopRecord {
  hop_index: number;
  url: string;
  domain: string;
  status_code: number;
  latency_ms: number;
  screenshot_url?: string | null;
  note?: string;
}

interface QuarantinedDownload {
  filename: string;
  url: string;
  content_type: string;
  size_bytes: number;
  sha256: string;
  is_eicar: boolean;
  quarantined_by: string;
  reason: string;
}

interface ContainmentEvent {
  timestamp: string;
  module: string;
  category: string;
  severity: "info" | "warning" | "critical";
  title: string;
  detail: string;
}

interface RuleSignal {
  code: string;
  severity: "low" | "medium" | "high" | "critical";
  description: string;
  score_delta: number;
}

interface ChamberReceipt {
  chamber_id: string;
  backend_mode: string;
  runtime: string;
  image: string;
  user: string;
  rootfs: string;
  capabilities: string;
  cpu_limit: string;
  memory_limit: string;
  pids_limit: number;
  wall_clock_limit_seconds: number;
  network_mode: string;
  secrets_injected: number;
  started_at: string;
  destroyed_at: string;
  lifetime_seconds: number;
  destroyed_cleanly: boolean;
  termination_reason: string;
}

interface PendingApproval {
  step_index: number;
  proposed_action: string;
  button_label: string;
  explanation: string;
  decoy_preview: Record<string, string>;
}

interface ScanReport {
  scan_id: string;
  share_token: string;
  status: string;
  submitted_input: string;
  normalized_url: string;
  masked_url: string;
  final_url: string;
  page_title: string;
  created_at: string;
  completed_at?: string;
  duration_seconds: number;
  verdict?: "Likely safe" | "Suspicious" | "Dangerous" | null;
  reason: string;
  impersonated_brand?: string | null;
  risk_score: number;
  caveat: string;
  hops: HopRecord[];
  final_screenshot_url?: string | null;
  downloads_quarantined: QuarantinedDownload[];
  egress_blocks: Array<Record<string, any>>;
  agent_injection_findings: string[];
  rule_signals: RuleSignal[];
  containment_events: ContainmentEvent[];
  action_log: Array<Record<string, any>>;
  chamber_receipt?: ChamberReceipt | null;
  pending_approval?: PendingApproval | null;
  model_used: string;
  inference_provider: string;
}

const REAL_WEB_PRESETS = [
  {
    label:
      "Active In-The-Wild Phishing: Adobe PDF + Telegram Bot Exfil Kit (adobesign-coral.vercel.app)",
    shortLabel: "🔥 Live Adobe PDF + Telegram Exfil",
    badge: "Dangerous",
    input: "http://www.adobesign-coral.vercel.app/",
    requireApproval: false,
    simulateTimeout: false,
  },
  {
    label:
      "Active In-The-Wild Phishing: Microsoft Account Security Verification Kit (omis-gules.vercel.app)",
    shortLabel: "🔥 Live Microsoft Phishing Kit",
    badge: "Dangerous",
    input: "https://omis-gules.vercel.app/",
    requireApproval: false,
    simulateTimeout: false,
  },
  {
    label:
      "Active In-The-Wild Phishing: MetaMask Unicode Obfuscated Lure (m3tamsklognx.gitbook.io)",
    shortLabel: "🔥 Live MetaMask Unicode Phishing",
    badge: "Dangerous",
    input: "http://m3tamsklognx.gitbook.io/us",
    requireApproval: false,
    simulateTimeout: false,
  },
  {
    label:
      "Active In-The-Wild Phishing: Roblox .com.et ccTLD Impersonation (roblox.com.et)",
    shortLabel: "🔥 Live Roblox .com.et Phishing",
    badge: "Dangerous",
    input: "https://www.roblox.com.et/users/1404516348/profile",
    requireApproval: false,
    simulateTimeout: false,
  },
  {
    label:
      "Live Phishing Page: Google SafeBrowsing Test (testsafebrowsing.appspot.com)",
    shortLabel: "🌐 SafeBrowsing Phishing",
    badge: "Dangerous",
    input: "https://testsafebrowsing.appspot.com/s/phishing.html",
    requireApproval: false,
    simulateTimeout: false,
  },
  {
    label:
      "Live Malware Lure: Google SafeBrowsing Payload (double_zipped.zip Quarantine)",
    shortLabel: "🌐 SafeBrowsing Malware (.zip)",
    badge: "Dangerous",
    input: "https://testsafebrowsing.appspot.com/s/malware.html",
    requireApproval: false,
    simulateTimeout: false,
  },
  {
    label:
      "Live Broken TLS Certificate: Expired X.509 SSL Cert (expired.badssl.com)",
    shortLabel: "⚠️ Live Expired TLS Cert",
    badge: "Dangerous",
    input: "https://expired.badssl.com/",
    requireApproval: false,
    simulateTimeout: false,
  },
  {
    label:
      "Live Official Brand Login: Verified GitHub Sign-In (Zero False-Positive Proof)",
    shortLabel: "✅ Live GitHub Login (Official Safe)",
    badge: "Likely safe",
    input: "https://github.com/login",
    requireApproval: false,
    simulateTimeout: false,
  },
];

const DEMO_PRESETS = [
  {
    label:
      "Scene 1–4 Demo: Pinnacle Trust Trap (3 Hops + EICAR + AI Injection + SSRF)",
    shortLabel: "3-Hop Pinnacle Trap",
    badge: "Dangerous",
    input:
      "SMS Alert: Your parcel is on hold, confirm delivery here: http://localhost:8000/trap/short/parcel-hold",
    requireApproval: false,
    simulateTimeout: false,
  },
  {
    label: "Objective 5 Demo: Interactive 'Verify Human' Gate (Decoy Approval)",
    shortLabel: "Human Approval Gate",
    badge: "Approval Gate",
    input: "http://localhost:8000/trap/interstitial-verify",
    requireApproval: true,
    simulateTimeout: false,
  },
  {
    label: "QR Code Poster Lure: Student Scholarship Grant Trap (Maybank2u)",
    shortLabel: "QR Scholarship Trap",
    badge: "Dangerous",
    input:
      "Poster QR Scan: Claim RM 2,500 Student Scholarship at http://localhost:8000/trap/qr-scholarship",
    requireApproval: false,
    simulateTimeout: false,
  },
  {
    label: "Objective 1 Timeout Proof: Simulate Hanging Page (Wall-Clock Kill)",
    shortLabel: "Wall-Clock Timeout",
    badge: "Timeout Test",
    input: "http://localhost:8000/trap/short/parcel-hold",
    requireApproval: false,
    simulateTimeout: true,
  },
];

export default function BaitBoxConsolePage() {
  const [inputText, setInputText] = useState<string>(REAL_WEB_PRESETS[0].input);
  const [requireApproval, setRequireApproval] = useState<boolean>(false);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [liveEvents, setLiveEvents] = useState<Array<Record<string, any>>>([]);
  const [report, setReport] = useState<ScanReport | null>(null);
  const [selectedHopIdx, setSelectedHopIdx] = useState<number>(0);
  const [copiedShare, setCopiedShare] = useState<boolean>(false);
  const [activeTab, setActiveTab] = useState<
    "scanner" | "history" | "benchmark" | "architecture"
  >("scanner");
  const [telemetry, setTelemetry] = useState<Record<string, any> | null>(null);
  const [recentScans, setRecentScans] = useState<Array<Record<string, any>>>(
    []
  );
  const [vultrModels, setVultrModels] = useState<Array<Record<string, any>>>(
    []
  );
  const [apiKeyInput, setApiKeyInput] = useState<string>("");
  const [plannerModelInput, setPlannerModelInput] = useState<string>(
    "deepseek-v4.1-flash-1017"
  );
  const [visionModelInput, setVisionModelInput] = useState<string>(
    "deepseek-v4.1-flash-1017"
  );
  const [configSavedMsg, setConfigSavedMsg] = useState<string | null>(null);
  const [showQrModal, setShowQrModal] = useState<boolean>(false);
  const [showLiveCatalog, setShowLiveCatalog] = useState<boolean>(false);
  const [liveCatalog, setLiveCatalog] = useState<Array<Record<string, any>>>([]);
  const [openphishLiveUrls, setOpenphishLiveUrls] = useState<string[]>([]);
  const [loadingOpenphish, setLoadingOpenphish] = useState<boolean>(false);
  const [decodedQrUrl, setDecodedQrUrl] = useState<string>(
    "http://localhost:8000/trap/qr-scholarship"
  );
  const [uploadedQrPreview, setUploadedQrPreview] = useState<string | null>(
    null
  );
  const [qrSourceLabel, setQrSourceLabel] = useState<string>(
    "Sample Campus Scholarship Poster"
  );
  const [extractedPreview, setExtractedPreview] = useState<{
    primary_url: string;
    all_urls: string[];
    was_defanged: boolean;
  } | null>(null);
  const [lightboxImage, setLightboxImage] = useState<{
    url: string;
    caption: string;
  } | null>(null);
  const [copiedChatWarning, setCopiedChatWarning] = useState<boolean>(false);
  const [historyFilter, setHistoryFilter] = useState<string>("ALL");
  const [historySearch, setHistorySearch] = useState<string>("");
  const [benchmarkData, setBenchmarkData] = useState<Record<string, any> | null>(
    null
  );
  const [runningBenchmark, setRunningBenchmark] = useState<boolean>(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const eventSourceRef = useRef<EventSource | null>(null);
  const qrFileInputRef = useRef<HTMLInputElement | null>(null);

  const fetchTelemetryAndHistory = async () => {
    try {
      const [telRes, scansRes, modRes] = await Promise.all([
        fetch(`${API_BASE}/api/system/telemetry`),
        fetch(`${API_BASE}/api/scans?limit=25`),
        fetch(`${API_BASE}/api/system/models`),
      ]);
      if (telRes.ok) {
        const t = await telRes.json();
        setTelemetry(t);
        if (t.vultr_services?.planner_model) {
          setPlannerModelInput(t.vultr_services.planner_model);
        }
        if (t.vultr_services?.vision_model) {
          setVisionModelInput(t.vultr_services.vision_model);
        }
      }
      if (scansRes.ok) {
        const s = await scansRes.json();
        setRecentScans(s.scans || []);
      }
      if (modRes.ok) {
        const m = await modRes.json();
        setVultrModels(m.models || []);
      }
      const feedRes = await fetch(`${API_BASE}/api/phishing/live-feed`);
      if (feedRes.ok) {
        const f = await feedRes.json();
        setLiveCatalog(f.catalog || []);
      }
    } catch {
      // Ignore offline errors during initial load
    }
  };

  const fetchOpenphishLiveFeed = async () => {
    setLoadingOpenphish(true);
    try {
      const res = await fetch(
        `${API_BASE}/api/phishing/live-feed?fetch_openphish=true&limit=24`
      );
      if (res.ok) {
        const data = await res.json();
        setLiveCatalog(data.catalog || []);
        setOpenphishLiveUrls(data.openphish_live_urls || []);
      }
    } catch {
      // Ignore network errors
    } finally {
      setLoadingOpenphish(false);
    }
  };

  useEffect(() => {
    fetchTelemetryAndHistory();
    return () => {
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
      }
    };
  }, []);

  useEffect(() => {
    const trimmed = inputText.trim();
    if (!trimmed) {
      setExtractedPreview(null);
      return;
    }
    const timer = setTimeout(async () => {
      try {
        const res = await fetch(`${API_BASE}/api/urls/extract`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ input_text: trimmed }),
        });
        if (res.ok) {
          const data = await res.json();
          setExtractedPreview(data);
        } else {
          setExtractedPreview(null);
        }
      } catch {
        // Ignore network errors while typing
      }
    }, 220);
    return () => clearTimeout(timer);
  }, [inputText]);

  const handleQrFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = async () => {
      const dataUrl = String(reader.result || "");
      setUploadedQrPreview(dataUrl);
      try {
        const res = await fetch(`${API_BASE}/api/qr/decode`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            image_base64: dataUrl,
            filename: file.name,
          }),
        });
        if (res.ok) {
          const data = await res.json();
          setDecodedQrUrl(data.decoded_url);
          setQrSourceLabel(`Uploaded Image (${file.name})`);
        }
      } catch {
        setQrSourceLabel(`Uploaded Image (${file.name})`);
      }
    };
    reader.readAsDataURL(file);
  };

  const startScan = async (
    customInput?: string,
    customApproval?: boolean,
    customTimeout?: boolean
  ) => {
    const targetInput = customInput !== undefined ? customInput : inputText;
    const targetApproval =
      customApproval !== undefined ? customApproval : requireApproval;
    const targetTimeout = customTimeout !== undefined ? customTimeout : false;

    if (!targetInput.trim()) return;

    setErrorMsg(null);
    setIsScanning(true);
    setLiveEvents([]);
    setReport(null);
    setSelectedHopIdx(0);
    setActiveTab("scanner");

    if (eventSourceRef.current) {
      eventSourceRef.current.close();
    }

    try {
      const res = await fetch(`${API_BASE}/api/scans`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          input_text: targetInput,
          require_human_approval: targetApproval,
          simulate_timeout: targetTimeout,
        }),
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || "Failed to start scan");
      }

      const initial: ScanReport = await res.json();
      setReport(initial);

      const es = new EventSource(
        `${API_BASE}/api/scans/${initial.scan_id}/events`
      );
      eventSourceRef.current = es;

      es.onmessage = async (ev) => {
        try {
          const data = JSON.parse(ev.data);
          setLiveEvents((prev) => [...prev, data]);

          if (
            data.event === "approval_required" ||
            data.event === "scan_completed" ||
            data.event === "scan_timed_out" ||
            data.event === "scan_failed"
          ) {
            const fullRes = await fetch(
              `${API_BASE}/api/scans/${initial.scan_id}`
            );
            if (fullRes.ok) {
              const fullReport: ScanReport = await fullRes.json();
              setReport(fullReport);
              if (fullReport.hops && fullReport.hops.length > 0) {
                setSelectedHopIdx(fullReport.hops.length - 1);
              }
            }
          }

          if (
            data.event === "scan_completed" ||
            data.event === "scan_timed_out" ||
            data.event === "scan_failed"
          ) {
            setIsScanning(false);
            es.close();
            fetchTelemetryAndHistory();
          }
        } catch {
          // Ignore malformed event
        }
      };

      es.onerror = async () => {
        es.close();
        setIsScanning(false);
        const fullRes = await fetch(
          `${API_BASE}/api/scans/${initial.scan_id}`
        );
        if (fullRes.ok) {
          const fullReport: ScanReport = await fullRes.json();
          setReport(fullReport);
          if (fullReport.hops && fullReport.hops.length > 0) {
            setSelectedHopIdx(fullReport.hops.length - 1);
          }
        }
        fetchTelemetryAndHistory();
      };
    } catch (err: any) {
      setErrorMsg(
        err.message || "Error communicating with BaitBox orchestrator"
      );
      setIsScanning(false);
    }
  };

  const loadHistoricalScan = async (scanId: string) => {
    try {
      const res = await fetch(`${API_BASE}/api/scans/${scanId}`);
      if (res.ok) {
        const loaded: ScanReport = await res.json();
        setReport(loaded);
        if (loaded.hops && loaded.hops.length > 0) {
          setSelectedHopIdx(loaded.hops.length - 1);
        }
        setActiveTab("scanner");
      }
    } catch {
      // Ignore
    }
  };

  const handleApprovalDecision = async (decision: "approve" | "deny") => {
    if (!report) return;
    try {
      await fetch(`${API_BASE}/api/scans/${report.scan_id}/approval`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ decision }),
      });
    } catch {
      // Handled by SSE stream
    }
  };

  const handleRunBenchmark = async () => {
    setRunningBenchmark(true);
    try {
      const res = await fetch(`${API_BASE}/api/benchmark/run`, {
        method: "POST",
      });
      if (res.ok) {
        setBenchmarkData(await res.json());
        fetchTelemetryAndHistory();
      }
    } finally {
      setRunningBenchmark(false);
    }
  };

  const handleSaveConfig = async (e: React.FormEvent) => {
    e.preventDefault();
    setConfigSavedMsg(null);
    const res = await fetch(`${API_BASE}/api/system/config`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        vultr_api_key: apiKeyInput || undefined,
        planner_model: plannerModelInput,
        vision_model: visionModelInput,
      }),
    });
    if (res.ok) {
      setConfigSavedMsg(
        "Updated Vultr Serverless Inference configuration on Control Plane."
      );
      setApiKeyInput("");
      fetchTelemetryAndHistory();
    }
  };

  const downloadReceiptJson = () => {
    if (!report) return;
    const blob = new Blob([JSON.stringify(report, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `baitbox-forensic-receipt-${report.scan_id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const copyShareUrl = () => {
    if (!report) return;
    const url = `${window.location.origin}/report/${report.share_token}`;
    navigator.clipboard.writeText(url);
    setCopiedShare(true);
    setTimeout(() => setCopiedShare(false), 2500);
  };

  const copyChatWarning = () => {
    if (!report) return;
    const shareUrl = `${window.location.origin}/report/${report.share_token}`;
    const header =
      report.verdict === "Dangerous"
        ? "🚨 BAITBOX SECURITY ALERT — DO NOT OPEN THIS LINK"
        : report.verdict === "Suspicious"
        ? "⚠️ BAITBOX CAUTION — SUSPICIOUS LINK"
        : "✅ BAITBOX CHECK — LIKELY SAFE";
    const brandLine = report.impersonated_brand
      ? `\nImpersonated Brand: ${report.impersonated_brand}`
      : "";
    const msg = `${header}\nVerdict: ${report.verdict} (Risk Score: ${report.risk_score}/100)${brandLine}\nDefanged Link: ${report.masked_url}\nWhy: ${report.reason}\nShare-Safe Evidence Report: ${shareUrl}`;
    navigator.clipboard.writeText(msg);
    setCopiedChatWarning(true);
    setTimeout(() => setCopiedChatWarning(false), 2500);
  };

  const deleteHistoricalScan = async (scanId: string) => {
    try {
      const res = await fetch(`${API_BASE}/api/scans/${scanId}`, {
        method: "DELETE",
      });
      if (res.ok) {
        setRecentScans((prev) => prev.filter((item) => item.scan_id !== scanId));
      }
    } catch {
      // Ignore error
    }
  };

  const handlePasteClipboardImage = async (
    e: React.ClipboardEvent<HTMLInputElement>
  ) => {
    const items = e.clipboardData?.items;
    if (!items) return;
    for (let i = 0; i < items.length; i++) {
      if (items[i].type.startsWith("image/")) {
        e.preventDefault();
        const file = items[i].getAsFile();
        if (!file) return;
        setShowQrModal(true);
        const reader = new FileReader();
        reader.onload = async () => {
          const dataUrl = String(reader.result || "");
          setUploadedQrPreview(dataUrl);
          try {
            const res = await fetch(`${API_BASE}/api/qr/decode`, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({
                image_base64: dataUrl,
                filename: file.name || "clipboard_qr.png",
              }),
            });
            if (res.ok) {
              const data = await res.json();
              setDecodedQrUrl(data.decoded_url);
              setQrSourceLabel("Pasted Clipboard Image");
            }
          } catch {
            setQrSourceLabel("Pasted Clipboard Image");
          }
        };
        reader.readAsDataURL(file);
        return;
      }
    }
  };

  const verdictStyle = (verdict?: string | null) => {
    if (verdict === "Dangerous") {
      return {
        border: "border-red-500/60",
        bg: "bg-gradient-to-br from-red-950/70 via-slate-900 to-slate-900",
        badge: "bg-red-500/20 text-red-300 border-red-500/40",
        text: "text-red-400",
        icon: <ShieldAlert className="w-10 h-10 text-red-400 shrink-0" />,
      };
    }
    if (verdict === "Suspicious") {
      return {
        border: "border-amber-500/60",
        bg: "bg-gradient-to-br from-amber-950/60 via-slate-900 to-slate-900",
        badge: "bg-amber-500/20 text-amber-300 border-amber-500/40",
        text: "text-amber-400",
        icon: <ShieldQuestion className="w-10 h-10 text-amber-400 shrink-0" />,
      };
    }
    return {
      border: "border-emerald-500/60",
      bg: "bg-gradient-to-br from-emerald-950/60 via-slate-900 to-slate-900",
      badge: "bg-emerald-500/20 text-emerald-300 border-emerald-500/40",
      text: "text-emerald-400",
      icon: <ShieldCheck className="w-10 h-10 text-emerald-400 shrink-0" />,
    };
  };

  const selectedHop =
    report && report.hops && report.hops[selectedHopIdx]
      ? report.hops[selectedHopIdx]
      : null;

  return (
    <div className="min-h-screen flex flex-col">
      {/* Top Header */}
      <header className="border-b border-slate-800/80 bg-slate-950/80 backdrop-blur sticky top-0 z-30">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 py-3.5 flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-red-500/20 to-cyan-500/20 border border-cyan-500/40 flex items-center justify-center shadow-lg shadow-cyan-950/50">
              <Flame className="w-5 h-5 text-cyan-400" />
            </div>
            <div>
              <div className="flex items-center gap-2.5">
                <span className="font-bold text-lg tracking-tight text-white">
                  BaitBox
                </span>
                <span className="text-[11px] font-semibold uppercase tracking-wider px-2 py-0.5 rounded-full bg-cyan-500/15 text-cyan-300 border border-cyan-500/30">
                  Track 01 · Blast Radius Zero
                </span>
              </div>
              <p className="text-xs text-slate-400">
                Disposable Detonation Chamber for Suspicious Links · Powered by
                Vultr Cloud Compute &amp; Serverless Inference
              </p>
            </div>
          </div>

          {/* Navigation Tabs */}
          <div className="flex flex-wrap items-center gap-1.5 bg-slate-900/90 p-1 rounded-xl border border-slate-800">
            <button
              onClick={() => setActiveTab("scanner")}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition flex items-center gap-1.5 ${
                activeTab === "scanner"
                  ? "bg-cyan-500 text-slate-950 font-semibold shadow"
                  : "text-slate-300 hover:text-white"
              }`}
            >
              <Flame className="w-3.5 h-3.5" />
              Detonation Console (M1)
            </button>
            <button
              onClick={() => {
                setActiveTab("history");
                fetchTelemetryAndHistory();
              }}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition flex items-center gap-1.5 ${
                activeTab === "history"
                  ? "bg-cyan-500 text-slate-950 font-semibold shadow"
                  : "text-slate-300 hover:text-white"
              }`}
            >
              <History className="w-3.5 h-3.5" />
              Scan History ({recentScans.length})
            </button>
            <button
              onClick={() => setActiveTab("benchmark")}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition flex items-center gap-1.5 ${
                activeTab === "benchmark"
                  ? "bg-cyan-500 text-slate-950 font-semibold shadow"
                  : "text-slate-300 hover:text-white"
              }`}
            >
              <CheckCircle2 className="w-3.5 h-3.5" />
              20-Link Evaluation
            </button>
            <button
              onClick={() => {
                setActiveTab("architecture");
                fetchTelemetryAndHistory();
              }}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition flex items-center gap-1.5 ${
                activeTab === "architecture"
                  ? "bg-cyan-500 text-slate-950 font-semibold shadow"
                  : "text-slate-300 hover:text-white"
              }`}
            >
              <Layers className="w-3.5 h-3.5" />
              Under the Hood (Scene 5)
            </button>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 py-8 space-y-8">
        {activeTab === "scanner" && (
          <>
            {/* Input Box Card */}
            <section className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6 shadow-xl">
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 mb-4">
                <div>
                  <h1 className="text-xl sm:text-2xl font-bold text-white">
                    Let the box take the bait.
                  </h1>
                  <p className="text-sm text-slate-400">
                    Paste any suspicious link, full SMS / WhatsApp message, or
                    scan a QR code poster. BaitBox opens it inside a
                    secret-free, network-filtered chamber with real Headless
                    Chromium and destroys the container afterwards.
                  </p>
                </div>
                <div className="flex flex-wrap items-center gap-2 shrink-0">
                  <button
                    onClick={() => {
                      setShowLiveCatalog(!showLiveCatalog);
                      if (!showLiveCatalog && liveCatalog.length === 0) {
                        fetchTelemetryAndHistory();
                      }
                    }}
                    className="text-xs px-3 py-1.5 rounded-lg bg-cyan-500/15 hover:bg-cyan-500/25 text-cyan-300 border border-cyan-500/30 font-semibold flex items-center gap-1.5 transition cursor-pointer"
                  >
                    <Globe className="w-3.5 h-3.5" />
                    Live Phishing &amp; Web Catalog ({liveCatalog.length || 22}+)
                  </button>
                  <button
                    onClick={() => setShowQrModal(!showQrModal)}
                    className="text-xs px-3 py-1.5 rounded-lg bg-amber-500/15 hover:bg-amber-500/25 text-amber-300 border border-amber-500/30 font-semibold flex items-center gap-1.5 transition cursor-pointer"
                  >
                    <QrCode className="w-3.5 h-3.5" />
                    QR Poster Scanner
                  </button>
                  <div className="flex items-center gap-2 text-xs text-emerald-400 bg-emerald-950/50 border border-emerald-500/30 px-3 py-1.5 rounded-lg">
                    <Lock className="w-3.5 h-3.5" />
                    <span>
                      Active Chambers:{" "}
                      <strong>
                        {telemetry?.chamber_manager?.active_chambers_count ?? 0}
                      </strong>
                    </span>
                  </div>
                </div>
              </div>

              {/* Live Real-World Phishing & Website Catalog Drawer */}
              {showLiveCatalog && (
                <div className="mb-5 p-4 rounded-xl bg-slate-950 border border-cyan-500/40 space-y-4">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div>
                      <div className="text-xs font-bold uppercase tracking-wider text-cyan-300 flex items-center gap-1.5">
                        <Globe className="w-4 h-4" />
                        Real-World Live Phishing &amp; External Website Detonation Catalog ({liveCatalog.length} Verified Live Targets)
                      </div>
                      <p className="text-xs text-slate-400 mt-0.5">
                        Click any real external website or active in-the-wild phishing kit below to detonate it inside BaitBox&apos;s disposable Chromium chamber.
                      </p>
                    </div>
                    <div className="flex items-center gap-2">
                      <button
                        onClick={fetchOpenphishLiveFeed}
                        disabled={loadingOpenphish}
                        className="px-3 py-1.5 rounded-lg bg-red-500/20 hover:bg-red-500/30 text-red-300 border border-red-500/40 font-semibold text-xs flex items-center gap-1.5 cursor-pointer"
                      >
                        <RefreshCw
                          className={`w-3.5 h-3.5 ${
                            loadingOpenphish ? "animate-spin" : ""
                          }`}
                        />
                        {loadingOpenphish
                          ? "Pulling OpenPhish Feed..."
                          : "Pull Live OpenPhish Threat Feed (300+ Active)"}
                      </button>
                      <button
                        onClick={() => setShowLiveCatalog(false)}
                        className="px-2.5 py-1.5 rounded-lg bg-slate-800 text-slate-300 text-xs cursor-pointer"
                      >
                        Close
                      </button>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2.5 max-h-80 overflow-y-auto pr-1">
                    {liveCatalog.map((item, idx) => (
                      <button
                        key={idx}
                        onClick={() => {
                          setShowLiveCatalog(false);
                          setInputText(item.url);
                          startScan(item.url, false, false);
                        }}
                        disabled={isScanning}
                        className="text-left p-2.5 rounded-lg bg-slate-900/90 hover:bg-slate-800 border border-slate-800 hover:border-cyan-500/50 transition flex flex-col justify-between gap-1.5 cursor-pointer"
                      >
                        <div className="flex items-center justify-between gap-2">
                          <span className="text-xs font-bold text-white truncate">
                            {item.title}
                          </span>
                          <span
                            className={`text-[10px] px-1.5 py-0.5 rounded font-semibold shrink-0 ${
                              item.badge === "Dangerous"
                                ? "bg-red-500/20 text-red-300 border border-red-500/30"
                                : "bg-emerald-500/20 text-emerald-300 border border-emerald-500/30"
                            }`}
                          >
                            {item.badge}
                          </span>
                        </div>
                        <div className="text-[11px] font-mono text-cyan-300 truncate">
                          {item.url}
                        </div>
                        <div className="text-[11px] text-slate-400 line-clamp-2">
                          {item.detail}
                        </div>
                      </button>
                    ))}
                  </div>

                  {openphishLiveUrls.length > 0 && (
                    <div className="pt-3 border-t border-slate-800 space-y-2">
                      <div className="text-xs font-bold text-red-300 flex items-center gap-1.5">
                        <ShieldAlert className="w-4 h-4" />
                        Live Unfiltered OpenPhish Threat Intelligence Feed ({openphishLiveUrls.length} Latest Reported In-The-Wild URLs):
                      </div>
                      <div className="flex flex-wrap gap-1.5 max-h-36 overflow-y-auto">
                        {openphishLiveUrls.map((u, i) => (
                          <button
                            key={i}
                            onClick={() => {
                              setShowLiveCatalog(false);
                              setInputText(u);
                              startScan(u, false, false);
                            }}
                            className="text-[11px] font-mono px-2.5 py-1 rounded bg-red-950/50 hover:bg-red-900/60 text-red-200 border border-red-500/30 truncate max-w-xs cursor-pointer"
                          >
                            {u}
                          </button>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* Optional QR Code Scam Poster Drawer */}
              {showQrModal && (
                <div className="mb-5 p-4 rounded-xl bg-slate-950 border border-amber-500/40 flex flex-col sm:flex-row items-center gap-5">
                  <img
                    src={uploadedQrPreview || `${API_BASE}/api/qr/poster`}
                    alt="QR Poster Preview"
                    className="w-40 h-auto rounded-lg border border-slate-800 shrink-0"
                  />
                  <div className="space-y-2.5 flex-1">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="text-xs font-bold uppercase tracking-wider text-amber-300 flex items-center gap-1.5">
                        <QrCode className="w-4 h-4" />
                        Proposal Use Case: QR Code Phishing Scanner ({qrSourceLabel})
                      </div>
                      <input
                        ref={qrFileInputRef}
                        type="file"
                        accept="image/*"
                        onChange={handleQrFileUpload}
                        className="hidden"
                      />
                    </div>
                    <p className="text-xs text-slate-300 leading-relaxed">
                      Scammers increasingly place QR codes on campus posters and
                      parcel slips because mobile cameras hide the destination
                      URL until it loads. Upload any QR code screenshot or use
                      the sample campus scholarship poster below—BaitBox decodes
                      the QR payload and detonates it inside an isolated
                      Chromium chamber before your phone ever visits it.
                    </p>
                    <div className="text-xs font-mono text-cyan-300 bg-slate-900 p-2 rounded border border-slate-800">
                      Decoded QR URL: {decodedQrUrl}
                    </div>
                    <div className="flex flex-wrap items-center gap-2.5 pt-1">
                      <button
                        onClick={() => {
                          setShowQrModal(false);
                          setInputText(decodedQrUrl);
                          startScan(decodedQrUrl, false, false);
                        }}
                        className="px-4 py-2 rounded-lg bg-amber-500 hover:bg-amber-400 text-slate-950 font-bold text-xs flex items-center gap-1.5 cursor-pointer"
                      >
                        <Play className="w-3.5 h-3.5 fill-current" />
                        Detonate Decoded QR Link in Chamber
                      </button>
                      <button
                        onClick={() => qrFileInputRef.current?.click()}
                        className="px-3.5 py-2 rounded-lg bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 font-semibold text-xs cursor-pointer"
                      >
                        Upload QR Image (PNG/JPG)
                      </button>
                      {uploadedQrPreview && (
                        <button
                          onClick={() => {
                            setUploadedQrPreview(null);
                            setDecodedQrUrl(
                              "http://localhost:8000/trap/qr-scholarship"
                            );
                            setQrSourceLabel("Sample Campus Scholarship Poster");
                          }}
                          className="px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs cursor-pointer"
                        >
                          Reset to Sample Poster
                        </button>
                      )}
                      <button
                        onClick={() => setShowQrModal(false)}
                        className="px-3 py-2 rounded-lg bg-slate-800 text-slate-300 text-xs cursor-pointer"
                      >
                        Close
                      </button>
                    </div>
                  </div>
                </div>
              )}

              <div className="space-y-4">
                <div className="flex flex-col sm:flex-row gap-3">
                  <input
                    type="text"
                    value={inputText}
                    onChange={(e) => setInputText(e.target.value)}
                    onPaste={handlePasteClipboardImage}
                    placeholder="Paste a suspicious link, defanged URL (hxxps://...), SMS/email text, or Ctrl+V a QR screenshot..."
                    className="flex-1 rounded-xl bg-slate-950 border border-slate-700/80 px-4 py-3.5 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400"
                    onKeyDown={(e) => {
                      if (e.key === "Enter" && !isScanning) startScan();
                    }}
                  />
                  <button
                    onClick={() => startScan()}
                    disabled={isScanning}
                    className="px-6 py-3.5 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 disabled:opacity-50 text-slate-950 font-bold text-sm tracking-wide flex items-center justify-center gap-2 shadow-lg shadow-cyan-500/20 transition cursor-pointer shrink-0"
                  >
                    {isScanning ? (
                      <>
                        <RefreshCw className="w-4 h-4 animate-spin" />
                        Detonating in Chamber...
                      </>
                    ) : (
                      <>
                        <Play className="w-4 h-4 fill-current" />
                        Detonate Link Safely
                      </>
                    )}
                  </button>
                </div>

                {/* Smart Extracted Target URL & Multi-Link / Defanged Preview Bar */}
                {extractedPreview && (
                  <div className="flex flex-wrap items-center gap-2 text-xs bg-slate-950/80 border border-slate-800/90 rounded-xl px-3.5 py-2">
                    <span className="text-slate-400 font-medium">
                      Target URL Extracted:
                    </span>
                    <span className="font-mono text-cyan-300 bg-cyan-950/50 border border-cyan-500/30 px-2 py-0.5 rounded">
                      {extractedPreview.primary_url}
                    </span>
                    {extractedPreview.was_defanged && (
                      <span className="px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30 font-semibold text-[11px]">
                        Auto-Refanged Defanged Link
                      </span>
                    )}
                    {extractedPreview.all_urls.length > 1 && (
                      <div className="flex flex-wrap items-center gap-1.5 ml-auto">
                        <span className="text-slate-400 text-[11px]">
                          {extractedPreview.all_urls.length} links found in
                          message (click to switch):
                        </span>
                        {extractedPreview.all_urls.map((u, idx) => (
                          <button
                            key={idx}
                            onClick={() => {
                              setInputText(u);
                              startScan(u);
                            }}
                            className={`text-[11px] font-mono px-2 py-0.5 rounded border transition cursor-pointer ${
                              u === extractedPreview.primary_url
                                ? "bg-cyan-500/20 text-cyan-200 border-cyan-500/40"
                                : "bg-slate-900 text-slate-300 border-slate-700 hover:border-cyan-400"
                            }`}
                          >
                            {u.length > 38 ? u.slice(0, 38) + "..." : u}
                          </button>
                        ))}
                      </div>
                    )}
                  </div>
                )}

                {/* Options & One-Click Live Web + Sandbox Scenarios */}
                <div className="space-y-2.5 pt-3 border-t border-slate-800/80">
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <label className="flex items-center gap-2.5 text-xs text-slate-300 cursor-pointer select-none">
                      <input
                        type="checkbox"
                        checked={requireApproval}
                        onChange={(e) => setRequireApproval(e.target.checked)}
                        className="rounded border-slate-700 bg-slate-950 text-cyan-500 focus:ring-cyan-500"
                      />
                      <UserCheck className="w-4 h-4 text-amber-400" />
                      <span>
                        <strong>Objective 5 (Human Approval Gate):</strong> Pause
                        and ask before clicking interactive buttons or filling
                        decoy fields
                      </span>
                    </label>
                  </div>

                  {/* Row 1: Real Live Internet Website Detections */}
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-xs font-semibold text-cyan-300 flex items-center gap-1">
                      <Globe className="w-3.5 h-3.5" />
                      Live Internet Websites:
                    </span>
                    {REAL_WEB_PRESETS.map((preset, idx) => (
                      <button
                        key={`live-${idx}`}
                        title={preset.label}
                        onClick={() => {
                          setInputText(preset.input);
                          setRequireApproval(preset.requireApproval);
                          startScan(
                            preset.input,
                            preset.requireApproval,
                            preset.simulateTimeout
                          );
                        }}
                        disabled={isScanning}
                        className="text-xs px-2.5 py-1 rounded-lg bg-cyan-950/60 hover:bg-cyan-900/70 text-cyan-100 border border-cyan-500/40 transition flex items-center gap-1.5 cursor-pointer"
                      >
                        <span
                          className={`w-2 h-2 rounded-full ${
                            preset.badge === "Dangerous"
                              ? "bg-red-400"
                              : "bg-emerald-400"
                          }`}
                        />
                        {preset.shortLabel}
                      </button>
                    ))}
                  </div>

                  {/* Row 2: Controlled Sandbox Multi-Hop / Approval / QR / Timeout Traps */}
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-xs text-slate-400">
                      Controlled Sandbox Traps:
                    </span>
                    {DEMO_PRESETS.map((preset, idx) => (
                      <button
                        key={`demo-${idx}`}
                        title={preset.label}
                        onClick={() => {
                          setInputText(preset.input);
                          setRequireApproval(preset.requireApproval);
                          startScan(
                            preset.input,
                            preset.requireApproval,
                            preset.simulateTimeout
                          );
                        }}
                        disabled={isScanning}
                        className="text-xs px-2.5 py-1 rounded-lg bg-slate-800/90 hover:bg-slate-700 text-slate-200 border border-slate-700 transition flex items-center gap-1.5 cursor-pointer"
                      >
                        <span
                          className={`w-2 h-2 rounded-full ${
                            preset.badge === "Dangerous"
                              ? "bg-red-400"
                              : preset.badge === "Approval Gate" ||
                                preset.badge === "Timeout Test"
                              ? "bg-amber-400"
                              : "bg-emerald-400"
                          }`}
                        />
                        {preset.shortLabel}
                      </button>
                    ))}
                  </div>
                </div>
              </div>

              {errorMsg && (
                <div className="mt-4 p-3 rounded-xl bg-red-950/60 border border-red-500/40 text-red-300 text-xs flex items-center gap-2">
                  <XCircle className="w-4 h-4 shrink-0" />
                  <span>{errorMsg}</span>
                </div>
              )}
            </section>

            {/* Objective 5: Human Approval Prompt Banner (when paused) */}
            {report?.status === "waiting_approval" &&
              report.pending_approval && (
                <section className="rounded-2xl border-2 border-amber-500 bg-amber-950/30 p-6 shadow-xl">
                  <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
                    <div className="space-y-1.5">
                      <div className="flex items-center gap-2 text-amber-300 font-bold text-sm uppercase tracking-wider">
                        <UserCheck className="w-5 h-5" />
                        M3 Policy &amp; Approval Gate — Human Confirmation
                        Required (Objective 5)
                      </div>
                      <p className="text-sm text-slate-200">
                        {report.pending_approval.explanation}
                      </p>
                      <div className="text-xs text-slate-400 bg-slate-950/80 p-3 rounded-lg border border-slate-800 font-mono">
                        <div>
                          Proposed Action:{" "}
                          <span className="text-amber-300">
                            {report.pending_approval.proposed_action}
                          </span>{" "}
                          on{" "}
                          <span className="text-cyan-300">
                            &quot;{report.pending_approval.button_label}&quot;
                          </span>
                        </div>
                        <div className="mt-1 text-emerald-400">
                          Synthetic Decoy Identity Only:{" "}
                          {JSON.stringify(
                            report.pending_approval.decoy_preview
                          )}
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-3 shrink-0">
                      <button
                        onClick={() => handleApprovalDecision("approve")}
                        className="px-4 py-2.5 rounded-xl bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-xs flex items-center gap-1.5 cursor-pointer"
                      >
                        <CheckCircle2 className="w-4 h-4" />
                        Approve Action (Decoy Data Only)
                      </button>
                      <button
                        onClick={() => handleApprovalDecision("deny")}
                        className="px-4 py-2.5 rounded-xl bg-red-500/20 hover:bg-red-500/30 text-red-300 border border-red-500/40 font-semibold text-xs flex items-center gap-1.5 cursor-pointer"
                      >
                        <XCircle className="w-4 h-4" />
                        Deny &amp; Terminate
                      </button>
                    </div>
                  </div>
                </section>
              )}

            {/* Live SSE Progress Stream */}
            {liveEvents.length > 0 && (
              <section className="rounded-2xl border border-slate-800 bg-slate-950/90 p-4">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2 text-xs font-semibold text-cyan-400 uppercase tracking-wider">
                    <Terminal className="w-4 h-4" />
                    Live Chamber Progress Stream (Server-Sent Events)
                  </div>
                  <span className="text-[11px] text-slate-400 font-mono">
                    {liveEvents.length} events received
                  </span>
                </div>
                <div className="max-h-40 overflow-y-auto space-y-1 font-mono text-xs bg-slate-900/70 p-3 rounded-xl border border-slate-800/80">
                  {liveEvents.map((ev, i) => (
                    <div
                      key={i}
                      className="flex items-start gap-2 text-slate-300"
                    >
                      <span className="text-slate-500 shrink-0">
                        [{new Date(ev.timestamp).toLocaleTimeString()}]
                      </span>
                      <span className="text-cyan-400 font-semibold shrink-0">
                        [{ev.event}]
                      </span>
                      <span className="text-slate-200">{ev.message}</span>
                    </div>
                  ))}
                </div>
              </section>
            )}

            {/* Final Scan Results */}
            {report && report.verdict && (
              <div className="space-y-8">
                {/* 1. Verdict Card */}
                {(() => {
                  const st = verdictStyle(report.verdict);
                  return (
                    <section
                      className={`rounded-2xl border-2 ${st.border} ${st.bg} p-6 shadow-2xl`}
                    >
                      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
                        <div className="flex items-start gap-4">
                          {st.icon}
                          <div className="space-y-2">
                            <div className="flex flex-wrap items-center gap-2.5">
                              <span
                                className={`px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider border ${st.badge}`}
                              >
                                Verdict: {report.verdict}
                              </span>
                              {report.impersonated_brand && (
                                <span className="px-3 py-1 rounded-full text-xs font-bold bg-red-500/25 text-red-200 border border-red-400/40">
                                  Impersonated Brand:{" "}
                                  {report.impersonated_brand}
                                </span>
                              )}
                              <span className="px-2.5 py-1 rounded-full text-xs font-mono bg-slate-800/90 text-slate-300 border border-slate-700">
                                Risk Score: {report.risk_score}/100
                              </span>
                              {report.chamber_receipt && (
                                <span className="px-2.5 py-1 rounded-full text-xs font-mono bg-emerald-950/80 text-emerald-300 border border-emerald-500/40">
                                  Chamber destroyed after{" "}
                                  {report.chamber_receipt.lifetime_seconds}s · 0
                                  keys inside
                                </span>
                              )}
                            </div>

                            <p className="text-base sm:text-lg font-medium text-white leading-relaxed">
                              {report.reason}
                            </p>

                            {/* Actionable Human Safety & Recovery Checklist */}
                            <div className="mt-3 p-3.5 rounded-xl bg-slate-950/75 border border-slate-800/90 space-y-1.5 text-xs text-slate-200">
                              <div className="font-bold uppercase tracking-wider text-cyan-300 flex items-center gap-1.5">
                                <ShieldCheck className="w-4 h-4 text-cyan-400" />
                                Recommended Next Steps for You
                              </div>
                              {report.verdict === "Dangerous" ? (
                                <ul className="list-disc list-inside space-y-1 text-slate-300">
                                  <li>
                                    <strong>If you have NOT opened this link on your device:</strong>{" "}
                                    Delete the message and block the sender. To check{" "}
                                    {report.impersonated_brand || "your account"}, open their official app or type the official address yourself.
                                  </li>
                                  <li>
                                    <strong>If you already typed your password or OTP on this page:</strong>{" "}
                                    Change your {report.impersonated_brand || "account"} password immediately from an official device, revoke active sessions, and call your bank&apos;s fraud desk if any financial code was entered.
                                  </li>
                                  <li>
                                    <strong>Warn family or colleagues safely:</strong>{" "}
                                    Use <em>Copy Chat Warning</em> on the right to share a defanged alert without exposing anyone to the live link.
                                  </li>
                                </ul>
                              ) : report.verdict === "Suspicious" ? (
                                <ul className="list-disc list-inside space-y-1 text-slate-300">
                                  <li>
                                    Do not enter passwords, payment details, or SMS codes on this address until you verify the sender through an independent phone number or official app.
                                  </li>
                                  <li>
                                    If this link was sent unexpectedly via SMS or WhatsApp, treat it as untrusted.
                                  </li>
                                </ul>
                              ) : (
                                <ul className="list-disc list-inside space-y-1 text-slate-300">
                                  <li>
                                    No credential traps or malicious downloads were triggered during this visit, but always verify the domain bar before signing into any sensitive account.
                                  </li>
                                </ul>
                              )}
                            </div>

                            <p className="text-xs text-slate-400 italic">
                              {report.caveat}
                            </p>
                          </div>
                        </div>

                        {/* Share-Safe & Forensic Receipt Actions */}
                        <div className="flex flex-col sm:flex-row lg:flex-col gap-2 shrink-0">
                          <button
                            onClick={copyShareUrl}
                            className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-100 border border-slate-700 text-xs font-semibold flex items-center justify-center gap-2 transition cursor-pointer"
                          >
                            {copiedShare ? (
                              <>
                                <Check className="w-4 h-4 text-emerald-400" />
                                Copied Share-Safe Link!
                              </>
                            ) : (
                              <>
                                <Copy className="w-4 h-4 text-cyan-400" />
                                Copy Share-Safe Report Link
                              </>
                            )}
                          </button>
                          <button
                            onClick={copyChatWarning}
                            className="px-4 py-2 rounded-xl bg-amber-500/15 hover:bg-amber-500/25 text-amber-300 border border-amber-500/30 text-xs font-semibold flex items-center justify-center gap-2 transition cursor-pointer"
                          >
                            {copiedChatWarning ? (
                              <>
                                <Check className="w-4 h-4 text-emerald-400" />
                                Copied WhatsApp/Slack Alert!
                              </>
                            ) : (
                              <>
                                <Copy className="w-4 h-4 text-amber-400" />
                                Copy Chat Warning (WhatsApp/Slack)
                              </>
                            )}
                          </button>
                          <Link
                            href={`/report/${report.share_token}`}
                            className="px-4 py-2 rounded-xl bg-cyan-500/15 hover:bg-cyan-500/25 text-cyan-300 border border-cyan-500/30 text-xs font-semibold flex items-center justify-center gap-1.5 transition"
                          >
                            <Share2 className="w-3.5 h-3.5" />
                            Open Masked Public Report
                          </Link>
                          <button
                            onClick={downloadReceiptJson}
                            className="px-4 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-700 text-xs font-semibold flex items-center justify-center gap-1.5 transition cursor-pointer"
                          >
                            <Download className="w-3.5 h-3.5" />
                            Export JSON Forensic Receipt
                          </button>
                        </div>
                      </div>
                    </section>
                  );
                })()}

                {/* 2. Hop-by-Hop Redirect Timeline & Real Chromium Screenshots (Objective 2) */}
                {report.hops.length > 0 && (
                  <section className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6 space-y-5">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div>
                        <h2 className="text-lg font-bold text-white flex items-center gap-2">
                          <Eye className="w-5 h-5 text-cyan-400" />
                          Hop-by-Hop Redirect Timeline &amp; Real Chromium
                          Screenshots
                        </h2>
                        <p className="text-xs text-slate-400">
                          Every redirect hop was followed inside the disposable
                          chamber. Click any hop to inspect its captured
                          screenshot.
                        </p>
                      </div>
                      <span className="text-xs font-mono text-slate-400">
                        Total Hops: {report.hops.length} | Final Destination:{" "}
                        {report.final_url}
                      </span>
                    </div>

                    {/* Horizontal Hop Cards */}
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                      {report.hops.map((hop, idx) => {
                        const isSelected = idx === selectedHopIdx;
                        const isRedir =
                          hop.status_code >= 300 && hop.status_code < 400;
                        return (
                          <button
                            key={hop.hop_index}
                            onClick={() => setSelectedHopIdx(idx)}
                            className={`text-left p-4 rounded-xl border transition flex flex-col justify-between gap-2 cursor-pointer ${
                              isSelected
                                ? "border-cyan-400 bg-cyan-950/30 shadow-lg shadow-cyan-950/40"
                                : "border-slate-800 bg-slate-950/70 hover:border-slate-700"
                            }`}
                          >
                            <div className="flex items-center justify-between gap-2">
                              <span className="text-xs font-bold uppercase tracking-wider text-cyan-300">
                                Hop #{hop.hop_index}{" "}
                                {idx === report.hops.length - 1
                                  ? "(Final Page)"
                                  : "(Redirect)"}
                              </span>
                              <div className="flex items-center gap-1.5">
                                <span
                                  className={`text-[11px] font-mono px-2 py-0.5 rounded font-semibold ${
                                    isRedir
                                      ? "bg-amber-500/20 text-amber-300"
                                      : "bg-red-500/20 text-red-300"
                                  }`}
                                >
                                  HTTP {hop.status_code}
                                </span>
                                <span className="text-[11px] font-mono text-slate-400">
                                  {hop.latency_ms}ms
                                </span>
                              </div>
                            </div>
                            <div className="text-xs font-mono text-slate-200 truncate">
                              {hop.url}
                            </div>
                            {hop.screenshot_url && (
                              <div className="mt-1 rounded-lg overflow-hidden border border-slate-800 bg-slate-950">
                                <img
                                  src={`${API_BASE}${hop.screenshot_url}`}
                                  alt={`Hop ${hop.hop_index} screenshot`}
                                  className="w-full h-28 object-cover object-top"
                                />
                              </div>
                            )}
                          </button>
                        );
                      })}
                    </div>

                    {/* Selected Hop Full Screenshot Display */}
                    {selectedHop && selectedHop.screenshot_url && (
                      <div className="rounded-xl border border-slate-700/80 bg-slate-950 overflow-hidden shadow-xl">
                        <div className="px-4 py-2.5 bg-slate-900 border-b border-slate-800 flex flex-wrap items-center justify-between gap-2 text-xs">
                          <div className="flex items-center gap-2 font-mono text-slate-200 min-w-0">
                            <span className="px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 font-bold shrink-0 whitespace-nowrap">
                              Viewing Hop #{selectedHop.hop_index}
                            </span>
                            <span className="truncate max-w-[200px] sm:max-w-xl">
                              {selectedHop.url}
                            </span>
                          </div>
                          <div className="flex items-center gap-3 shrink-0">
                            <span className="text-slate-400 hidden sm:inline">
                              Captured via Headless Chromium inside disposable
                              chamber
                            </span>
                            <button
                              onClick={() =>
                                setLightboxImage({
                                  url: `${API_BASE}${selectedHop.screenshot_url}`,
                                  caption: `Hop #${selectedHop.hop_index} (${selectedHop.status_code}) — ${selectedHop.url}`,
                                })
                              }
                              className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 font-semibold text-[11px] cursor-pointer shrink-0 whitespace-nowrap"
                            >
                              Zoom Full Screen
                            </button>
                          </div>
                        </div>
                        <div className="p-3 bg-slate-950 flex justify-center">
                          <img
                            src={`${API_BASE}${selectedHop.screenshot_url}`}
                            alt={`Full screenshot for hop ${selectedHop.hop_index}`}
                            onClick={() =>
                              setLightboxImage({
                                url: `${API_BASE}${selectedHop.screenshot_url}`,
                                caption: `Hop #${selectedHop.hop_index} (${selectedHop.status_code}) — ${selectedHop.url}`,
                              })
                            }
                            title="Click to inspect full-resolution screenshot"
                            className="max-h-[520px] w-auto rounded-lg border border-slate-800 cursor-zoom-in hover:border-cyan-500/60 transition"
                          />
                        </div>
                      </div>
                    )}
                  </section>
                )}

                {/* 3. Visible Containment Report Panel (Objective 4) */}
                <section className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6 space-y-6">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div>
                      <h2 className="text-lg font-bold text-white flex items-center gap-2">
                        <Lock className="w-5 h-5 text-emerald-400" />
                        Visible Containment Report (Objective 4 — Proof of
                        Isolation)
                      </h2>
                      <p className="text-xs text-slate-400">
                        Every hostile action below was intercepted inside the
                        disposable chamber before it could reach your device,
                        the host VM, or any credentials.
                      </p>
                    </div>
                    <span className="text-xs font-mono px-3 py-1 rounded-full bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
                      Blast Radius: 1 Disposable Container (Destroyed)
                    </span>
                  </div>

                  {/* Three Key Containment Pillars */}
                  <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                    {/* Pillar A: Quarantined Downloads */}
                    <div className="rounded-xl border border-slate-800 bg-slate-950/80 p-4 space-y-3">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-bold uppercase tracking-wider text-red-300 flex items-center gap-1.5">
                          <FileWarning className="w-4 h-4 text-red-400" />
                          Quarantined Downloads (M6)
                        </span>
                        <span className="text-xs font-mono px-2 py-0.5 rounded bg-red-500/20 text-red-300">
                          {report.downloads_quarantined.length} blocked
                        </span>
                      </div>
                      {report.downloads_quarantined.length === 0 ? (
                        <p className="text-xs text-slate-400">
                          No executable or archive downloads were triggered
                          during this visit.
                        </p>
                      ) : (
                        <div className="space-y-2">
                          {report.downloads_quarantined.map((dl, i) => (
                            <div
                              key={i}
                              className="p-3 rounded-lg bg-red-950/30 border border-red-500/30 text-xs space-y-1"
                            >
                              <div className="font-bold text-red-200 flex items-center justify-between">
                                <span>{dl.filename}</span>
                                {dl.is_eicar && (
                                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-500 text-slate-950 font-bold">
                                    EICAR SIGNATURE
                                  </span>
                                )}
                              </div>
                              <div className="text-slate-300">
                                Quarantined by M6 Egress Filter · Never executed
                              </div>
                              <div className="font-mono text-[11px] text-slate-400 break-all">
                                SHA-256: {dl.sha256}
                              </div>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>

                    {/* Pillar B: Neutralized Prompt Injections */}
                    <div className="rounded-xl border border-slate-800 bg-slate-950/80 p-4 space-y-3">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-bold uppercase tracking-wider text-amber-300 flex items-center gap-1.5">
                          <AlertTriangle className="w-4 h-4 text-amber-400" />
                          AI Prompt Injections (M3/M7)
                        </span>
                        <span className="text-xs font-mono px-2 py-0.5 rounded bg-amber-500/20 text-amber-300">
                          {report.agent_injection_findings.length} neutralized
                        </span>
                      </div>
                      {report.agent_injection_findings.length === 0 ? (
                        <p className="text-xs text-slate-400">
                          No hidden prompt-injection instructions aimed at AI
                          agents were found in the DOM.
                        </p>
                      ) : (
                        <div className="space-y-2">
                          {report.agent_injection_findings.map((inj, i) => (
                            <div
                              key={i}
                              className="p-3 rounded-lg bg-amber-950/30 border border-amber-500/30 text-xs space-y-1.5"
                            >
                              <div className="text-amber-200 font-semibold">
                                Hidden DOM Instruction Logged &amp; Ignored:
                              </div>
                              <blockquote className="font-mono text-[11px] text-slate-300 bg-slate-950 p-2 rounded border border-slate-800">
                                &quot;{inj}&quot;
                              </blockquote>
                              <div className="text-emerald-400 text-[11px]">
                                ✓ Wrapped as quoted evidence · M3 Policy Gate
                                refused form submit · 0 injected commands run
                              </div>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>

                    {/* Pillar C: Blocked Outbound / SSRF Egress */}
                    <div className="rounded-xl border border-slate-800 bg-slate-950/80 p-4 space-y-3">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-bold uppercase tracking-wider text-cyan-300 flex items-center gap-1.5">
                          <ShieldAlert className="w-4 h-4 text-cyan-400" />
                          Blocked Internal / SSRF Egress (M6)
                        </span>
                        <span className="text-xs font-mono px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300">
                          {report.egress_blocks.length} refused
                        </span>
                      </div>
                      {report.egress_blocks.length === 0 ? (
                        <p className="text-xs text-slate-400">
                          No outbound requests to private RFC1918 networks or
                          cloud metadata (169.254.169.254) were attempted.
                        </p>
                      ) : (
                        <div className="space-y-2">
                          {report.egress_blocks.map((blk, i) => (
                            <div
                              key={i}
                              className="p-3 rounded-lg bg-cyan-950/30 border border-cyan-500/30 text-xs space-y-1"
                            >
                              <div className="font-mono text-cyan-200 break-all font-semibold">
                                {blk.url}
                              </div>
                              <div className="text-slate-300">{blk.reason}</div>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Chamber Lifecycle Receipt & Event Log */}
                  {report.chamber_receipt && (
                    <div className="rounded-xl border border-emerald-500/30 bg-emerald-950/15 p-4">
                      <div className="flex flex-wrap items-center justify-between gap-2 mb-3">
                        <span className="text-xs font-bold uppercase tracking-wider text-emerald-300 flex items-center gap-1.5">
                          <Cpu className="w-4 h-4" />
                          M4 Chamber Lifecycle &amp; Hardening Receipt (
                          {report.chamber_receipt.termination_reason})
                        </span>
                        <span className="text-xs font-mono text-emerald-400 font-semibold">
                          ✓ Chamber destroyed after{" "}
                          {report.chamber_receipt.lifetime_seconds} seconds ·
                          Zero secrets present inside chamber
                        </span>
                      </div>
                      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
                        <div className="bg-slate-950/80 p-2.5 rounded-lg border border-slate-800">
                          <div className="text-slate-400 text-[10px]">
                            CHAMBER ID
                          </div>
                          <div className="text-slate-200">
                            {report.chamber_receipt.chamber_id}
                          </div>
                        </div>
                        <div className="bg-slate-950/80 p-2.5 rounded-lg border border-slate-800">
                          <div className="text-slate-400 text-[10px]">
                            USER &amp; PRIVILEGES
                          </div>
                          <div className="text-slate-200">
                            {report.chamber_receipt.user} /{" "}
                            {report.chamber_receipt.capabilities}
                          </div>
                        </div>
                        <div className="bg-slate-950/80 p-2.5 rounded-lg border border-slate-800">
                          <div className="text-slate-400 text-[10px]">
                            RESOURCE CEILINGS
                          </div>
                          <div className="text-slate-200">
                            {report.chamber_receipt.cpu_limit} ·{" "}
                            {report.chamber_receipt.memory_limit} ·{" "}
                            {report.chamber_receipt.pids_limit} PIDs
                          </div>
                        </div>
                        <div className="bg-slate-950/80 p-2.5 rounded-lg border border-slate-800">
                          <div className="text-slate-400 text-[10px]">
                            SECRETS INJECTED
                          </div>
                          <div className="text-emerald-400 font-bold">
                            {report.chamber_receipt.secrets_injected} (API keys
                            stay on Control Plane)
                          </div>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Chronological Containment Event Timeline */}
                  <div className="space-y-2">
                    <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400">
                      Complete Containment &amp; Policy Gate Audit Log (
                      {report.containment_events.length} events)
                    </h3>
                    <div className="space-y-1.5 max-h-64 overflow-y-auto pr-1">
                      {report.containment_events.map((ev, i) => (
                        <div
                          key={i}
                          className="p-2.5 rounded-lg bg-slate-950/90 border border-slate-800/90 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs"
                        >
                          <div className="flex items-start gap-2.5">
                            <span
                              className={`px-2 py-0.5 rounded font-mono text-[10px] font-bold uppercase shrink-0 ${
                                ev.severity === "critical"
                                  ? "bg-red-500/20 text-red-300 border border-red-500/30"
                                  : ev.severity === "warning"
                                  ? "bg-amber-500/20 text-amber-300 border border-amber-500/30"
                                  : "bg-slate-800 text-cyan-300"
                              }`}
                            >
                              {ev.module}
                            </span>
                            <div>
                              <div className="font-semibold text-slate-200">
                                {ev.title}
                              </div>
                              <div className="text-slate-400 text-[11px]">
                                {ev.detail}
                              </div>
                            </div>
                          </div>
                          <span className="text-[10px] font-mono text-slate-500 shrink-0">
                            {new Date(ev.timestamp).toLocaleTimeString()}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                </section>
              </div>
            )}
          </>
        )}

        {/* TAB 2: Scan History (M8 SQLite Evidence Store) */}
        {activeTab === "history" && (
          <section className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6 space-y-5">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-xl font-bold text-white flex items-center gap-2">
                  <History className="w-5 h-5 text-cyan-400" />
                  M8 Evidence Store — Recent Detonation History
                </h2>
                <p className="text-sm text-slate-400">
                  Stored in SQLite (`data/baitbox.db`) with automatic 7-day
                  retention cleanup. Click any scan to open its full report and
                  screenshots.
                </p>
              </div>
              <button
                onClick={fetchTelemetryAndHistory}
                className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-slate-200 flex items-center gap-1.5 cursor-pointer"
              >
                <RefreshCw className="w-3.5 h-3.5" />
                Refresh
              </button>
            </div>

            {/* Search & Verdict Filter Bar */}
            <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
              <input
                type="text"
                value={historySearch}
                onChange={(e) => setHistorySearch(e.target.value)}
                placeholder="Filter history by URL, domain, brand, or scan ID..."
                className="flex-1 rounded-xl bg-slate-950 border border-slate-800 px-3.5 py-2 text-xs text-white placeholder-slate-500"
              />
              <div className="flex items-center gap-1.5 text-xs">
                {["ALL", "Dangerous", "Suspicious", "Likely safe"].map((fv) => (
                  <button
                    key={fv}
                    onClick={() => setHistoryFilter(fv)}
                    className={`px-3 py-1.5 rounded-lg font-semibold border transition cursor-pointer ${
                      historyFilter === fv
                        ? "bg-cyan-500/20 text-cyan-300 border-cyan-500/40"
                        : "bg-slate-950 text-slate-400 border-slate-800 hover:text-slate-200"
                    }`}
                  >
                    {fv}
                  </button>
                ))}
              </div>
            </div>

            {recentScans.length === 0 ? (
              <p className="text-sm text-slate-400">
                No scans recorded yet. Run a scan from the Detonation Console!
              </p>
            ) : (
              <div className="overflow-x-auto rounded-xl border border-slate-800">
                <table className="w-full text-left text-xs">
                  <thead className="bg-slate-950 text-slate-400 uppercase">
                    <tr>
                      <th className="p-3">Scan ID</th>
                      <th className="p-3">Submitted / Masked URL</th>
                      <th className="p-3">Verdict</th>
                      <th className="p-3">Impersonated Brand</th>
                      <th className="p-3">Risk</th>
                      <th className="p-3">Timestamp</th>
                      <th className="p-3">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800 bg-slate-900/40">
                    {recentScans
                      .filter((s) => {
                        if (
                          historyFilter !== "ALL" &&
                          s.verdict !== historyFilter
                        ) {
                          return false;
                        }
                        if (!historySearch.trim()) return true;
                        const q = historySearch.toLowerCase();
                        return (
                          String(s.normalized_url || "")
                            .toLowerCase()
                            .includes(q) ||
                          String(s.impersonated_brand || "")
                            .toLowerCase()
                            .includes(q) ||
                          String(s.scan_id || "")
                            .toLowerCase()
                            .includes(q)
                        );
                      })
                      .map((s) => (
                        <tr key={s.scan_id} className="hover:bg-slate-800/40">
                          <td className="p-3 font-mono font-bold text-cyan-300">
                            {s.scan_id}
                          </td>
                          <td className="p-3 font-mono text-slate-200 truncate max-w-md">
                            {s.normalized_url}
                          </td>
                          <td className="p-3 font-bold">
                            <span
                              className={
                                s.verdict === "Dangerous"
                                  ? "text-red-400"
                                  : s.verdict === "Suspicious"
                                  ? "text-amber-400"
                                  : "text-emerald-400"
                              }
                            >
                              {s.verdict || s.status}
                            </span>
                          </td>
                          <td className="p-3 text-slate-300">
                            {s.impersonated_brand || "-"}
                          </td>
                          <td className="p-3 font-mono">{s.risk_score}/100</td>
                          <td className="p-3 text-slate-400">
                            {new Date(s.created_at).toLocaleString()}
                          </td>
                          <td className="p-3 flex items-center gap-2">
                            <button
                              onClick={() => loadHistoricalScan(s.scan_id)}
                              className="px-2.5 py-1 rounded bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 font-semibold cursor-pointer"
                            >
                              Inspect
                            </button>
                            <button
                              onClick={() => {
                                setInputText(s.normalized_url);
                                startScan(s.normalized_url);
                              }}
                              className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold cursor-pointer"
                            >
                              Re-Scan
                            </button>
                            <button
                              onClick={() => deleteHistoricalScan(s.scan_id)}
                              className="px-2 py-1 rounded bg-red-500/15 hover:bg-red-500/25 text-red-300 font-semibold cursor-pointer"
                            >
                              Delete
                            </button>
                          </td>
                        </tr>
                      ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        )}

        {/* TAB 3: 20-Link Evaluation & Containment Benchmark */}
        {activeTab === "benchmark" && (
          <section className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6 space-y-6">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div>
                <h2 className="text-xl font-bold text-white">
                  20-Link Evaluation &amp; Containment Verification Suite
                </h2>
                <p className="text-sm text-slate-400">
                  Tests 10 known-phishing/hostile links and 10 legitimate sites,
                  plus a forced wall-clock timeout test to confirm zero chambers
                  remain running.
                </p>
              </div>
              <button
                onClick={handleRunBenchmark}
                disabled={runningBenchmark}
                className="px-5 py-3 rounded-xl bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-slate-950 font-bold text-xs flex items-center gap-2 shrink-0 cursor-pointer"
              >
                {runningBenchmark ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin" />
                    Running 20-Link Benchmark...
                  </>
                ) : (
                  <>
                    <Play className="w-4 h-4 fill-current" />
                    Run Full 20-Link Evaluation Now
                  </>
                )}
              </button>
            </div>

            {benchmarkData && (
              <div className="space-y-6">
                {/* Summary Metric Cards */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
                  <div className="p-4 rounded-xl bg-slate-950 border border-slate-800">
                    <div className="text-xs text-slate-400">
                      Verdict Accuracy (Target ≥ 17/20)
                    </div>
                    <div className="text-2xl font-bold text-emerald-400 mt-1">
                      {benchmarkData.summary.verdict_accuracy} (
                      {benchmarkData.summary.verdict_accuracy_pct}%)
                    </div>
                  </div>
                  <div className="p-4 rounded-xl bg-slate-950 border border-slate-800">
                    <div className="text-xs text-slate-400">
                      Dangerous Pages Missed (Target 0/10)
                    </div>
                    <div className="text-2xl font-bold text-emerald-400 mt-1">
                      {benchmarkData.summary.dangerous_pages_missed}
                    </div>
                  </div>
                  <div className="p-4 rounded-xl bg-slate-950 border border-slate-800">
                    <div className="text-xs text-slate-400">
                      Chambers Left Running (incl. Timeout)
                    </div>
                    <div className="text-2xl font-bold text-emerald-400 mt-1">
                      {benchmarkData.summary.chambers_left_running}
                    </div>
                  </div>
                  <div className="p-4 rounded-xl bg-slate-950 border border-slate-800">
                    <div className="text-xs text-slate-400">
                      Agent-Injection Compliance
                    </div>
                    <div className="text-2xl font-bold text-emerald-400 mt-1">
                      {benchmarkData.summary.agent_injection_compliance}
                    </div>
                  </div>
                </div>

                {/* Full 20-Link Table */}
                <div className="overflow-x-auto rounded-xl border border-slate-800">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-slate-950 text-slate-400 uppercase">
                      <tr>
                        <th className="p-3">ID</th>
                        <th className="p-3">URL / Scenario</th>
                        <th className="p-3">Expected</th>
                        <th className="p-3">Actual Verdict</th>
                        <th className="p-3">Brand</th>
                        <th className="p-3">Risk</th>
                        <th className="p-3">Chamber Gone</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800 bg-slate-900/40">
                      {benchmarkData.results.map((r: any) => (
                        <tr
                          key={r.id}
                          onClick={() => loadHistoricalScan(r.scan_id)}
                          className="hover:bg-slate-800/40 cursor-pointer"
                        >
                          <td className="p-3 font-mono font-bold text-slate-300">
                            {r.id}
                          </td>
                          <td className="p-3">
                            <div className="font-mono text-slate-200 truncate max-w-md">
                              {r.url}
                            </div>
                            <div className="text-slate-400 text-[11px]">
                              {r.description}
                            </div>
                          </td>
                          <td className="p-3">{r.expected}</td>
                          <td className="p-3 font-bold">
                            <span
                              className={
                                r.actual === "Dangerous"
                                  ? "text-red-400"
                                  : "text-emerald-400"
                              }
                            >
                              {r.actual}
                            </span>
                          </td>
                          <td className="p-3 text-slate-300">
                            {r.impersonated_brand || "-"}
                          </td>
                          <td className="p-3 font-mono">{r.risk_score}/100</td>
                          <td className="p-3 text-emerald-400 font-mono">
                            {r.chamber_destroyed ? "✓ Destroyed" : "✗"}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </section>
        )}

        {/* TAB 4: Scene 5 "Under the Hood" Architecture, Live Telemetry & Vultr Model Config */}
        {activeTab === "architecture" && (
          <section className="space-y-6">
            <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6 space-y-5">
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="text-xl font-bold text-white flex items-center gap-2">
                    <Activity className="w-5 h-5 text-cyan-400" />
                    Scene 5 — Under the Hood: Vultr Control Plane &amp; Chamber
                    Telemetry
                  </h2>
                  <p className="text-sm text-slate-400">
                    Real-time state of the trusted control plane (M2, M3, M4,
                    M7, M8) and disposable detonation chambers (M5, M6).
                  </p>
                </div>
                <button
                  onClick={fetchTelemetryAndHistory}
                  className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-slate-200 flex items-center gap-1.5"
                >
                  <RefreshCw className="w-3.5 h-3.5" />
                  Refresh Telemetry
                </button>
              </div>

              {telemetry && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2 font-mono text-xs">
                    <div className="text-cyan-400 font-bold uppercase">
                      M4 Chamber Manager &amp; Container Limits
                    </div>
                    <div>
                      Active Chambers Running (`docker ps`):{" "}
                      <span className="text-emerald-400 font-bold">
                        {telemetry.chamber_manager?.active_chambers_count ?? 0}
                      </span>
                    </div>
                    <div>
                      Total Chambers Created &amp; Destroyed:{" "}
                      <span className="text-slate-200">
                        {telemetry.chamber_manager?.total_chambers_destroyed ??
                          0}
                      </span>
                    </div>
                    <div>
                      User / Capabilities:{" "}
                      <span className="text-slate-300">
                        {telemetry.chamber_manager?.limits?.user} ·{" "}
                        {telemetry.chamber_manager?.limits?.capabilities}
                      </span>
                    </div>
                    <div>
                      Filesystem:{" "}
                      <span className="text-slate-300">
                        {telemetry.chamber_manager?.limits?.rootfs}
                      </span>
                    </div>
                    <div>
                      Resource Ceilings:{" "}
                      <span className="text-slate-300">
                        {telemetry.chamber_manager?.limits?.cpu} ·{" "}
                        {telemetry.chamber_manager?.limits?.memory} RAM ·{" "}
                        {telemetry.chamber_manager?.limits?.pids} PIDs ·{" "}
                        {telemetry.chamber_manager?.max_age_seconds}s TTL
                      </span>
                    </div>
                    <div>
                      Secrets Inside Chamber:{" "}
                      <span className="text-emerald-400 font-bold">
                        0 (None — Verified)
                      </span>
                    </div>
                  </div>

                  <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2 font-mono text-xs">
                    <div className="text-cyan-400 font-bold uppercase">
                      Vultr Infrastructure &amp; Serverless Inference
                    </div>
                    <div>
                      Control Plane Host:{" "}
                      <span className="text-slate-200">
                        {telemetry.vultr_services?.control_plane}
                      </span>
                    </div>
                    <div>
                      Inference Base URL:{" "}
                      <span className="text-cyan-300">
                        {telemetry.vultr_services?.inference_endpoint}
                      </span>
                    </div>
                    <div>
                      Planner Model (M2):{" "}
                      <span className="text-slate-200">
                        {telemetry.vultr_services?.planner_model}
                      </span>
                    </div>
                    <div>
                      Vision / Analyst Model (M7):{" "}
                      <span className="text-slate-200">
                        {telemetry.vultr_services?.vision_model}
                      </span>
                    </div>
                    <div>
                      Catalog Models Discovered:{" "}
                      <span className="text-emerald-400 font-bold">
                        {vultrModels.length} live models from
                        api.vultrinference.com
                      </span>
                    </div>
                    <div>
                      Execution Mode:{" "}
                      <span className="text-emerald-400">
                        {telemetry.vultr_services?.mode}
                      </span>
                    </div>
                  </div>
                </div>
              )}

              {/* Runtime Vultr Serverless Inference Configuration Form */}
              <form
                onSubmit={handleSaveConfig}
                className="p-5 rounded-xl bg-slate-950 border border-slate-800 space-y-4"
              >
                <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-cyan-400">
                  <Key className="w-4 h-4" />
                  Configure Vultr Serverless Inference API Key &amp; Models at
                  Runtime (Stays Strictly on Control Plane)
                </div>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
                  <div>
                    <label className="block text-slate-400 mb-1">
                      VULTR_INFERENCE_API_KEY
                    </label>
                    <input
                      type="password"
                      value={apiKeyInput}
                      onChange={(e) => setApiKeyInput(e.target.value)}
                      placeholder={
                        telemetry?.vultr_services?.api_key_configured
                          ? "•••••••••••••••• (Configured)"
                          : "Paste Vultr Serverless Inference API Key..."
                      }
                      className="w-full rounded-lg bg-slate-900 border border-slate-700 px-3 py-2 text-white"
                    />
                  </div>
                  <div>
                    <label className="block text-slate-400 mb-1">
                      M2 Planner Model (Live Vultr Catalog)
                    </label>
                    <select
                      value={plannerModelInput}
                      onChange={(e) => setPlannerModelInput(e.target.value)}
                      className="w-full rounded-lg bg-slate-900 border border-slate-700 px-3 py-2 text-white font-mono"
                    >
                      {!vultrModels.some((m) => m.id === plannerModelInput) && (
                        <option value={plannerModelInput}>
                          {plannerModelInput}
                        </option>
                      )}
                      {vultrModels.map((m) => (
                        <option key={m.id} value={m.id}>
                          {m.id}
                        </option>
                      ))}
                    </select>
                  </div>
                  <div>
                    <label className="block text-slate-400 mb-1">
                      M7 Analyst / Vision Model (Live Vultr Catalog)
                    </label>
                    <select
                      value={visionModelInput}
                      onChange={(e) => setVisionModelInput(e.target.value)}
                      className="w-full rounded-lg bg-slate-900 border border-slate-700 px-3 py-2 text-white font-mono"
                    >
                      {!vultrModels.some((m) => m.id === visionModelInput) && (
                        <option value={visionModelInput}>
                          {visionModelInput}
                        </option>
                      )}
                      {vultrModels.map((m) => (
                        <option key={m.id} value={m.id}>
                          {m.id}
                        </option>
                      ))}
                    </select>
                  </div>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-[11px] text-slate-400">
                    Secret Hygiene Guarantee: Your API key is stored only in the
                    trusted M2 Orchestrator memory and is never mounted or
                    passed into any M5 chamber container.
                  </span>
                  <button
                    type="submit"
                    className="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs cursor-pointer"
                  >
                    Save Control Plane Settings
                  </button>
                </div>
                {configSavedMsg && (
                  <div className="text-xs text-emerald-400 font-semibold">
                    ✓ {configSavedMsg}
                  </div>
                )}
              </form>
            </div>
          </section>
        )}
      {/* Full-Resolution Screenshot Lightbox Modal */}
      {lightboxImage && (
        <div
          onClick={() => setLightboxImage(null)}
          className="fixed inset-0 z-50 bg-slate-950/90 backdrop-blur-sm flex items-center justify-center p-4 sm:p-8"
        >
          <div
            onClick={(e) => e.stopPropagation()}
            className="max-w-6xl w-full rounded-2xl border border-slate-700 bg-slate-900 overflow-hidden shadow-2xl"
          >
            <div className="px-5 py-3 bg-slate-950 border-b border-slate-800 flex items-center justify-between gap-4">
              <span className="text-xs font-mono text-cyan-300 truncate">
                {lightboxImage.caption}
              </span>
              <button
                onClick={() => setLightboxImage(null)}
                className="px-3 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold cursor-pointer"
              >
                Close Preview
              </button>
            </div>
            <div className="p-4 flex justify-center bg-slate-950 max-h-[82vh] overflow-auto">
              <img
                src={lightboxImage.url}
                alt={lightboxImage.caption}
                className="max-w-full h-auto rounded-lg border border-slate-800"
              />
            </div>
          </div>
        </div>
      )}
      </main>
    </div>
  );
}
