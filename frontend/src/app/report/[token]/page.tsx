"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import {
  ShieldAlert,
  ShieldCheck,
  ShieldQuestion,
  Lock,
  ArrowLeft,
  FileWarning,
  AlertTriangle,
} from "lucide-react";

const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE_URL ||
  (typeof window !== "undefined" &&
  window.location.hostname !== "localhost" &&
  window.location.hostname !== "127.0.0.1"
    ? ""
    : "http://localhost:8000");

export default function SharedReportPage() {
  const params = useParams();
  const token = params?.token as string;
  const [report, setReport] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!token) return;
    fetch(`${API_BASE}/api/reports/shared/${token}`)
      .then(async (res) => {
        if (!res.ok) throw new Error("Shared report not found or expired");
        setReport(await res.json());
      })
      .catch((e) => setError(e.message));
  }, [token]);

  if (error) {
    return (
      <div className="min-h-screen flex items-center justify-center p-6">
        <div className="max-w-md w-full rounded-2xl border border-red-500/40 bg-slate-900 p-6 text-center space-y-4">
          <p className="text-red-300 font-semibold">{error}</p>
          <Link
            href="/"
            className="inline-flex items-center gap-2 text-xs text-cyan-400 hover:underline"
          >
            <ArrowLeft className="w-4 h-4" /> Back to BaitBox Console
          </Link>
        </div>
      </div>
    );
  }

  if (!report) {
    return (
      <div className="min-h-screen flex items-center justify-center p-6 text-slate-400 text-sm">
        Loading Share-Safe BaitBox Report...
      </div>
    );
  }

  return (
    <div className="min-h-screen max-w-5xl mx-auto px-4 py-8 space-y-6">
      <div className="flex items-center justify-between">
        <Link
          href="/"
          className="inline-flex items-center gap-2 text-xs font-semibold text-cyan-400 hover:text-cyan-300"
        >
          <ArrowLeft className="w-4 h-4" /> Scan Another Link on BaitBox
        </Link>
        <span className="text-xs px-3 py-1 rounded-full bg-emerald-500/15 text-emerald-300 border border-emerald-500/30 font-mono">
          Objective 6 · Share-Safe Defanged Report (Live URL Masked)
        </span>
      </div>

      <section className="rounded-2xl border-2 border-red-500/50 bg-slate-900/90 p-6 space-y-4">
        <div className="flex items-center gap-3">
          {report.verdict === "Dangerous" ? (
            <ShieldAlert className="w-9 h-9 text-red-400" />
          ) : report.verdict === "Suspicious" ? (
            <ShieldQuestion className="w-9 h-9 text-amber-400" />
          ) : (
            <ShieldCheck className="w-9 h-9 text-emerald-400" />
          )}
          <div>
            <div className="text-xs uppercase font-bold tracking-wider text-slate-400">
              BaitBox Share-Safe Verdict
            </div>
            <h1 className="text-2xl font-bold text-white">
              {report.verdict}{" "}
              {report.impersonated_brand
                ? `— Imitates ${report.impersonated_brand}`
                : ""}
            </h1>
          </div>
        </div>

        <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 font-mono text-xs text-slate-300">
          Masked Suspicious Address (Safe to Forward):{" "}
          <span className="text-amber-300 font-bold">{report.masked_url}</span>
        </div>

        <p className="text-base text-slate-100 leading-relaxed">
          {report.reason}
        </p>

        <div className="flex flex-wrap items-center gap-2 pt-1 text-xs font-mono">
          <span className="px-2.5 py-1 rounded-full bg-slate-800 text-slate-200 border border-slate-700">
            Risk Score: {report.risk_score}/100
          </span>
          {report.chamber_receipt && (
            <span className="px-2.5 py-1 rounded-full bg-emerald-950/80 text-emerald-300 border border-emerald-500/40">
              Chamber destroyed after {report.chamber_receipt.lifetime_seconds}s · 0 keys inside
            </span>
          )}
          <span className="px-2.5 py-1 rounded-full bg-slate-800 text-cyan-300 border border-slate-700">
            Redirect Hops: {report.hops?.length || 1}
          </span>
        </div>

        <p className="text-xs text-slate-400 italic">{report.caveat}</p>
      </section>

      {report.final_screenshot_url && (
        <section className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6 space-y-3">
          <h2 className="text-sm font-bold uppercase tracking-wider text-slate-300">
            Evidence Screenshot Captured Inside Disposable Chamber
          </h2>
          <img
            src={`${API_BASE}${report.final_screenshot_url}`}
            alt="Final screenshot"
            className="rounded-xl border border-slate-800 max-h-[460px] w-auto mx-auto"
          />
        </section>
      )}

      {/* Defanged Redirect Chain & Containment Summary */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <section className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5 space-y-3">
          <h3 className="text-xs font-bold uppercase tracking-wider text-cyan-300 flex items-center gap-2">
            <Lock className="w-4 h-4" />
            Defanged Redirect Hop Chain (Unclickable)
          </h3>
          <div className="space-y-2 text-xs font-mono">
            {(report.hops || []).map((h: any) => (
              <div
                key={h.hop_index}
                className="p-2.5 rounded-xl bg-slate-950 border border-slate-800 flex items-center justify-between gap-2"
              >
                <span className="text-slate-300 truncate">
                  Hop #{h.hop_index}:{" "}
                  {String(h.domain || "host").replace(/\./g, "[.]")} (
                  {h.note || "visited"})
                </span>
                <span className="px-2 py-0.5 rounded bg-slate-800 text-amber-300 shrink-0">
                  HTTP {h.status_code}
                </span>
              </div>
            ))}
          </div>
        </section>

        <section className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5 space-y-3">
          <h3 className="text-xs font-bold uppercase tracking-wider text-emerald-300 flex items-center gap-2">
            <FileWarning className="w-4 h-4" />
            Chamber Containment Summary (Objective 4)
          </h3>
          <div className="space-y-2 text-xs text-slate-300">
            <div className="p-2.5 rounded-xl bg-slate-950 border border-slate-800 flex items-center justify-between">
              <span>Drive-By Downloads Quarantined (M6)</span>
              <span className="font-mono font-bold text-red-300">
                {report.downloads_quarantined?.length || 0} blocked
              </span>
            </div>
            <div className="p-2.5 rounded-xl bg-slate-950 border border-slate-800 flex items-center justify-between">
              <span>AI Prompt Injections Neutralized (M3/M7)</span>
              <span className="font-mono font-bold text-amber-300">
                {report.agent_injection_findings?.length || 0} neutralized
              </span>
            </div>
            <div className="p-2.5 rounded-xl bg-slate-950 border border-slate-800 flex items-center justify-between">
              <span>Internal / Cloud Metadata Probes Refused (M6)</span>
              <span className="font-mono font-bold text-cyan-300">
                {report.egress_blocks?.length || 0} refused
              </span>
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}
