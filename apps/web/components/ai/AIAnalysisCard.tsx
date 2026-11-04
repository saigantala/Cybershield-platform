"use client";

import { useState } from "react";
import {
  Sparkles,
  Bot,
  RefreshCw,
  CheckCircle2,
  AlertTriangle,
  ChevronDown,
  ChevronUp,
  Shield,
  Check,
  X,
} from "lucide-react";
import { apiAI } from "@/lib/api-client";

interface AIAnalysisCardProps {
  entityType: "alert" | "incident" | "vulnerability" | "asset";
  entityId: string;
  initialSummary?: string;
  initialEvidence?: string[];
  initialSteps?: string[];
}

export function AIAnalysisCard({
  entityType,
  entityId,
  initialSummary,
  initialEvidence = [],
  initialSteps = [],
}: AIAnalysisCardProps) {
  const [loading, setLoading] = useState(false);
  const [summary, setSummary] = useState(initialSummary || "");
  const [evidence, setEvidence] = useState<string[]>(initialEvidence);
  const [steps, setSteps] = useState<string[]>(initialSteps);
  const [isExpanded, setIsExpanded] = useState(true);
  const [reviewStatus, setReviewStatus] = useState<"Pending" | "Approved" | "Rejected">("Pending");
  const [error, setError] = useState<string | null>(null);

  const handleGenerate = async () => {
    setLoading(true);
    setError(null);
    try {
      if (entityType === "alert") {
        const res = await apiAI.analyzeAlert(entityId);
        if (res.data) {
          setSummary(res.data.summary);
          setEvidence(res.data.supporting_evidence || []);
          setSteps(res.data.investigation_steps || []);
        }
      } else if (entityType === "incident") {
        const res = await apiAI.summarizeIncident(entityId);
        if (res.data) {
          setSummary(res.data.overview);
          setEvidence(res.data.timeline_summary || []);
          setSteps(res.data.recommended_next_steps || []);
        }
      } else if (entityType === "vulnerability") {
        const res = await apiAI.recommendRemediation(entityId);
        if (res.data) {
          setSummary(res.data.explanation);
          setEvidence(res.data.supporting_references || []);
          setSteps(res.data.suggested_steps || []);
        }
      }
    } catch (e: any) {
      setError(e?.message || "Failed to generate AI analysis.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="bg-[#111C2D]/80 border border-slate-800/80 rounded-2xl overflow-hidden backdrop-blur-sm">
      <div className="p-4 border-b border-slate-800 flex items-center justify-between">
        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded-xl bg-gradient-to-tr from-blue-600/20 to-cyan-500/20 border border-blue-500/30 text-cyan-400">
            <Sparkles className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-xs font-bold text-white tracking-tight uppercase">
                AI Security Synthesis & Advisory
              </h3>
              <span className="px-2 py-0.5 text-[9px] font-mono rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                MOCK SOC MODEL
              </span>
            </div>
            <p className="text-[11px] text-slate-400">
              Correlated reasonings • Human review gate enforced
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleGenerate}
            disabled={loading}
            className="flex items-center gap-1 px-2.5 py-1 text-xs font-semibold rounded-lg bg-blue-600/20 hover:bg-blue-600/30 text-blue-400 border border-blue-500/30 transition-colors disabled:opacity-40"
          >
            <RefreshCw className={`w-3 h-3 ${loading ? "animate-spin" : ""}`} />
            {summary ? "Regenerate" : "Analyze"}
          </button>
          <button
            onClick={() => setIsExpanded(!isExpanded)}
            className="p-1 text-slate-400 hover:text-white"
          >
            {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </button>
        </div>
      </div>

      {isExpanded && (
        <div className="p-4 space-y-3.5 text-xs">
          {error && (
            <div className="p-2.5 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-300 text-xs">
              {error}
            </div>
          )}

          {summary ? (
            <>
              <div>
                <span className="text-slate-400 font-semibold block mb-1">Executive Synthesis:</span>
                <p className="text-slate-200 leading-relaxed bg-[#080D18]/70 p-3 rounded-xl border border-slate-800">
                  {summary}
                </p>
              </div>

              {steps.length > 0 && (
                <div>
                  <span className="text-slate-400 font-semibold block mb-1">
                    Recommended Triage Actions:
                  </span>
                  <ul className="space-y-1.5 pl-4 list-disc text-slate-300">
                    {steps.map((st, i) => (
                      <li key={i}>{st}</li>
                    ))}
                  </ul>
                </div>
              )}

              {evidence.length > 0 && (
                <div>
                  <span className="text-slate-400 font-semibold block mb-1">Supporting Context:</span>
                  <div className="flex flex-wrap gap-1.5">
                    {evidence.map((ev, i) => (
                      <span
                        key={i}
                        className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-[11px] text-cyan-400 font-mono"
                      >
                        {ev}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Review Disposition */}
              <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between text-[11px]">
                <span className="text-slate-500">
                  Status:{" "}
                  <strong
                    className={
                      reviewStatus === "Approved"
                        ? "text-emerald-400"
                        : reviewStatus === "Rejected"
                        ? "text-rose-400"
                        : "text-amber-400"
                    }
                  >
                    {reviewStatus}
                  </strong>
                </span>

                <div className="flex items-center gap-1.5">
                  <button
                    onClick={() => setReviewStatus("Approved")}
                    className="px-2 py-0.5 rounded bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 flex items-center gap-1 transition-colors"
                  >
                    <Check className="w-3 h-3" /> Approve Advice
                  </button>
                  <button
                    onClick={() => setReviewStatus("Rejected")}
                    className="px-2 py-0.5 rounded bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border border-rose-500/30 flex items-center gap-1 transition-colors"
                  >
                    <X className="w-3 h-3" /> Decline
                  </button>
                </div>
              </div>
            </>
          ) : (
            <div className="py-6 text-center text-slate-500">
              <Bot className="w-8 h-8 mx-auto mb-2 text-slate-600" />
              <p>Click &quot;Analyze&quot; to synthesize AI security telemetry for this record.</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
