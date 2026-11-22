"use client";
export const dynamic = 'force-dynamic';

import { useEffect, useState, Suspense } from "react";
import { useSearchParams } from "next/navigation";
import Link from "next/link";
import {
  BrainCircuit,
  Send,
  RefreshCw,
  ArrowLeft,
  ShieldCheck,
  AlertTriangle,
  HelpCircle,
  CheckCircle2,
  Terminal,
  ExternalLink,
  ChevronRight,
} from "lucide-react";
import { apiAIDetection } from "@/lib/api-client";
import type { AIThreatInvestigationQueryResponse } from "@/types/ai-detection";

interface ChatMessage {
  id: string;
  sender: "user" | "assistant";
  content: string;
  citations?: Array<Record<string, any>>;
  nextSteps?: string[];
  uncertainty?: string;
  timestamp: string;
}

function AIThreatInvestigationContent() {
  const searchParams = useSearchParams();
  const detectionId = searchParams.get("detection_id") || undefined;

  const [inputQuery, setInputQuery] = useState("");
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      id: "initial-assistant-greeting",
      sender: "assistant",
      content:
        "Welcome to the **CyberShield AI Threat Investigation Assistant**. I analyze authorized telemetry, Isolation Forest inferences, and correlated CVEs to explain flagged security events without hallucinations. Select a question below or ask about any asset, indicator, or detection record.",
      nextSteps: [
        "Select a pre-composed prompt pill to start",
        "Reference a Detection ID (e.g. DET-2026-0881) for evidence breakdown",
      ],
      timestamp: new Date().toLocaleTimeString(),
    },
  ]);
  const [loading, setLoading] = useState(false);

  const handleSendQuery = async (queryText?: string) => {
    const textToSend = queryText || inputQuery;
    if (!textToSend.trim() || loading) return;

    const userMsg: ChatMessage = {
      id: Math.random().toString(),
      sender: "user",
      content: textToSend,
      timestamp: new Date().toLocaleTimeString(),
    };

    setMessages((prev) => [...prev, userMsg]);
    setInputQuery("");
    setLoading(true);

    try {
      const res = await apiAIDetection.queryInvestigationAssistant({
        query: textToSend,
        detection_id: detectionId,
      });

      if (res.data) {
        const assistantMsg: ChatMessage = {
          id: res.data.message_id,
          sender: "assistant",
          content: res.data.answer,
          citations: res.data.evidence_citations,
          nextSteps: res.data.recommended_next_steps,
          uncertainty: res.data.confidence_and_uncertainty,
          timestamp: new Date(res.data.created_at).toLocaleTimeString(),
        };
        setMessages((prev) => [...prev, assistantMsg]);
      } else if (res.isOffline) {
        const offlineFallbackMsg: ChatMessage = {
          id: Math.random().toString(),
          sender: "assistant",
          content: `⚠️ **Security Gateway Offline**\n\n${res.error}\n\n---\n\n### 🛡️ Simulated AI Triage Preview for: *"${textToSend}"*\n\n- **Inference Summary**: Query analyzed against pre-compiled baseline threat signatures. Under live FastAPI connectivity, isolation forest & autoencoder models evaluate behavioral anomaly deviance in real time.\n- **Correlated Techniques**: Evaluated against MITRE ATT&CK **T1071** (Standard Application Layer Protocol) & **T1041** (Exfiltration Over C2).\n- **Recommended Next Step**: Verify that the FastAPI backend is running and reachable, then rerun your investigation query.`,
          nextSteps: [
            "Check backend deployment status in Render / local environment",
            "Ensure NEXT_PUBLIC_API_URL is configured for the frontend service",
            "Rerun query once FastAPI reports healthy at /api/v1/health",
          ],
          uncertainty: "Simulated offline preview. Live model scoring requires an active FastAPI connection.",
          timestamp: new Date().toLocaleTimeString(),
        };
        setMessages((prev) => [...prev, offlineFallbackMsg]);
      } else {
        setMessages((prev) => [
          ...prev,
          {
            id: Math.random().toString(),
            sender: "assistant",
            content: `Investigation query failed: ${res.error || "Unknown error"}`,
            timestamp: new Date().toLocaleTimeString(),
          },
        ]);
      }
    } catch (e: any) {
      setMessages((prev) => [
        ...prev,
        {
          id: Math.random().toString(),
          sender: "assistant",
          content: `Error connecting to AI Threat Service: ${e.message}`,
          timestamp: new Date().toLocaleTimeString(),
        },
      ]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6 p-6 md:p-8">
      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <Link
            href="/ai-detection"
            className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-400 hover:text-slate-200"
          >
            <ArrowLeft className="h-4 w-4" />
            Back to AI Threat Hub
          </Link>
          <div className="mt-2 flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-violet-500/30 bg-violet-950/40 text-violet-400">
              <BrainCircuit className="h-6 w-6" />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-white md:text-3xl">
                AI Threat Investigation Assistant
              </h1>
              <p className="text-sm text-slate-400">
                Grounded conversational triage explaining model inferences, evidence chains, and correlated CVEs
              </p>
            </div>
          </div>
        </div>

        {detectionId && (
          <div className="rounded-lg border border-cyan-500/40 bg-cyan-950/30 px-3 py-1.5 text-xs font-mono text-cyan-300">
            Active Context: Detection {detectionId.slice(0, 8)}...
          </div>
        )}
      </div>

      {/* Suggested Prompt Pills */}
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs font-medium text-slate-400">Suggested Queries:</span>
        {[
          "Why was this event flagged and what evidence supports it?",
          "Which assets and vulnerabilities are correlated with this detection?",
          "What should the analyst investigate next?",
          "Does this indicator match known threat intelligence?",
        ].map((pill, idx) => (
          <button
            key={idx}
            onClick={() => handleSendQuery(pill)}
            className="rounded-full border border-slate-800 bg-slate-900/80 px-3 py-1 text-xs font-medium text-slate-300 transition-colors hover:border-violet-500/50 hover:bg-slate-800"
          >
            {pill}
          </button>
        ))}
      </div>

      {/* Chat Messages Console */}
      <div className="h-[60vh] overflow-y-auto rounded-xl border border-slate-800 bg-slate-900/60 p-6 backdrop-blur-md space-y-4">
        {messages.map((msg) => (
          <div
            key={msg.id}
            className={`flex flex-col ${
              msg.sender === "user" ? "items-end" : "items-start"
            }`}
          >
            <div
              className={`max-w-2xl rounded-xl p-4 text-sm ${
                msg.sender === "user"
                  ? "bg-violet-600 text-white rounded-br-none"
                  : "border border-slate-800 bg-slate-950/80 text-slate-200 rounded-bl-none"
              }`}
            >
              <div className="whitespace-pre-line leading-relaxed">{msg.content}</div>

              {/* Citations Panel */}
              {msg.citations && msg.citations.length > 0 && (
                <div className="mt-4 border-t border-slate-800 pt-3">
                  <div className="text-[11px] font-semibold text-cyan-400 uppercase tracking-wider mb-1.5">
                    Grounded Telemetry Citations
                  </div>
                  <div className="space-y-1">
                    {msg.citations.map((c, i) => (
                      <div key={i} className="flex items-center gap-2 text-xs text-slate-400 font-mono">
                        <Terminal className="h-3 w-3 text-cyan-400 shrink-0" />
                        <span>Record: {c.id?.slice(0, 8)}...</span>
                        <span>({c.category || "detection"})</span>
                        <span className="text-emerald-400 font-bold">Conf: {Math.round((c.confidence || 0.9) * 100)}%</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Recommended Next Steps */}
              {msg.nextSteps && msg.nextSteps.length > 0 && (
                <div className="mt-4 border-t border-slate-800 pt-3">
                  <div className="text-[11px] font-semibold text-amber-400 uppercase tracking-wider mb-1.5">
                    Recommended Investigative Actions
                  </div>
                  <ul className="space-y-1 text-xs text-slate-300">
                    {msg.nextSteps.map((step, i) => (
                      <li key={i} className="flex items-start gap-1.5">
                        <ChevronRight className="h-3.5 w-3.5 text-amber-400 mt-0.5 shrink-0" />
                        <span>{step}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Uncertainty Disclosure */}
              {msg.uncertainty && (
                <div className="mt-3 flex items-start gap-2 rounded bg-slate-900/90 p-2 text-[11px] text-slate-400 border border-slate-800/80">
                  <HelpCircle className="h-3.5 w-3.5 text-violet-400 mt-0.5 shrink-0" />
                  <span>
                    <strong className="text-slate-300">Evidence & Uncertainty:</strong> {msg.uncertainty}
                  </span>
                </div>
              )}

              <div className="mt-2 text-right text-[10px] text-slate-500">
                {msg.timestamp}
              </div>
            </div>
          </div>
        ))}

        {loading && (
          <div className="flex items-center gap-2 text-xs text-violet-400 p-2">
            <RefreshCw className="h-4 w-4 animate-spin" />
            <span>Analyzing authorized telemetry and isolating evidence...</span>
          </div>
        )}
      </div>

      {/* Input Box */}
      <div className="flex items-center gap-3">
        <input
          type="text"
          value={inputQuery}
          onChange={(e) => setInputQuery(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && handleSendQuery()}
          placeholder="Ask a threat investigation question (e.g. 'Why was this event flagged?')..."
          className="flex-1 rounded-xl border border-slate-800 bg-slate-900/80 px-4 py-3 text-sm text-white placeholder-slate-500 focus:border-violet-500 focus:outline-none"
        />
        <button
          onClick={() => handleSendQuery()}
          disabled={loading || !inputQuery.trim()}
          className="flex items-center gap-2 rounded-xl bg-violet-600 px-5 py-3 text-sm font-semibold text-white shadow-lg shadow-violet-950/50 hover:bg-violet-500 disabled:opacity-50"
        >
          <Send className="h-4 w-4" />
          Send
        </button>
      </div>
    </div>
  );
}

export default function AIThreatInvestigationPage() {
  return (
    <Suspense fallback={null}>
      <AIThreatInvestigationContent />
    </Suspense>
  );
}
