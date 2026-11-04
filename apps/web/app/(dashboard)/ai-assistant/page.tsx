"use client";

import { useState, useEffect, useRef } from "react";
import Link from "next/link";
import {
  Bot,
  User,
  Send,
  Plus,
  Trash2,
  Copy,
  Check,
  RefreshCw,
  Sparkles,
  Shield,
  AlertTriangle,
  Bug,
  Server,
  Flame,
  ExternalLink,
  MessageSquare,
  Clock,
  CheckCircle2,
  Info,
} from "lucide-react";
import {
  AIChatResponse,
  AIConversationSummary,
  ChatMessage,
  SourceReference,
} from "@/types/ai";
import { apiAI } from "@/lib/api-client";
import { formatDateTime } from "@/lib/utils";

const SUGGESTED_QUERIES = [
  "Summarize today's security activity",
  "Identify my highest-risk assets",
  "Explain my critical vulnerabilities",
  "Summarize unresolved incidents",
  "Explain CVE-2024-21762 in simple terms",
];

export default function AIAssistantPage() {
  const [conversations, setConversations] = useState<AIConversationSummary[]>([]);
  const [activeConversationId, setActiveConversationId] = useState<string | null>(null);
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      role: "assistant",
      content:
        "Welcome to the **CyberShield AI SOC Assistant**. I am connected to your organization's security telemetry in read-only mode.\n\n" +
        "You can ask me to analyze open vulnerabilities, evaluate high-risk assets, summarize active incidents, or interpret CVE and threat intelligence records. How can I assist your investigation today?",
      source_references: [],
      created_at: new Date().toISOString(),
    },
  ]);
  const [inputQuery, setInputQuery] = useState("");
  const [loading, setLoading] = useState(false);
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);
  const [selectedRef, setSelectedRef] = useState<SourceReference | null>(null);
  const [error, setError] = useState<string | null>(null);

  const messagesEndRef = useRef<HTMLDivElement>(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages, loading]);

  const fetchConversations = async () => {
    try {
      const res = await apiAI.listConversations();
      if (res.data) {
        setConversations(res.data);
      }
    } catch (e) {
      // Ignore initial load error
    }
  };

  useEffect(() => {
    fetchConversations();
  }, []);

  const handleSelectConversation = async (convId: string) => {
    setActiveConversationId(convId);
    setLoading(true);
    setError(null);
    try {
      const res = await apiAI.getConversation(convId);
      if (res.data && res.data.messages) {
        setMessages(res.data.messages);
      }
    } catch (e: any) {
      setError(e?.message || "Failed to load conversation history.");
    } finally {
      setLoading(false);
    }
  };

  const handleNewConversation = () => {
    setActiveConversationId(null);
    setMessages([
      {
        role: "assistant",
        content:
          "Starting a new security consultation. Ask me about critical vulnerabilities, asset risks, active alerts, or incident playbooks.",
        source_references: [],
        created_at: new Date().toISOString(),
      },
    ]);
  };

  const handleDeleteConversation = async (convId: string, e: React.MouseEvent) => {
    e.stopPropagation();
    try {
      await apiAI.deleteConversation(convId);
      setConversations((prev) => prev.filter((c) => c.id !== convId));
      if (activeConversationId === convId) {
        handleNewConversation();
      }
    } catch (err: any) {
      alert(err?.message || "Failed to delete conversation.");
    }
  };

  const handleSendMessage = async (textToSend?: string) => {
    const query = (textToSend || inputQuery).trim();
    if (!query || loading) return;

    setInputQuery("");
    setError(null);

    // Optimistically add user message
    const userMsg: ChatMessage = {
      role: "user",
      content: query,
      created_at: new Date().toISOString(),
    };
    setMessages((prev) => [...prev, userMsg]);
    setLoading(true);

    try {
      let res;
      if (activeConversationId) {
        res = await apiAI.postMessage(activeConversationId, query);
      } else {
        res = await apiAI.chat(query);
      }

      if (res.data) {
        const assistantMsg: ChatMessage = {
          role: "assistant",
          content: res.data.response,
          source_references: res.data.source_references || [],
          created_at: res.data.created_at || new Date().toISOString(),
        };
        setMessages((prev) => [...prev, assistantMsg]);
        if (!activeConversationId && res.data.conversation_id) {
          setActiveConversationId(res.data.conversation_id);
          fetchConversations();
        }
      }
    } catch (err: any) {
      setError(err?.message || "Failed to generate AI response.");
    } finally {
      setLoading(false);
    }
  };

  const handleCopy = (content: string, idx: number) => {
    navigator.clipboard.writeText(content);
    setCopiedIndex(idx);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  return (
    <div className="flex h-[calc(100vh-5.5rem)] gap-4">
      {/* Left History Sidebar */}
      <div className="hidden md:flex w-72 flex-col bg-[#111C2D]/80 border border-slate-800/80 rounded-2xl backdrop-blur-md overflow-hidden">
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Bot className="w-5 h-5 text-blue-400" />
            <span className="text-sm font-bold text-white">Consultations</span>
          </div>
          <button
            onClick={handleNewConversation}
            className="flex items-center gap-1 px-2.5 py-1 text-xs font-semibold rounded-lg bg-blue-600/20 hover:bg-blue-600/30 text-blue-400 border border-blue-500/30 transition-all"
          >
            <Plus className="w-3.5 h-3.5" /> New
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-2 space-y-1">
          {conversations.length === 0 ? (
            <div className="p-4 text-center text-xs text-slate-500">
              No previous consultations recorded.
            </div>
          ) : (
            conversations.map((c) => (
              <div
                key={c.id}
                onClick={() => handleSelectConversation(c.id)}
                className={`group flex items-center justify-between p-2.5 rounded-xl text-xs cursor-pointer transition-all ${
                  activeConversationId === c.id
                    ? "bg-blue-600/20 text-blue-300 border border-blue-500/30 font-medium"
                    : "text-slate-400 hover:bg-slate-800/60 hover:text-slate-200 border border-transparent"
                }`}
              >
                <div className="flex items-center gap-2 truncate pr-2">
                  <MessageSquare className="w-3.5 h-3.5 shrink-0 opacity-70" />
                  <span className="truncate">{c.title}</span>
                </div>
                <button
                  onClick={(e) => handleDeleteConversation(c.id, e)}
                  className="opacity-0 group-hover:opacity-100 hover:text-rose-400 p-1 transition-opacity"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              </div>
            ))
          )}
        </div>

        {/* Guardrail Disclaimer */}
        <div className="p-3 border-t border-slate-800 bg-[#080D18]/50 text-[11px] text-slate-500 flex items-start gap-2">
          <Shield className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
          <span>Multi-tenant isolated, read-only AI. Does not execute actions without human sign-off.</span>
        </div>
      </div>

      {/* Main Chat Pane */}
      <div className="flex-1 flex flex-col bg-[#111C2D]/80 border border-slate-800/80 rounded-2xl backdrop-blur-md overflow-hidden">
        {/* Chat Header */}
        <div className="px-5 py-3.5 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-gradient-to-tr from-blue-600/30 to-cyan-500/30 border border-blue-500/30 text-cyan-400">
              <Sparkles className="w-5 h-5 animate-pulse" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-base font-bold text-white tracking-tight">AI SOC Assistant</h2>
                <span className="px-2 py-0.5 text-[10px] font-mono font-semibold rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                  MOCK ENGINE (SAFE DEV)
                </span>
                <span className="px-2 py-0.5 text-[10px] font-mono font-semibold rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                  READ-ONLY GUARDRAILS
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Autonomous security inquiry, CVE research, and incident triage reasoning.
              </p>
            </div>
          </div>
          <button
            onClick={handleNewConversation}
            className="md:hidden flex items-center gap-1 px-3 py-1.5 text-xs font-semibold rounded-lg bg-blue-600 text-white"
          >
            <Plus className="w-3.5 h-3.5" /> New
          </button>
        </div>

        {/* Message Stream */}
        <div className="flex-1 overflow-y-auto p-5 space-y-5">
          {messages.map((msg, idx) => (
            <div
              key={idx}
              className={`flex items-start gap-3.5 ${msg.role === "user" ? "flex-row-reverse" : ""}`}
            >
              {msg.role === "user" ? (
                <div className="w-8 h-8 rounded-lg bg-blue-600 text-white flex items-center justify-center shrink-0 shadow-md">
                  <User className="w-4 h-4" />
                </div>
              ) : (
                <div className="w-8 h-8 rounded-lg bg-cyan-500/20 border border-cyan-500/30 text-cyan-400 flex items-center justify-center shrink-0">
                  <Bot className="w-4 h-4" />
                </div>
              )}

              <div
                className={`max-w-[85%] rounded-2xl p-4 text-xs leading-relaxed space-y-3 ${
                  msg.role === "user"
                    ? "bg-blue-600/90 text-white rounded-tr-none shadow-lg"
                    : "bg-[#080D18]/90 border border-slate-800 text-slate-200 rounded-tl-none shadow-md backdrop-blur-sm"
                }`}
              >
                <div className="whitespace-pre-line font-sans">{msg.content}</div>

                {/* Grounded Citation Badges */}
                {msg.source_references && msg.source_references.length > 0 && (
                  <div className="pt-2 border-t border-slate-800/80">
                    <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-500 block mb-1.5">
                      Verified Grounded Telemetry Citations:
                    </span>
                    <div className="flex flex-wrap gap-1.5">
                      {msg.source_references.map((ref, rIdx) => (
                        <button
                          key={rIdx}
                          onClick={() => setSelectedRef(ref)}
                          className="inline-flex items-center gap-1 px-2 py-0.5 text-[11px] rounded-md bg-slate-900 border border-slate-700/80 hover:border-cyan-500/60 text-cyan-400 font-mono transition-colors"
                        >
                          <ExternalLink className="w-2.5 h-2.5" />
                          <span>{ref.name}</span>
                          {ref.severity && (
                            <span className="text-[9px] px-1 rounded bg-slate-800 text-slate-400">
                              {ref.severity}
                            </span>
                          )}
                        </button>
                      ))}
                    </div>
                  </div>
                )}

                {/* Bubble Footer */}
                {msg.role === "assistant" && (
                  <div className="flex items-center justify-between text-[10px] text-slate-500 pt-1">
                    <span className="flex items-center gap-1">
                      <Sparkles className="w-3 h-3 text-cyan-400" /> AI-Generated Analysis • Verify Critical Actions
                    </span>
                    <button
                      onClick={() => handleCopy(msg.content, idx)}
                      className="hover:text-slate-300 transition-colors flex items-center gap-1"
                    >
                      {copiedIndex === idx ? (
                        <>
                          <Check className="w-3 h-3 text-emerald-400" /> Copied
                        </>
                      ) : (
                        <>
                          <Copy className="w-3 h-3" /> Copy
                        </>
                      )}
                    </button>
                  </div>
                )}
              </div>
            </div>
          ))}

          {loading && (
            <div className="flex items-start gap-3.5">
              <div className="w-8 h-8 rounded-lg bg-cyan-500/20 border border-cyan-500/30 text-cyan-400 flex items-center justify-center shrink-0">
                <Bot className="w-4 h-4 animate-spin" />
              </div>
              <div className="bg-[#080D18]/90 border border-slate-800 rounded-2xl rounded-tl-none p-4 text-xs text-slate-400 flex items-center gap-2">
                <span className="h-2 w-2 rounded-full bg-cyan-400 animate-ping" />
                <span>Retrieving authorized organization telemetry & formulating reasoning...</span>
              </div>
            </div>
          )}

          {error && (
            <div className="p-3.5 rounded-xl bg-rose-500/10 border border-rose-500/20 text-xs text-rose-300 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          <div ref={messagesEndRef} />
        </div>

        {/* Suggested Prompts Ticker */}
        <div className="px-5 py-2 border-t border-slate-800/80 bg-[#080D18]/40 flex items-center gap-2 overflow-x-auto text-xs">
          <span className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider shrink-0 flex items-center gap-1">
            <Sparkles className="w-3 h-3 text-blue-400" /> Suggested:
          </span>
          {SUGGESTED_QUERIES.map((q, idx) => (
            <button
              key={idx}
              onClick={() => handleSendMessage(q)}
              className="px-2.5 py-1 rounded-lg bg-slate-800/70 hover:bg-slate-700/80 text-slate-300 hover:text-white border border-slate-700/50 whitespace-nowrap transition-colors"
            >
              {q}
            </button>
          ))}
        </div>

        {/* Input Bar */}
        <div className="p-4 border-t border-slate-800 bg-[#080D18]/60">
          <form
            onSubmit={(e) => {
              e.preventDefault();
              handleSendMessage();
            }}
            className="flex items-center gap-3"
          >
            <input
              type="text"
              placeholder="Ask the AI SOC Assistant about vulnerabilities, assets, alerts, CVEs, or playbooks..."
              value={inputQuery}
              onChange={(e) => setInputQuery(e.target.value)}
              className="flex-1 px-4 py-2.5 bg-[#111C2D] border border-slate-700/80 rounded-xl text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500/70 transition-colors"
            />
            <button
              type="submit"
              disabled={loading || !inputQuery.trim()}
              className="px-4 py-2.5 rounded-xl bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500 text-white text-xs font-semibold shadow-lg shadow-blue-500/20 disabled:opacity-40 transition-all flex items-center gap-1.5"
            >
              <Send className="w-3.5 h-3.5" />
              <span>Send</span>
            </button>
          </form>
        </div>
      </div>

      {/* Citation Deep-Dive Modal */}
      {selectedRef && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="bg-[#111C2D] border border-slate-800 rounded-2xl w-full max-w-md shadow-2xl p-5 space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <Info className="w-4 h-4 text-cyan-400" />
                <h3 className="text-sm font-bold text-white">Grounded Citation Details</h3>
              </div>
              <button
                onClick={() => setSelectedRef(null)}
                className="text-slate-400 hover:text-white p-1 text-xs"
              >
                Close
              </button>
            </div>
            <div className="space-y-2 text-xs">
              <div>
                <span className="text-slate-500">Source Type: </span>
                <span className="font-semibold text-slate-200 uppercase">{selectedRef.source_type}</span>
              </div>
              <div>
                <span className="text-slate-500">Entity Identifier: </span>
                <code className="text-cyan-400 font-mono text-[11px]">{selectedRef.name}</code>
              </div>
              {selectedRef.summary && (
                <div>
                  <span className="text-slate-500">Summary: </span>
                  <p className="text-slate-300 mt-1 leading-relaxed">{selectedRef.summary}</p>
                </div>
              )}
              {selectedRef.severity && (
                <div>
                  <span className="text-slate-500">Severity: </span>
                  <span className="px-1.5 py-0.5 rounded bg-slate-900 text-amber-400 font-semibold text-[10px]">
                    {selectedRef.severity}
                  </span>
                </div>
              )}
            </div>
            <div className="pt-2 flex justify-end">
              <button
                onClick={() => setSelectedRef(null)}
                className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-slate-200"
              >
                Dismiss
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
