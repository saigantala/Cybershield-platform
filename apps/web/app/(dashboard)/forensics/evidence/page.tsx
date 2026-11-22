"use client";
export const dynamic = 'force-dynamic';

import { useEffect, useState, Suspense } from "react";
import { useSearchParams } from "next/navigation";
import Link from "next/link";
import {
  FolderArchive,
  HardDrive,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  Search,
  Plus,
  RefreshCw,
  Clock,
  Layers,
  Lock,
  ArrowRight,
  FileCode,
  X,
  FileText,
  History,
} from "lucide-react";
import { apiForensics } from "@/lib/api-client";
import type {
  ForensicEvidenceItem,
  ForensicEvidenceItemCreate,
  ForensicCustodyEvent,
  CustodyChainVerificationResponse,
  EvidenceCategory,
} from "@/types/forensics";

function ForensicEvidenceVaultContent() {
  const searchParams = useSearchParams();
  const verifyParam = searchParams.get("verify");

  const [evidenceList, setEvidenceList] = useState<ForensicEvidenceItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState("");
  const [categoryFilter, setCategoryFilter] = useState("All");

  // Custody Chain Drawer / Modal
  const [activeEvidence, setActiveEvidence] = useState<ForensicEvidenceItem | null>(null);
  const [custodyChain, setCustodyChain] = useState<ForensicCustodyEvent[]>([]);
  const [loadingCustody, setLoadingCustody] = useState(false);
  const [verificationResult, setVerificationResult] = useState<CustodyChainVerificationResponse | null>(null);
  const [verifying, setVerifying] = useState(false);

  // New Evidence Modal
  const [showUploadModal, setShowUploadModal] = useState(false);
  const [cases, setCases] = useState<any[]>([]);
  const [selectedCaseId, setSelectedCaseId] = useState("");
  const [evName, setEvName] = useState("");
  const [evFilename, setEvFilename] = useState("");
  const [evCategory, setEvCategory] = useState<EvidenceCategory>("log_file");
  const [evDesc, setEvDesc] = useState("");
  const [uploading, setUploading] = useState(false);

  const loadData = async () => {
    setLoading(true);
    try {
      const [evRes, casesRes] = await Promise.all([
        apiForensics.listEvidence(),
        apiForensics.listCases(),
      ]);
      if (evRes.data) setEvidenceList(evRes.data);
      if (casesRes.data) {
        setCases(casesRes.data);
        if (casesRes.data.length > 0) setSelectedCaseId(casesRes.data[0].id);
      }

      if (verifyParam && evRes.data) {
        const found = evRes.data.find((e) => e.id === verifyParam);
        if (found) handleOpenCustody(found);
      }
    } catch (err) {
      console.error("Failed to load evidence vault:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleOpenCustody = async (item: ForensicEvidenceItem) => {
    setActiveEvidence(item);
    setVerificationResult(null);
    setLoadingCustody(true);
    try {
      const res = await apiForensics.getCustodyChain(item.id);
      if (res.data) setCustodyChain(res.data);
    } catch (err) {
      console.error("Failed to load custody chain:", err);
    } finally {
      setLoadingCustody(false);
    }
  };

  const handleVerifyChain = async () => {
    if (!activeEvidence) return;
    setVerifying(true);
    try {
      const res = await apiForensics.verifyChain(activeEvidence.id);
      if (res.data) setVerificationResult(res.data);
    } catch (err) {
      console.error("Failed to verify chain:", err);
    } finally {
      setVerifying(false);
    }
  };

  const handleUploadEvidence = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedCaseId || !evName || !evFilename) return;
    setUploading(true);
    try {
      const payload: ForensicEvidenceItemCreate = {
        forensic_case_id: selectedCaseId,
        evidence_name: evName,
        category: evCategory,
        original_filename: evFilename,
        description: evDesc || undefined,
      };
      const res = await apiForensics.uploadEvidence(payload);
      if (res.data) {
        setEvidenceList([res.data, ...evidenceList]);
        setShowUploadModal(false);
        setEvName("");
        setEvFilename("");
        setEvDesc("");
      }
    } catch (err) {
      console.error("Failed to preserve evidence:", err);
    } finally {
      setUploading(false);
    }
  };

  const filteredEvidence = evidenceList.filter((e) => {
    if (categoryFilter !== "All" && e.category !== categoryFilter) return false;
    if (
      searchQuery &&
      !e.evidence_name.toLowerCase().includes(searchQuery.toLowerCase()) &&
      !e.original_filename.toLowerCase().includes(searchQuery.toLowerCase()) &&
      !e.sha256_hash.toLowerCase().includes(searchQuery.toLowerCase())
    ) {
      return false;
    }
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b border-slate-800/80 pb-6">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-purple-500/10 text-purple-400 border border-purple-500/20 shadow-lg shadow-purple-500/5">
              <FolderArchive className="h-6 w-6" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-slate-100">Digital Evidence Vault</h1>
              <p className="text-sm text-slate-400">
                Immutable bitstream preservation with cryptographic SHA-256 tamper-evident chain of custody
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={loadData}
            disabled={loading}
            className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-slate-800/80 hover:bg-slate-700/80 text-slate-300 border border-slate-700/60 transition text-sm font-medium"
          >
            <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </button>
          <button
            onClick={() => setShowUploadModal(true)}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white shadow-lg shadow-purple-500/20 text-sm font-medium transition"
          >
            <Plus className="h-4 w-4" />
            Ingest Evidence Artifact
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col md:flex-row gap-4 justify-between items-center bg-slate-900/60 backdrop-blur-md border border-slate-800/80 rounded-xl p-4 shadow-xl">
        <div className="relative w-full md:w-96">
          <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
          <input
            type="text"
            placeholder="Search by label, filename, or SHA-256 hash..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-10 pr-4 py-2 bg-slate-800/60 border border-slate-700/60 rounded-lg text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-purple-500/50"
          />
        </div>

        <div className="flex items-center gap-2 w-full md:w-auto">
          <span className="text-xs text-slate-400">Category:</span>
          <select
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            className="bg-slate-800/70 border border-slate-700/60 text-slate-200 text-xs rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-purple-500/50"
          >
            <option value="All">All Categories</option>
            <option value="log_file">Log Files</option>
            <option value="network_metadata_pcap">Network PCAP Flows</option>
            <option value="memory_dump_metadata">Memory Dump Artifacts</option>
            <option value="disk_artifact">Disk Image Artifacts</option>
            <option value="csv_export">CSV Data Exports</option>
            <option value="screenshot">Screenshots</option>
          </select>
        </div>
      </div>

      {/* Evidence Table */}
      <div className="bg-slate-900/60 backdrop-blur-md border border-slate-800/80 rounded-xl overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-slate-300">
            <thead className="bg-slate-800/60 text-slate-400 uppercase tracking-wider text-[10px] border-b border-slate-800">
              <tr>
                <th className="py-3 px-4">Artifact Label</th>
                <th className="py-3 px-4">Category</th>
                <th className="py-3 px-4">Filename & Size</th>
                <th className="py-3 px-4">Cryptographic Hash (SHA-256)</th>
                <th className="py-3 px-4">Integrity Status</th>
                <th className="py-3 px-4 text-right">Chain of Custody</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {loading ? (
                <tr>
                  <td colSpan={6} className="text-center py-16 text-slate-500">
                    <RefreshCw className="h-6 w-6 animate-spin mx-auto mb-2 text-purple-400" />
                    Loading digital evidence vault...
                  </td>
                </tr>
              ) : filteredEvidence.length === 0 ? (
                <tr>
                  <td colSpan={6} className="text-center py-16 text-slate-500">
                    No evidence artifacts found matching your criteria.
                  </td>
                </tr>
              ) : (
                filteredEvidence.map((e) => (
                  <tr key={e.id} className="hover:bg-slate-800/30 transition">
                    <td className="py-3 px-4 font-semibold text-slate-100">
                      {e.evidence_name}
                      {e.is_derived && (
                        <span className="ml-2 text-[10px] px-1.5 py-0.2 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/20 font-mono">
                          Derived
                        </span>
                      )}
                    </td>
                    <td className="py-3 px-4">
                      <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700 text-[11px] capitalize">
                        {e.category.replace("_", " ")}
                      </span>
                    </td>
                    <td className="py-3 px-4 font-mono text-slate-400 text-[11px]">
                      <div>{e.original_filename}</div>
                      <span className="text-slate-500 text-[10px]">
                        {(e.file_size / (1024 * 1024)).toFixed(2)} MB
                      </span>
                    </td>
                    <td className="py-3 px-4 font-mono text-[11px] text-purple-300 max-w-xs truncate">
                      {e.sha256_hash}
                    </td>
                    <td className="py-3 px-4">
                      <span className="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-bold text-[10px] flex items-center gap-1 w-fit">
                        <CheckCircle2 className="h-3 w-3" />
                        {e.integrity_status}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-right">
                      <button
                        onClick={() => handleOpenCustody(e)}
                        className="px-3 py-1 rounded bg-purple-600/20 hover:bg-purple-600/30 text-purple-300 border border-purple-500/30 font-medium transition"
                      >
                        Inspect Chain
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Chain of Custody Drawer / Modal */}
      {activeEvidence && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm animate-in fade-in">
          <div className="w-full max-w-2xl bg-slate-900 border border-slate-800 rounded-xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
            <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800">
              <div className="flex items-center gap-2 text-purple-400">
                <ShieldCheck className="h-5 w-5" />
                <h3 className="font-semibold text-slate-100">Cryptographic Chain of Custody</h3>
              </div>
              <button
                onClick={() => setActiveEvidence(null)}
                className="text-slate-400 hover:text-slate-200 transition"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            {/* Evidence Header */}
            <div className="p-6 border-b border-slate-800 bg-slate-950/40 space-y-2">
              <div className="flex items-center justify-between">
                <h4 className="text-base font-bold text-slate-100">{activeEvidence.evidence_name}</h4>
                <button
                  onClick={handleVerifyChain}
                  disabled={verifying}
                  className="flex items-center gap-2 px-3.5 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold shadow transition disabled:opacity-50"
                >
                  {verifying ? <RefreshCw className="h-3.5 w-3.5 animate-spin" /> : <ShieldCheck className="h-3.5 w-3.5" />}
                  Verify Hash Continuity
                </button>
              </div>
              <p className="text-xs font-mono text-slate-400">
                Bitstream SHA-256: <strong className="text-purple-300">{activeEvidence.sha256_hash}</strong>
              </p>

              {/* Verification Live Alert */}
              {verificationResult && (
                <div
                  className={`p-3 rounded-lg border text-xs flex items-center gap-2.5 ${
                    verificationResult.is_chain_valid
                      ? "bg-emerald-500/10 text-emerald-300 border-emerald-500/30"
                      : "bg-rose-500/10 text-rose-300 border-rose-500/30"
                  }`}
                >
                  {verificationResult.is_chain_valid ? (
                    <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-400" />
                  ) : (
                    <AlertTriangle className="h-4 w-4 shrink-0 text-rose-400" />
                  )}
                  <div>
                    <strong className="block font-semibold">
                      {verificationResult.is_chain_valid ? "Cryptographic Chain Verified" : "Hash Continuity Broken"}
                    </strong>
                    <span>{verificationResult.details}</span>
                  </div>
                </div>
              )}
            </div>

            {/* Custody Chain Blocks */}
            <div className="p-6 overflow-y-auto space-y-4 flex-1">
              {loadingCustody ? (
                <div className="text-center py-10 text-slate-400 text-xs">
                  <RefreshCw className="h-5 w-5 animate-spin mx-auto mb-2 text-purple-400" />
                  Loading cryptographic custody records...
                </div>
              ) : custodyChain.length === 0 ? (
                <div className="text-center py-10 text-slate-500 text-xs">
                  No custody records logged for this artifact yet.
                </div>
              ) : (
                custodyChain.map((ce, idx) => (
                  <div
                    key={ce.id}
                    className="p-4 rounded-xl bg-slate-800/40 border border-slate-800 space-y-2 relative"
                  >
                    <div className="flex items-center justify-between text-xs">
                      <div className="flex items-center gap-2">
                        <span className="font-mono font-bold text-purple-400">#{idx + 1}</span>
                        <span className="px-2 py-0.5 rounded bg-purple-500/10 text-purple-300 border border-purple-500/20 font-semibold text-[11px]">
                          {ce.action}
                        </span>
                        <span className="text-slate-300 font-medium">by {ce.actor_name}</span>
                      </div>
                      <span className="text-slate-500 font-mono text-[11px]">
                        {new Date(ce.timestamp).toLocaleString()}
                      </span>
                    </div>

                    <div className="space-y-1 text-[11px] font-mono text-slate-400 pt-1">
                      <div className="truncate">
                        Prev Hash: <span className="text-slate-500">{ce.previous_record_hash}</span>
                      </div>
                      <div className="truncate">
                        Curr Hash: <span className="text-emerald-300">{ce.current_record_hash}</span>
                      </div>
                    </div>

                    {ce.metadata && Object.keys(ce.metadata).length > 0 && (
                      <div className="text-[10px] text-slate-500 pt-1 border-t border-slate-800/80">
                        Metadata: {JSON.stringify(ce.metadata)}
                      </div>
                    )}
                  </div>
                ))
              )}
            </div>

            <div className="p-4 border-t border-slate-800 bg-slate-950 flex justify-end">
              <button
                onClick={() => setActiveEvidence(null)}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium transition"
              >
                Close Vault
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Upload Modal */}
      {showUploadModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-in fade-in">
          <div className="w-full max-w-lg bg-slate-900 border border-slate-800 rounded-xl shadow-2xl overflow-hidden">
            <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800">
              <div className="flex items-center gap-2 text-purple-400">
                <FolderArchive className="h-5 w-5" />
                <h3 className="font-semibold text-slate-100">Preserve Digital Evidence</h3>
              </div>
              <button
                onClick={() => setShowUploadModal(false)}
                className="text-slate-400 hover:text-slate-200 transition"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <form onSubmit={handleUploadEvidence} className="p-6 space-y-4">
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Target Forensic Case <span className="text-rose-400">*</span>
                </label>
                <select
                  required
                  value={selectedCaseId}
                  onChange={(e) => setSelectedCaseId(e.target.value)}
                  className="w-full px-3.5 py-2 bg-slate-800 border border-slate-700 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-purple-500"
                >
                  {cases.map((c) => (
                    <option key={c.id} value={c.id}>
                      {c.case_number} - {c.title}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Evidence Label / Title <span className="text-rose-400">*</span>
                </label>
                <input
                  type="text"
                  required
                  placeholder="e.g. DC-01 Security Event Log Bitstream"
                  value={evName}
                  onChange={(e) => setEvName(e.target.value)}
                  className="w-full px-3.5 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-purple-500"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Original Filename <span className="text-rose-400">*</span>
                </label>
                <input
                  type="text"
                  required
                  placeholder="e.g. dc01_security_evtx_export.json"
                  value={evFilename}
                  onChange={(e) => setEvFilename(e.target.value)}
                  className="w-full px-3.5 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-purple-500 font-mono"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">Category</label>
                <select
                  value={evCategory}
                  onChange={(e) => setEvCategory(e.target.value as EvidenceCategory)}
                  className="w-full px-3.5 py-2 bg-slate-800 border border-slate-700 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-purple-500"
                >
                  <option value="log_file">Log File</option>
                  <option value="network_metadata_pcap">Network PCAP Flow Metadata</option>
                  <option value="memory_dump_metadata">Memory Dump Artifact</option>
                  <option value="disk_artifact">Disk Image Artifact</option>
                  <option value="csv_export">CSV Data Export</option>
                  <option value="screenshot">Screenshot</option>
                </select>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">Description / Notes</label>
                <textarea
                  rows={2}
                  placeholder="Bitstream preservation notes..."
                  value={evDesc}
                  onChange={(e) => setEvDesc(e.target.value)}
                  className="w-full px-3.5 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-purple-500"
                />
              </div>

              <div className="flex justify-end gap-3 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowUploadModal(false)}
                  className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-sm font-medium transition"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={uploading}
                  className="px-4 py-2 rounded-lg bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white text-sm font-medium shadow-lg shadow-purple-500/20 transition flex items-center gap-2"
                >
                  {uploading && <RefreshCw className="h-4 w-4 animate-spin" />}
                  Register & Compute SHA-256
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

export default function ForensicEvidenceVaultPage() {
  return (
    <Suspense fallback={null}>
      <ForensicEvidenceVaultContent />
    </Suspense>
  );
}
