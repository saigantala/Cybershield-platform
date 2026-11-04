"use client";

import { useEffect, useState, useRef } from "react";
import Link from "next/link";
import {
  FolderLock,
  Upload,
  FileCheck,
  Search,
  Copy,
  Check,
  Trash2,
  AlertTriangle,
  CheckCircle2,
  RefreshCw,
  FileText,
  Lock,
  X,
} from "lucide-react";
import { apiCompliance } from "@/lib/api-client";
import type { ComplianceEvidence } from "@/types/compliance";

export default function ComplianceEvidencePage() {
  const [evidenceList, setEvidenceList] = useState<ComplianceEvidence[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState("");
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  // Upload modal state
  const [showUploadModal, setShowUploadModal] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [description, setDescription] = useState("");
  const [controlId, setControlId] = useState("");
  const [uploading, setUploading] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [uploadSuccess, setUploadSuccess] = useState<string | null>(null);

  const fileInputRef = useRef<HTMLInputElement>(null);

  const loadEvidence = async () => {
    setLoading(true);
    const res = await apiCompliance.listEvidence();
    if (res.data) {
      setEvidenceList(res.data);
    } else {
      // Mock fallback
      setEvidenceList([
        {
          id: "83000000-0000-0000-0000-000000000001",
          organization_id: "e4a29a43-089c-4f70-a889-cb4c5b36dc32",
          control_id: "ID.AM-01",
          file_name: "asset_inventory_audit_signed.pdf",
          file_size: 245120,
          mime_type: "application/pdf",
          sha256_hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          storage_path: "evidence/e4a29a43-089c-4f70-a889-cb4c5b36dc32/audit_signed.pdf",
          description: "Signed Q3 Asset Inventory Verification Audit",
          uploaded_by: "Lead Infrastructure Architect",
          uploaded_at: "2026-10-15T12:00:00Z",
        },
      ]);
    }
    setLoading(false);
  };

  useEffect(() => {
    loadEvidence();
  }, []);

  const handleCopyHash = (hash: string) => {
    navigator.clipboard.writeText(hash);
    setCopiedHash(hash);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0];
      const disallowed = [".exe", ".bat", ".cmd", ".sh", ".ps1", ".vbs"];
      if (disallowed.some((ext) => file.name.toLowerCase().endsWith(ext))) {
        setUploadError("Executable files (.exe, .bat, .sh) are prohibited in the Evidence Vault.");
        setSelectedFile(null);
        return;
      }
      if (file.size > 26214400) {
        setUploadError("File exceeds the 25MB maximum allowable upload limit.");
        setSelectedFile(null);
        return;
      }
      setUploadError(null);
      setSelectedFile(file);
    }
  };

  const handleUploadSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedFile) return;

    setUploading(true);
    setUploadError(null);

    const formData = new FormData();
    formData.append("file", selectedFile);
    if (controlId) formData.append("control_id", controlId);
    if (description) formData.append("description", description);

    const res = await apiCompliance.uploadEvidence(formData);
    setUploading(false);

    if (res.data) {
      setUploadSuccess(`Evidence '${res.data.file_name}' uploaded successfully with SHA-256 integrity hash.`);
      setShowUploadModal(false);
      setSelectedFile(null);
      setDescription("");
      setControlId("");
      loadEvidence();
      setTimeout(() => setUploadSuccess(null), 4000);
    } else {
      setUploadError(res.error || "Upload failed");
    }
  };

  const handleDelete = async (evidenceId: string) => {
    if (!confirm("Permanently delete this compliance evidence file from the vault?")) return;
    const res = await apiCompliance.deleteEvidence(evidenceId);
    if (res.data) {
      loadEvidence();
    }
  };

  const filteredEvidence = evidenceList.filter(
    (e) =>
      e.file_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (e.control_id && e.control_id.toLowerCase().includes(searchTerm.toLowerCase())) ||
      (e.description && e.description.toLowerCase().includes(searchTerm.toLowerCase()))
  );

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return "0 Bytes";
    const k = 1024;
    const sizes = ["Bytes", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2 text-xs text-slate-400 mb-1">
            <Link href="/compliance" className="hover:text-cyan-400 transition-colors">
              Compliance
            </Link>
            <span>/</span>
            <span className="text-cyan-400 font-medium">Evidence Vault</span>
          </div>
          <h1 className="text-2xl font-black text-white tracking-tight flex items-center gap-2.5">
            <FolderLock className="h-6 w-6 text-cyan-400" />
            Compliance Evidence Vault & Audit Trail
          </h1>
          <p className="text-sm text-slate-400 mt-0.5">
            Cryptographically hashed repository of audit artifacts, architecture diagrams, and signed policies.
          </p>
        </div>

        <button
          onClick={() => setShowUploadModal(true)}
          className="px-4 py-2 rounded-xl text-xs font-semibold bg-gradient-to-r from-blue-600 to-cyan-500 hover:from-blue-500 hover:to-cyan-400 text-white shadow-lg shadow-blue-500/20 flex items-center gap-2 transition-all self-start md:self-auto"
        >
          <Upload className="h-4 w-4" />
          Upload Evidence
        </button>
      </div>

      {uploadSuccess && (
        <div className="p-3.5 rounded-xl bg-emerald-500/10 border border-emerald-500/30 flex items-center gap-3 text-emerald-300 text-xs">
          <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-400" />
          <span>{uploadSuccess}</span>
        </div>
      )}

      {/* Search Toolbar */}
      <div className="p-4 rounded-2xl bg-[#111C2D]/80 border border-slate-800/80 backdrop-blur-md flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="relative flex-1 max-w-md">
          <Search className="h-4 w-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
          <input
            type="text"
            placeholder="Search by filename, control ID, or description..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-9 pr-4 py-2 rounded-xl bg-slate-900 border border-slate-700 text-xs text-white focus:outline-none focus:border-cyan-500"
          />
        </div>

        <div className="text-xs text-slate-400 font-mono">
          {filteredEvidence.length} Stored Evidence Artifacts
        </div>
      </div>

      {/* Evidence Table */}
      <div className="rounded-2xl bg-[#111C2D]/80 border border-slate-800/80 backdrop-blur-md overflow-hidden">
        {filteredEvidence.length === 0 ? (
          <div className="p-8 text-center text-xs text-slate-500">
            No compliance evidence uploaded yet. Click &quot;Upload Evidence&quot; to attach audit artifacts.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-900/60 text-slate-400 border-b border-slate-800">
                <tr>
                  <th className="py-3 px-4 font-semibold">File Name</th>
                  <th className="py-3 px-4 font-semibold">Associated Control</th>
                  <th className="py-3 px-4 font-semibold">Size & Type</th>
                  <th className="py-3 px-4 font-semibold">SHA-256 Integrity Hash</th>
                  <th className="py-3 px-4 font-semibold">Uploaded</th>
                  <th className="py-3 px-4 font-semibold text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {filteredEvidence.map((ev) => (
                  <tr key={ev.id} className="hover:bg-slate-800/20 transition-colors">
                    <td className="py-3.5 px-4">
                      <div className="flex items-center gap-2.5">
                        <FileText className="h-4 w-4 text-cyan-400 shrink-0" />
                        <div>
                          <div className="font-semibold text-white">{ev.file_name}</div>
                          {ev.description && (
                            <div className="text-[11px] text-slate-400 mt-0.5 truncate max-w-xs">
                              {ev.description}
                            </div>
                          )}
                        </div>
                      </div>
                    </td>

                    <td className="py-3.5 px-4 font-mono font-bold text-cyan-300">
                      {ev.control_id || <span className="text-slate-500 font-normal">General</span>}
                    </td>

                    <td className="py-3.5 px-4 font-mono text-slate-300">
                      <div>{formatBytes(ev.file_size)}</div>
                      <div className="text-[10px] text-slate-500 font-normal truncate max-w-[120px]">
                        {ev.mime_type}
                      </div>
                    </td>

                    <td className="py-3.5 px-4">
                      <div className="flex items-center gap-2">
                        <code className="text-[11px] font-mono text-slate-400 bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
                          {ev.sha256_hash.slice(0, 16)}...{ev.sha256_hash.slice(-8)}
                        </code>
                        <button
                          onClick={() => handleCopyHash(ev.sha256_hash)}
                          className="p-1 rounded text-slate-500 hover:text-cyan-400 transition-colors"
                          title="Copy Full SHA-256 Hash"
                        >
                          {copiedHash === ev.sha256_hash ? (
                            <Check className="h-3.5 w-3.5 text-emerald-400" />
                          ) : (
                            <Copy className="h-3.5 w-3.5" />
                          )}
                        </button>
                      </div>
                    </td>

                    <td className="py-3.5 px-4 font-mono text-slate-400">
                      {new Date(ev.uploaded_at).toLocaleDateString()}
                    </td>

                    <td className="py-3.5 px-4 text-right">
                      <button
                        onClick={() => handleDelete(ev.id)}
                        className="p-1.5 rounded-lg text-slate-500 hover:text-rose-400 hover:bg-rose-500/10 transition-colors"
                        title="Delete Evidence"
                      >
                        <Trash2 className="h-4 w-4" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Upload Evidence Modal */}
      {showUploadModal && (
        <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="w-full max-w-md p-6 rounded-2xl bg-[#111C2D] border border-cyan-500/40 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2 text-sm font-bold text-white">
                <Upload className="h-4 w-4 text-cyan-400" />
                Upload Compliance Evidence
              </div>
              <button
                onClick={() => setShowUploadModal(false)}
                className="text-slate-400 hover:text-white"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            {uploadError && (
              <div className="p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs flex items-center gap-2">
                <AlertTriangle className="h-4 w-4 shrink-0" />
                <span>{uploadError}</span>
              </div>
            )}

            <form onSubmit={handleUploadSubmit} className="space-y-4">
              <div className="space-y-1.5">
                <label className="text-xs font-medium text-slate-300">Select File (PDF, DOCX, PNG, CSV - Max 25MB)</label>
                <input
                  type="file"
                  ref={fileInputRef}
                  onChange={handleFileChange}
                  required
                  className="w-full text-xs text-slate-400 file:mr-3 file:py-2 file:px-3 file:rounded-xl file:border-0 file:text-xs file:font-semibold file:bg-cyan-500/20 file:text-cyan-300 hover:file:bg-cyan-500/30 cursor-pointer"
                />
              </div>

              <div className="space-y-1.5">
                <label className="text-xs font-medium text-slate-300">Associated Control ID (Optional)</label>
                <input
                  type="text"
                  placeholder="e.g. ID.AM-01 or CIS-1.1"
                  value={controlId}
                  onChange={(e) => setControlId(e.target.value)}
                  className="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-700 text-xs text-white focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="space-y-1.5">
                <label className="text-xs font-medium text-slate-300">Evidence Description & Audit Notes</label>
                <textarea
                  rows={3}
                  placeholder="Document artifact context, auditor sign-off, or verification method..."
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  className="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-700 text-xs text-white focus:outline-none focus:border-cyan-500 resize-none"
                />
              </div>

              <div className="pt-3 border-t border-slate-800 flex items-center justify-end gap-3">
                <button
                  type="button"
                  onClick={() => setShowUploadModal(false)}
                  className="px-4 py-2 rounded-xl text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={uploading || !selectedFile}
                  className="px-4 py-2 rounded-xl text-xs font-semibold bg-gradient-to-r from-blue-600 to-cyan-500 hover:from-blue-500 hover:to-cyan-400 text-white shadow-lg shadow-blue-500/20 flex items-center gap-1.5 transition-all disabled:opacity-50"
                >
                  {uploading ? (
                    <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                  ) : (
                    <Upload className="h-3.5 w-3.5" />
                  )}
                  Upload to Vault
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
