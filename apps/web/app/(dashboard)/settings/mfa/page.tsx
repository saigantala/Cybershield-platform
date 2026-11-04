"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  Smartphone,
  ShieldCheck,
  Key,
  Copy,
  Check,
  RefreshCw,
  AlertTriangle,
  Lock,
  ArrowLeft,
  Download,
  Fingerprint,
  Zap,
} from "lucide-react";
import { apiIdentity } from "@/lib/api-client";
import type {
  MFASetupResponse,
  MFARecoveryCodeResponse,
  UserSecurityOverview,
} from "@/types/identity";

export default function MFASettingsPage() {
  const [overview, setOverview] = useState<UserSecurityOverview | null>(null);
  const [setupData, setSetupData] = useState<MFASetupResponse | null>(null);
  const [totpCode, setTotpCode] = useState("");
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);
  const [rotateCode, setRotateCode] = useState("");
  const [stepUpCode, setStepUpCode] = useState("");
  const [stepUpResult, setStepUpResult] = useState<string | null>(null);

  const [loading, setLoading] = useState(false);
  const [verifying, setVerifying] = useState(false);
  const [rotating, setRotating] = useState(false);
  const [steppingUp, setSteppingUp] = useState(false);
  const [copiedKey, setCopiedKey] = useState(false);
  const [copiedCodes, setCopiedCodes] = useState(false);
  const [statusMessage, setStatusMessage] = useState<{ type: "success" | "error"; text: string } | null>(null);

  const loadOverview = async () => {
    try {
      setLoading(true);
      const res = await apiIdentity.getOverview();
      if (res.data) {
        setOverview(res.data);
      }
    } catch (e: any) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadOverview();
  }, []);

  const handleStartSetup = async () => {
    try {
      setLoading(true);
      setStatusMessage(null);
      const res = await apiIdentity.setupMFA();
      if (res.data) {
        setSetupData(res.data);
      } else {
        setStatusMessage({ type: "error", text: res.error || "Failed to initiate MFA setup" });
      }
    } catch (err: any) {
      setStatusMessage({ type: "error", text: err?.message || "Failed to initiate MFA setup" });
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyCode = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!totpCode || totpCode.length < 6) return;

    try {
      setVerifying(true);
      setStatusMessage(null);
      const res = await apiIdentity.verifyMFA({ code: totpCode.trim() });
      if (res.data?.success) {
        setStatusMessage({
          type: "success",
          text: "MFA verified and enabled successfully! Save your recovery codes below.",
        });
        if (res.data.recovery_codes) {
          setRecoveryCodes(res.data.recovery_codes);
        }
        setSetupData(null);
        setTotpCode("");
        loadOverview();
      } else {
        setStatusMessage({
          type: "error",
          text: res.error || "Invalid verification code. Please check your authenticator clock.",
        });
      }
    } catch (err: any) {
      setStatusMessage({ type: "error", text: err?.message || "Verification failed." });
    } finally {
      setVerifying(false);
    }
  };

  const handleRotateRecoveryCodes = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!rotateCode || rotateCode.length < 6) return;

    try {
      setRotating(true);
      setStatusMessage(null);
      const res = await apiIdentity.rotateRecoveryCodes(rotateCode.trim());
      if (res.data) {
        setRecoveryCodes(res.data.recovery_codes);
        setRotateCode("");
        setStatusMessage({
          type: "success",
          text: "Recovery codes rotated successfully. Old codes are permanently invalidated.",
        });
        loadOverview();
      } else {
        setStatusMessage({ type: "error", text: res.error || "Failed to rotate recovery codes" });
      }
    } catch (err: any) {
      setStatusMessage({ type: "error", text: err?.message || "Rotation failed." });
    } finally {
      setRotating(false);
    }
  };

  const handleTestStepUp = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!stepUpCode || stepUpCode.length < 6) return;

    try {
      setSteppingUp(true);
      setStepUpResult(null);
      const res = await apiIdentity.stepUpAuth("export_evidence", stepUpCode.trim());
      if (res.data?.success) {
        setStepUpResult(`Step-Up Granted! Token: ${res.data.step_up_token.slice(0, 30)}... (Valid 5 mins)`);
        setStepUpCode("");
      } else {
        setStatusMessage({ type: "error", text: res.error || "Step-up authentication rejected" });
      }
    } catch (err: any) {
      setStatusMessage({ type: "error", text: err?.message || "Step-up authorization failed." });
    } finally {
      setSteppingUp(false);
    }
  };

  const copySecretKey = () => {
    if (setupData?.secret) {
      navigator.clipboard.writeText(setupData.secret);
      setCopiedKey(true);
      setTimeout(() => setCopiedKey(false), 2000);
    }
  };

  const copyRecoveryCodes = () => {
    if (recoveryCodes.length > 0) {
      navigator.clipboard.writeText(recoveryCodes.join("\n"));
      setCopiedCodes(true);
      setTimeout(() => setCopiedCodes(false), 2000);
    }
  };

  const downloadRecoveryCodes = () => {
    if (recoveryCodes.length === 0) return;
    const blob = new Blob([
      "CYBERSHIELD ENTERPRISE SOC - BACKUP RECOVERY CODES\n",
      "Confidential & Single-Use\n\n",
      recoveryCodes.join("\n"),
      "\n\nEach code can only be used once. Generated at: " + new Date().toISOString(),
    ], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "cybershield-recovery-codes.txt";
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6 max-w-5xl">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <Link
            href="/settings/security"
            className="inline-flex items-center gap-1.5 text-xs text-slate-400 hover:text-cyan-400 mb-2 transition-colors"
          >
            <ArrowLeft className="w-3.5 h-3.5" /> Back to Security Overview
          </Link>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
            <Smartphone className="w-6 h-6 text-emerald-400" />
            Multi-Factor Authentication (MFA)
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Enforce Time-Based One-Time Passwords (RFC 6238 TOTP) and secure single-use recovery code vaults.
          </p>
        </div>
        <div className="flex items-center gap-2">
          {overview?.mfa_enabled ? (
            <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
              <ShieldCheck className="w-4 h-4" /> MFA Enrolled (AAL2)
            </span>
          ) : (
            <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/30">
              <AlertTriangle className="w-4 h-4" /> MFA Not Configured
            </span>
          )}
        </div>
      </div>

      {/* Alert Messages */}
      {statusMessage && (
        <div
          className={`p-4 rounded-xl border flex items-center gap-3 text-sm ${
            statusMessage.type === "success"
              ? "bg-emerald-950/40 border-emerald-500/40 text-emerald-200"
              : "bg-rose-950/40 border-rose-500/40 text-rose-200"
          }`}
        >
          {statusMessage.type === "success" ? (
            <ShieldCheck className="w-5 h-5 text-emerald-400 shrink-0" />
          ) : (
            <AlertTriangle className="w-5 h-5 text-rose-400 shrink-0" />
          )}
          <span>{statusMessage.text}</span>
        </div>
      )}

      {/* Enrollment Card */}
      <div className="p-6 rounded-2xl bg-slate-900/40 border border-slate-800 backdrop-blur-xl">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-6 border-b border-slate-800">
          <div>
            <h2 className="text-lg font-semibold text-white">Authenticator App (TOTP)</h2>
            <p className="text-xs text-slate-400 mt-1">
              Supports Google Authenticator, 1Password, Bitwarden, Microsoft Authenticator, and YubiKey.
            </p>
          </div>
          {!setupData && (
            <button
              onClick={handleStartSetup}
              disabled={loading}
              className="px-4 py-2 text-sm font-semibold text-black bg-cyan-400 hover:bg-cyan-300 rounded-xl transition-all shadow-lg shadow-cyan-500/20 cursor-pointer whitespace-nowrap"
            >
              {overview?.mfa_enabled ? "Re-configure Authenticator" : "Setup Authenticator App"}
            </button>
          )}
        </div>

        {/* Setup Wizard */}
        {setupData && (
          <div className="mt-6 grid grid-cols-1 md:grid-cols-2 gap-8 items-start">
            {/* Step 1: Scan QR */}
            <div className="space-y-4">
              <span className="text-xs font-bold uppercase tracking-wider text-cyan-400">Step 1: Scan QR Code</span>
              <div
                className="w-52 h-52 p-3 bg-slate-950 rounded-2xl border border-cyan-500/30 flex items-center justify-center shadow-xl shadow-cyan-950/40"
                dangerouslySetInnerHTML={{ __html: setupData.qr_code_svg }}
              />
              <div className="space-y-1">
                <span className="text-xs text-slate-400">Can't scan? Use manual setup key:</span>
                <div className="flex items-center gap-2">
                  <code className="px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 font-mono text-xs text-cyan-300 select-all">
                    {setupData.secret}
                  </code>
                  <button
                    onClick={copySecretKey}
                    className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
                    title="Copy Key"
                  >
                    {copiedKey ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                  </button>
                </div>
              </div>
            </div>

            {/* Step 2: Verify Code */}
            <div className="space-y-4">
              <span className="text-xs font-bold uppercase tracking-wider text-cyan-400">Step 2: Enter Verification Code</span>
              <p className="text-xs text-slate-400">
                Enter the 6-digit verification code generated by your authenticator app to finalize enrollment.
              </p>
              <form onSubmit={handleVerifyCode} className="space-y-4">
                <div>
                  <input
                    type="text"
                    maxLength={6}
                    value={totpCode}
                    onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, ""))}
                    placeholder="000000"
                    className="w-48 px-4 py-3 text-center tracking-widest text-2xl font-mono rounded-xl bg-slate-950 border border-cyan-500/40 text-cyan-300 focus:outline-none focus:ring-2 focus:ring-cyan-400"
                    required
                  />
                </div>
                <div className="flex items-center gap-3">
                  <button
                    type="submit"
                    disabled={verifying || totpCode.length < 6}
                    className="px-5 py-2.5 text-sm font-semibold text-black bg-cyan-400 hover:bg-cyan-300 disabled:opacity-50 rounded-xl transition-all shadow-lg shadow-cyan-500/20 cursor-pointer"
                  >
                    {verifying ? "Verifying..." : "Verify & Activate MFA"}
                  </button>
                  <button
                    type="button"
                    onClick={() => setSetupData(null)}
                    className="px-4 py-2.5 text-sm font-medium text-slate-400 hover:text-white bg-slate-800/60 rounded-xl transition-all"
                  >
                    Cancel
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}
      </div>

      {/* Recovery Codes Vault */}
      <div className="p-6 rounded-2xl bg-slate-900/40 border border-slate-800 backdrop-blur-xl">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800">
          <div>
            <h2 className="text-lg font-semibold text-white flex items-center gap-2">
              <Key className="w-5 h-5 text-amber-400" />
              Backup Recovery Codes
            </h2>
            <p className="text-xs text-slate-400 mt-1">
              Single-use rescue credentials when authenticator devices are unavailable.
            </p>
          </div>
          {recoveryCodes.length > 0 && (
            <div className="flex items-center gap-2">
              <button
                onClick={copyRecoveryCodes}
                className="px-3 py-1.5 text-xs font-medium text-slate-300 hover:text-white bg-slate-800 hover:bg-slate-700 rounded-lg transition-colors flex items-center gap-1.5"
              >
                {copiedCodes ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                Copy All
              </button>
              <button
                onClick={downloadRecoveryCodes}
                className="px-3 py-1.5 text-xs font-medium text-slate-300 hover:text-white bg-slate-800 hover:bg-slate-700 rounded-lg transition-colors flex items-center gap-1.5"
              >
                <Download className="w-3.5 h-3.5" /> Download .txt
              </button>
            </div>
          )}
        </div>

        {recoveryCodes.length > 0 ? (
          <div className="mt-4">
            <div className="p-3 rounded-xl bg-amber-500/10 border border-amber-500/20 text-xs text-amber-300 mb-4">
              <strong>IMPORTANT:</strong> Store these 10 recovery codes in a secure password manager. Each code can only be used once. CyberShield support cannot recover your account without these codes.
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-5 gap-2.5">
              {recoveryCodes.map((code, idx) => (
                <div
                  key={idx}
                  className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-center font-mono text-xs font-semibold text-cyan-300 select-all"
                >
                  {code}
                </div>
              ))}
            </div>
          </div>
        ) : (
          <div className="mt-4 text-xs text-slate-400 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <p>
              Recovery codes were generated during your initial enrollment. You currently have{" "}
              <span className="text-cyan-400 font-semibold">{overview?.recovery_codes_remaining ?? 10}</span> unused codes.
            </p>
          </div>
        )}

        {/* Rotate Recovery Codes Section */}
        <div className="mt-6 pt-4 border-t border-slate-800/60">
          <form onSubmit={handleRotateRecoveryCodes} className="flex flex-col sm:flex-row sm:items-center gap-3">
            <input
              type="text"
              maxLength={6}
              value={rotateCode}
              onChange={(e) => setRotateCode(e.target.value.replace(/\D/g, ""))}
              placeholder="Current 6-digit TOTP"
              className="w-48 px-3 py-2 text-sm font-mono rounded-lg bg-slate-950 border border-slate-700 text-white focus:outline-none focus:border-cyan-400"
            />
            <button
              type="submit"
              disabled={rotating || rotateCode.length < 6}
              className="px-4 py-2 text-xs font-semibold text-slate-200 hover:text-white bg-slate-800 hover:bg-slate-700 disabled:opacity-50 rounded-lg transition-colors flex items-center gap-2 cursor-pointer"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${rotating ? "animate-spin" : ""}`} />
              Rotate Recovery Codes
            </button>
          </form>
        </div>
      </div>

      {/* Step-Up Authentication Sandbox */}
      <div className="p-6 rounded-2xl bg-gradient-to-r from-purple-950/30 to-slate-900/40 border border-purple-500/20 backdrop-blur-xl">
        <div className="flex items-center gap-3 mb-2">
          <Zap className="w-5 h-5 text-purple-400" />
          <h2 className="text-base font-semibold text-white">Step-Up Authentication Demonstration</h2>
        </div>
        <p className="text-xs text-slate-400 mb-4 leading-relaxed">
          Critical operations (such as digital forensics evidence extraction, API key regeneration, or IdP configuration changes) demand instantaneous TOTP re-verification to elevate session assurance to AAL2.
        </p>

        <form onSubmit={handleTestStepUp} className="flex flex-col sm:flex-row sm:items-center gap-3">
          <input
            type="text"
            maxLength={6}
            value={stepUpCode}
            onChange={(e) => setStepUpCode(e.target.value.replace(/\D/g, ""))}
            placeholder="6-digit TOTP"
            className="w-48 px-3 py-2 text-sm font-mono rounded-lg bg-slate-950 border border-purple-500/40 text-purple-300 focus:outline-none focus:ring-2 focus:ring-purple-400"
          />
          <button
            type="submit"
            disabled={steppingUp || stepUpCode.length < 6}
            className="px-4 py-2 text-xs font-semibold text-white bg-purple-600 hover:bg-purple-500 disabled:opacity-50 rounded-lg transition-colors flex items-center gap-2 cursor-pointer shadow-lg shadow-purple-900/30"
          >
            <ShieldCheck className="w-4 h-4" />
            {steppingUp ? "Authorizing..." : "Request Sensitive Step-Up Token"}
          </button>
        </form>

        {stepUpResult && (
          <div className="mt-4 p-3 rounded-xl bg-purple-950/40 border border-purple-500/40 text-xs text-purple-200 font-mono">
            {stepUpResult}
          </div>
        )}
      </div>
    </div>
  );
}
