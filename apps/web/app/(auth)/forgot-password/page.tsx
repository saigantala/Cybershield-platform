"use client";

import { useState } from "react";
import Link from "next/link";
import { Mail, ArrowRight, AlertCircle, CheckCircle2, KeyRound } from "lucide-react";
import { createClient } from "@/lib/supabase/client";

export default function ForgotPasswordPage() {
  const [email, setEmail] = useState("");
  const [loading, setLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState("");
  const [successMessage, setSuccessMessage] = useState("");

  const handleReset = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage("");
    setSuccessMessage("");
    setLoading(true);

    if (!email.trim()) {
      setErrorMessage("Please enter your registered corporate email.");
      setLoading(false);
      return;
    }

    try {
      const supabase = createClient();
      const origin = typeof window !== "undefined" ? window.location.origin : "";

      const { error } = await supabase.auth.resetPasswordForEmail(email.trim(), {
        redirectTo: `${origin}/auth/callback?next=/settings`,
      });

      if (error) {
        setErrorMessage(error.message);
        setLoading(false);
        return;
      }

      setSuccessMessage(
        "Password recovery link dispatched. If an account matches this email, check your inbox to reset your password."
      );
      setLoading(false);
    } catch (err: any) {
      setErrorMessage(err?.message || "Failed to process recovery request.");
      setLoading(false);
    }
  };

  return (
    <div className="soc-glass rounded-2xl p-6 sm:p-8 border border-blue-500/30 shadow-2xl space-y-6">
      <div className="text-center space-y-1.5">
        <div className="h-12 w-12 rounded-2xl bg-amber-600/20 border border-amber-500/40 text-amber-400 flex items-center justify-center mx-auto mb-2 shadow-lg shadow-amber-500/20">
          <KeyRound className="h-6 w-6" />
        </div>
        <h2 className="text-xl font-black text-white tracking-tight">
          Recover Security Key
        </h2>
        <p className="text-xs text-slate-400">
          Receive a cryptographic password reset token to restore your session
        </p>
      </div>

      {errorMessage && (
        <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-start gap-2">
          <AlertCircle className="h-4 w-4 shrink-0 mt-0.5 text-rose-400" />
          <span>{errorMessage}</span>
        </div>
      )}

      {successMessage && (
        <div className="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs flex items-start gap-2">
          <CheckCircle2 className="h-4 w-4 shrink-0 mt-0.5 text-emerald-400" />
          <span>{successMessage}</span>
        </div>
      )}

      <form onSubmit={handleReset} className="space-y-4 text-xs">
        <div>
          <label className="text-slate-300 font-semibold block mb-1">
            Registered Corporate Email
          </label>
          <div className="relative">
            <Mail className="h-4 w-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="email"
              placeholder="analyst@nexusdefense.internal"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              className="w-full bg-[#0B1220] border border-blue-500/20 rounded-lg pl-9 pr-3 py-2 text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-400"
            />
          </div>
        </div>

        <button
          type="submit"
          disabled={loading}
          className="w-full flex items-center justify-center gap-2 py-2.5 rounded-lg bg-gradient-to-r from-blue-600 to-cyan-600 text-white font-bold text-xs hover:shadow-lg hover:shadow-blue-500/25 active:scale-95 transition-all disabled:opacity-70 cursor-pointer"
        >
          {loading ? (
            <span>Dispatching Reset Token...</span>
          ) : (
            <>
              <span>Send Recovery Link</span>
              <ArrowRight className="h-4 w-4" />
            </>
          )}
        </button>
      </form>

      <div className="text-center pt-2 border-t border-slate-800 text-xs text-slate-400">
        Remember your password?{" "}
        <Link href="/login" className="text-cyan-400 font-semibold hover:underline">
          Return to Sign In
        </Link>
      </div>
    </div>
  );
}
