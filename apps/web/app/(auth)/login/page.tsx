"use client";

import { useState, Suspense } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Lock, Mail, ArrowRight, AlertCircle, ShieldCheck, CheckCircle2 } from "lucide-react";
import { createClient } from "@/lib/supabase/client";

function LoginForm() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const redirectTo = searchParams.get("redirectTo") || "/";
  const callbackError = searchParams.get("error");

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState(callbackError || "");
  const [successMessage, setSuccessMessage] = useState("");

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage("");
    setSuccessMessage("");
    setLoading(true);

    if (!email || !password) {
      setErrorMessage("Please enter both email and password.");
      setLoading(false);
      return;
    }

    try {
      const supabase = createClient();
      const { data, error } = await supabase.auth.signInWithPassword({
        email: email.trim(),
        password,
      });

      if (error) {
        setErrorMessage(error.message);
        setLoading(false);
        return;
      }

      if (data?.session) {
        setSuccessMessage("Authentication verified. Redirecting to SOC...");
        setTimeout(() => {
          router.push(redirectTo);
          router.refresh();
        }, 500);
      }
    } catch (err: any) {
      setErrorMessage(err?.message || "Failed to authenticate with security server.");
      setLoading(false);
    }
  };

  return (
    <div className="soc-glass rounded-2xl p-6 sm:p-8 border border-blue-500/30 shadow-2xl space-y-6">
      <div className="text-center space-y-1.5">
        <div className="h-12 w-12 rounded-2xl bg-blue-600/20 border border-blue-500/40 text-cyan-400 flex items-center justify-center mx-auto mb-2 shadow-lg shadow-blue-500/20">
          <Lock className="h-6 w-6" />
        </div>
        <h2 className="text-xl font-black text-white tracking-tight">
          Operator Authentication
        </h2>
        <p className="text-xs text-slate-400">
          Enter your authorized credentials to access the SOC terminal
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

      <form onSubmit={handleLogin} className="space-y-4 text-xs">
        <div>
          <label className="text-slate-300 font-semibold block mb-1">
            Corporate Email
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

        <div>
          <div className="flex items-center justify-between mb-1">
            <label className="text-slate-300 font-semibold">Password</label>
            <Link
              href="/forgot-password"
              className="text-cyan-400 hover:underline text-[11px]"
            >
              Forgot password?
            </Link>
          </div>
          <div className="relative">
            <Lock className="h-4 w-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="password"
              placeholder="••••••••••••"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              className="w-full bg-[#0B1220] border border-blue-500/20 rounded-lg pl-9 pr-3 py-2 text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-400 font-mono"
            />
          </div>
        </div>

        <div className="p-3 rounded-lg bg-blue-950/30 border border-blue-500/20 text-[11px] text-slate-300 flex items-center gap-2">
          <ShieldCheck className="h-4 w-4 text-cyan-400 shrink-0" />
          <span>Supabase Auth Session &amp; RLS token validation active</span>
        </div>

        <button
          type="submit"
          disabled={loading}
          className="w-full flex items-center justify-center gap-2 py-2.5 rounded-lg bg-gradient-to-r from-blue-600 to-cyan-600 text-white font-bold text-xs hover:shadow-lg hover:shadow-blue-500/25 active:scale-95 transition-all disabled:opacity-70 cursor-pointer"
        >
          {loading ? (
            <span>Verifying Credentials...</span>
          ) : (
            <>
              <span>Authenticate &amp; Enter SOC</span>
              <ArrowRight className="h-4 w-4" />
            </>
          )}
        </button>
      </form>

      <div className="text-center pt-2 border-t border-slate-800 text-xs text-slate-400">
        New cybersecurity operator?{" "}
        <Link href="/signup" className="text-cyan-400 font-semibold hover:underline">
          Create Account
        </Link>
      </div>
    </div>
  );
}

export default function LoginPage() {
  return (
    <Suspense
      fallback={
        <div className="soc-glass rounded-2xl p-8 border border-blue-500/30 shadow-2xl text-center text-xs text-slate-400 animate-pulse">
          Loading authentication gateway...
        </div>
      }
    >
      <LoginForm />
    </Suspense>
  );
}
