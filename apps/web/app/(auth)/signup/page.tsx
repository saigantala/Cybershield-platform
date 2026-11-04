"use client";

import { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Shield, Mail, Lock, User, ArrowRight, AlertCircle, CheckCircle2, Building2 } from "lucide-react";
import { createClient } from "@/lib/supabase/client";

export default function SignupPage() {
  const router = useRouter();
  const [fullName, setFullName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [orgName, setOrgName] = useState("");
  const [loading, setLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState("");
  const [successMessage, setSuccessMessage] = useState("");

  const handleSignup = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage("");
    setSuccessMessage("");
    setLoading(true);

    if (!fullName.trim() || !email.trim() || !password) {
      setErrorMessage("Please complete all required fields.");
      setLoading(false);
      return;
    }

    if (password.length < 8) {
      setErrorMessage("Password must be at least 8 characters long.");
      setLoading(false);
      return;
    }

    try {
      const supabase = createClient();
      const origin = typeof window !== "undefined" ? window.location.origin : "";

      const { data, error } = await supabase.auth.signUp({
        email: email.trim(),
        password,
        options: {
          emailRedirectTo: `${origin}/auth/callback`,
          data: {
            full_name: fullName.trim(),
            organization_name: orgName.trim() || "Default Security Org",
          },
        },
      });

      if (error) {
        setErrorMessage(error.message);
        setLoading(false);
        return;
      }

      if (data?.session) {
        setSuccessMessage("Account created successfully! Redirecting to SOC...");
        setTimeout(() => {
          router.push("/");
          router.refresh();
        }, 800);
      } else if (data?.user) {
        setSuccessMessage(
          "Registration initialized! Please check your email for the confirmation link to activate your SOC operator profile."
        );
        setLoading(false);
      }
    } catch (err: any) {
      setErrorMessage(err?.message || "Failed to initialize registration with Supabase.");
      setLoading(false);
    }
  };

  return (
    <div className="soc-glass rounded-2xl p-6 sm:p-8 border border-blue-500/30 shadow-2xl space-y-6">
      <div className="text-center space-y-1.5">
        <div className="h-12 w-12 rounded-2xl bg-cyan-600/20 border border-cyan-500/40 text-cyan-400 flex items-center justify-center mx-auto mb-2 shadow-lg shadow-cyan-500/20">
          <Shield className="h-6 w-6" />
        </div>
        <h2 className="text-xl font-black text-white tracking-tight">
          Register Security Operator
        </h2>
        <p className="text-xs text-slate-400">
          Create your tenant workspace profile with automated RLS isolation
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

      <form onSubmit={handleSignup} className="space-y-4 text-xs">
        <div>
          <label className="text-slate-300 font-semibold block mb-1">
            Operator Full Name
          </label>
          <div className="relative">
            <User className="h-4 w-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Elena Rostova"
              value={fullName}
              onChange={(e) => setFullName(e.target.value)}
              required
              className="w-full bg-[#0B1220] border border-blue-500/20 rounded-lg pl-9 pr-3 py-2 text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-400"
            />
          </div>
        </div>

        <div>
          <label className="text-slate-300 font-semibold block mb-1">
            Organization / Tenant Name
          </label>
          <div className="relative">
            <Building2 className="h-4 w-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="e.g. Nexus Defense Labs"
              value={orgName}
              onChange={(e) => setOrgName(e.target.value)}
              className="w-full bg-[#0B1220] border border-blue-500/20 rounded-lg pl-9 pr-3 py-2 text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-400"
            />
          </div>
        </div>

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
          <label className="text-slate-300 font-semibold block mb-1">
            Master Security Key (Password)
          </label>
          <div className="relative">
            <Lock className="h-4 w-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="password"
              placeholder="Minimum 8 characters"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              minLength={8}
              className="w-full bg-[#0B1220] border border-blue-500/20 rounded-lg pl-9 pr-3 py-2 text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-400 font-mono"
            />
          </div>
        </div>

        <button
          type="submit"
          disabled={loading}
          className="w-full flex items-center justify-center gap-2 py-2.5 rounded-lg bg-gradient-to-r from-blue-600 to-cyan-600 text-white font-bold text-xs hover:shadow-lg hover:shadow-blue-500/25 active:scale-95 transition-all disabled:opacity-70 cursor-pointer"
        >
          {loading ? (
            <span>Creating Operator Profile...</span>
          ) : (
            <>
              <span>Provision Profile &amp; Join</span>
              <ArrowRight className="h-4 w-4" />
            </>
          )}
        </button>
      </form>

      <div className="text-center pt-2 border-t border-slate-800 text-xs text-slate-400">
        Already registered?{" "}
        <Link href="/login" className="text-cyan-400 font-semibold hover:underline">
          Sign In
        </Link>
      </div>
    </div>
  );
}
