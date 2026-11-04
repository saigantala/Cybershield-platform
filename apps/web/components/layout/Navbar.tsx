"use client";

import { useState, useEffect } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import {
  Bell,
  Search,
  Plus,
  Radio,
  CheckCircle2,
  AlertTriangle,
  User,
  ExternalLink,
  X,
  Menu,
  Clock,
  ShieldCheck,
  LogOut,
  Sliders,
  ChevronDown,
} from "lucide-react";
import { mockCurrentUser, mockNotifications, mockScans } from "@/lib/mockData";
import { cn } from "@/lib/utils";
import { createClient } from "@/lib/supabase/client";
import { getBackendHealth } from "@/lib/api-client";

interface NavbarProps {
  onToggleMobileMenu?: () => void;
}

export function Navbar({ onToggleMobileMenu }: NavbarProps) {
  const router = useRouter();
  const [showNotifications, setShowNotifications] = useState(false);
  const [showProfileMenu, setShowProfileMenu] = useState(false);
  const [notifications, setNotifications] = useState(mockNotifications);
  const [currentTime, setCurrentTime] = useState("");
  const [liveUser, setLiveUser] = useState<{ email: string; fullName: string; role: string } | null>(null);
  const [backendState, setBackendState] = useState<{ isOnline: boolean; checked: boolean }>({
    isOnline: false,
    checked: false,
  });

  const activeScan = mockScans.find((s) => s.status === "running");

  useEffect(() => {
    async function checkApi() {
      const health = await getBackendHealth();
      setBackendState({ isOnline: health.isOnline, checked: true });
    }
    checkApi();
  }, []);

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      setCurrentTime(
        now.toLocaleTimeString("en-US", {
          hour: "2-digit",
          minute: "2-digit",
          second: "2-digit",
          hour12: false,
          timeZone: "UTC",
        }) + " UTC"
      );
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  // Fetch real authenticated operator if active session exists
  useEffect(() => {
    async function loadAuth() {
      try {
        const supabase = createClient();
        const {
          data: { user },
        } = await supabase.auth.getUser();

        if (user) {
          const fullName =
            user.user_metadata?.full_name ||
            user.email?.split("@")[0].replace(".", " ") ||
            "Security Operator";
          setLiveUser({
            email: user.email || "",
            fullName,
            role: "Operator",
          });
        }
      } catch {
        // Fall back gracefully to mock user in dev/preview
      }
    }
    loadAuth();
  }, []);

  const unreadCount = notifications.filter((n) => !n.read).length;

  const markAllRead = () => {
    setNotifications((prev) => prev.map((n) => ({ ...n, read: true })));
  };

  const handleSignOut = async () => {
    try {
      const supabase = createClient();
      await supabase.auth.signOut();
    } catch {
      // Ignore network errors on logout
    }
    setLiveUser(null);
    setShowProfileMenu(false);
    router.push("/login");
    router.refresh();
  };

  const currentDisplayUser = liveUser || {
    fullName: mockCurrentUser.fullName,
    email: mockCurrentUser.email,
    role: mockCurrentUser.role,
  };

  return (
    <header className="h-16 bg-[#080D18]/90 backdrop-blur-md border-b border-[#1E293B] sticky top-0 z-20 flex items-center justify-between px-4 sm:px-6">
      {/* Left: Mobile Toggle & Global Search Bar */}
      <div className="flex items-center gap-3 flex-1 max-w-lg">
        {onToggleMobileMenu && (
          <button
            onClick={onToggleMobileMenu}
            className="md:hidden p-2 rounded-lg bg-[#111C2D] border border-blue-500/20 text-slate-300 hover:text-white"
            aria-label="Open menu"
          >
            <Menu className="h-4 w-4" />
          </button>
        )}

        <div className="relative w-full">
          <Search className="h-4 w-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search assets, CVEs, IPs, or incidents (Press Ctrl + K)..."
            className="w-full bg-[#111C2D] border border-blue-500/20 rounded-lg pl-9 pr-14 py-1.5 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-400/60 focus:ring-1 focus:ring-cyan-400/40 transition-all"
          />
          <kbd className="hidden sm:inline-block absolute right-2.5 top-1/2 -translate-y-1/2 text-[10px] font-mono text-slate-400 bg-[#162338] px-1.5 py-0.5 rounded border border-slate-700">
            Ctrl K
          </kbd>
        </div>
      </div>

      {/* Right controls */}
      <div className="flex items-center gap-3 sm:gap-4 ml-2">
        {/* Ops Clock */}
        <div className="hidden lg:flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-[#111C2D] border border-blue-500/20 text-[11px] font-mono text-slate-300">
          <Clock className="h-3.5 w-3.5 text-cyan-400" />
          <span>{currentTime || "16:00:00 UTC"}</span>
        </div>

        {/* Live Active SOC indicator pill */}
        <div className="hidden sm:flex items-center gap-2 px-2.5 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs font-semibold">
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
            <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500" />
          </span>
          <span className="text-[11px] tracking-wider uppercase font-mono">
            {liveUser ? "AUTH ACTIVE" : "LIVE SOC"}
          </span>
        </div>

        {/* Backend Gateway Connectivity Badge */}
        <div
          className={cn(
            "hidden md:flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-mono font-semibold border transition-colors",
            backendState.isOnline
              ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-400"
              : "bg-blue-500/10 border-blue-500/20 text-slate-400"
          )}
          title={
            backendState.isOnline
              ? "FastAPI Security Gateway: Connected"
              : "FastAPI Security Gateway: Ready (Offline Standalone Mode)"
          }
        >
          <span
            className={cn(
              "h-1.5 w-1.5 rounded-full",
              backendState.isOnline ? "bg-emerald-400 animate-pulse" : "bg-cyan-400"
            )}
          />
          <span className="text-[10px] tracking-wider uppercase">
            {backendState.isOnline ? "API: ONLINE" : "API: READY"}
          </span>
        </div>

        {/* Active scan status indicator */}
        {activeScan && (
          <Link
            href="/scans"
            className="hidden xl:flex items-center gap-2 px-3 py-1.5 rounded-lg bg-blue-950/40 border border-blue-500/30 hover:border-blue-500/50 transition-colors"
          >
            <div className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75" />
              <span className="relative inline-flex rounded-full h-2 w-2 bg-cyan-500" />
            </div>
            <div className="text-xs truncate max-w-[160px]">
              <span className="text-slate-300 font-medium">{activeScan.title}</span>
              <span className="ml-2 font-mono text-cyan-400 font-semibold">
                {activeScan.progress}%
              </span>
            </div>
          </Link>
        )}

        {/* Quick Scan Action */}
        <Link
          href="/scans"
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-gradient-to-r from-blue-600 to-cyan-600 text-white text-xs font-semibold hover:shadow-lg hover:shadow-blue-500/20 active:scale-95 transition-all shrink-0"
        >
          <Plus className="h-3.5 w-3.5" />
          <span className="hidden sm:inline">Launch Scan</span>
        </Link>

        {/* Notification Bell */}
        <div className="relative">
          <button
            onClick={() => {
              setShowNotifications(!showNotifications);
              setShowProfileMenu(false);
            }}
            className="relative p-2 rounded-lg bg-[#111C2D] border border-blue-500/20 text-slate-300 hover:text-white hover:border-blue-500/40 transition-colors"
            aria-label="Notifications"
          >
            <Bell className="h-4 w-4" />
            {unreadCount > 0 && (
              <span className="absolute -top-1 -right-1 h-4 w-4 rounded-full bg-rose-500 text-white text-[10px] font-bold flex items-center justify-center animate-pulse">
                {unreadCount}
              </span>
            )}
          </button>

          {/* Notifications Dropdown */}
          {showNotifications && (
            <div className="absolute right-0 mt-2 w-80 sm:w-96 bg-[#111C2D] border border-blue-500/30 rounded-xl shadow-2xl p-3 z-50 animate-in fade-in-50 duration-150">
              <div className="flex items-center justify-between pb-2 mb-2 border-b border-[#1E293B]">
                <div className="flex items-center gap-2">
                  <h4 className="text-xs font-bold text-white uppercase tracking-wider">
                    SOC Security Alerts
                  </h4>
                  {unreadCount > 0 && (
                    <span className="text-[10px] font-semibold px-2 py-0.5 rounded-full bg-rose-500/20 text-rose-300 border border-rose-500/30">
                      {unreadCount} New
                    </span>
                  )}
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={markAllRead}
                    className="text-[11px] text-cyan-400 hover:underline"
                  >
                    Mark read
                  </button>
                  <button
                    onClick={() => setShowNotifications(false)}
                    className="text-slate-400 hover:text-white"
                  >
                    <X className="h-4 w-4" />
                  </button>
                </div>
              </div>

              <div className="space-y-2 max-h-80 overflow-y-auto pr-1">
                {notifications.map((notif) => (
                  <div
                    key={notif.id}
                    className={cn(
                      "p-2.5 rounded-lg border text-xs transition-colors",
                      notif.read
                        ? "bg-[#162338]/40 border-slate-800 text-slate-400"
                        : "bg-[#162338] border-blue-500/30 text-slate-200"
                    )}
                  >
                    <div className="flex items-start justify-between gap-2 mb-1">
                      <span className="font-semibold text-white flex items-center gap-1.5">
                        {notif.severity === "critical" ? (
                          <AlertTriangle className="h-3.5 w-3.5 text-rose-400 shrink-0" />
                        ) : (
                          <Radio className="h-3.5 w-3.5 text-cyan-400 shrink-0" />
                        )}
                        {notif.title}
                      </span>
                      <span className="text-[10px] text-slate-400 font-mono">
                        Just now
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-300 leading-relaxed">
                      {notif.message}
                    </p>
                    {notif.link && (
                      <Link
                        href={notif.link}
                        onClick={() => setShowNotifications(false)}
                        className="mt-1.5 inline-flex items-center gap-1 text-[11px] text-cyan-400 hover:underline font-medium"
                      >
                        Inspect finding <ExternalLink className="h-3 w-3" />
                      </Link>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* User Profile Dropdown */}
        <div className="relative">
          <button
            onClick={() => {
              setShowProfileMenu(!showProfileMenu);
              setShowNotifications(false);
            }}
            className="flex items-center gap-2 pl-2 border-l border-[#1E293B] hover:opacity-90 transition-opacity cursor-pointer"
          >
            <div className="h-8 w-8 rounded-full bg-gradient-to-tr from-blue-600 to-cyan-400 flex items-center justify-center font-bold text-xs text-white shadow-md shadow-blue-500/20">
              {currentDisplayUser.fullName.charAt(0).toUpperCase()}
            </div>
            <div className="hidden sm:block text-left">
              <p className="text-xs font-semibold text-slate-200 leading-tight">
                {currentDisplayUser.fullName}
              </p>
              <div className="flex items-center gap-1.5 mt-0.5">
                <span className="text-[9px] uppercase font-bold tracking-wider px-1.5 py-0.2 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                  {currentDisplayUser.role}
                </span>
                <span className="text-[10px] text-slate-400 font-mono">
                  {liveUser ? "Verified" : "Demo"}
                </span>
              </div>
            </div>
            <ChevronDown className="h-3.5 w-3.5 text-slate-400 hidden sm:block" />
          </button>

          {showProfileMenu && (
            <div className="absolute right-0 mt-2 w-60 bg-[#111C2D] border border-blue-500/30 rounded-xl shadow-2xl p-2 z-50 text-xs animate-in fade-in-50 duration-150">
              <div className="p-2 border-b border-slate-800 mb-1">
                <p className="font-bold text-white">{currentDisplayUser.fullName}</p>
                <p className="text-[11px] text-slate-400 font-mono truncate">
                  {currentDisplayUser.email}
                </p>
                {liveUser && (
                  <span className="mt-1 inline-flex items-center gap-1 text-[10px] text-emerald-400 font-medium">
                    <CheckCircle2 className="h-3 w-3" /> Supabase Session Active
                  </span>
                )}
              </div>

              <Link
                href="/settings"
                onClick={() => setShowProfileMenu(false)}
                className="flex items-center gap-2 px-2.5 py-2 rounded-lg text-slate-300 hover:text-white hover:bg-blue-600/20 transition-colors"
              >
                <Sliders className="h-3.5 w-3.5 text-cyan-400" />
                <span>Security Settings</span>
              </Link>

              <Link
                href="/audit-logs"
                onClick={() => setShowProfileMenu(false)}
                className="flex items-center gap-2 px-2.5 py-2 rounded-lg text-slate-300 hover:text-white hover:bg-blue-600/20 transition-colors"
              >
                <ShieldCheck className="h-3.5 w-3.5 text-emerald-400" />
                <span>Operator Audit Trail</span>
              </Link>

              <div className="my-1 border-t border-slate-800" />

              {liveUser ? (
                <button
                  onClick={handleSignOut}
                  className="w-full flex items-center gap-2 px-2.5 py-2 rounded-lg text-rose-400 hover:bg-rose-500/10 transition-colors text-left cursor-pointer"
                >
                  <LogOut className="h-3.5 w-3.5" />
                  <span>Sign Out Session</span>
                </button>
              ) : (
                <Link
                  href="/login"
                  onClick={() => setShowProfileMenu(false)}
                  className="flex items-center gap-2 px-2.5 py-2 rounded-lg text-cyan-400 hover:bg-cyan-500/10 transition-colors"
                >
                  <User className="h-3.5 w-3.5" />
                  <span>Authenticate Operator</span>
                </Link>
              )}
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
