import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatDateTime(isoString?: string): string {
  if (!isoString) return "N/A";
  try {
    const d = new Date(isoString);
    return new Intl.DateTimeFormat("en-US", {
      month: "short",
      day: "numeric",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      hour12: false,
    }).format(d);
  } catch {
    return isoString;
  }
}

export function getSeverityColor(severity: string) {
  switch (severity?.toLowerCase()) {
    case "critical":
      return "text-[#FB7185] bg-[#FB7185]/10 border-[#FB7185]/30";
    case "high":
      return "text-[#F59E0B] bg-[#F59E0B]/10 border-[#F59E0B]/30";
    case "medium":
      return "text-[#38BDF8] bg-[#38BDF8]/10 border-[#38BDF8]/30";
    case "low":
      return "text-[#34D399] bg-[#34D399]/10 border-[#34D399]/30";
    default:
      return "text-[#94A3B8] bg-[#94A3B8]/10 border-[#94A3B8]/30";
  }
}

export function getStatusBadge(status: string) {
  switch (status?.toLowerCase()) {
    case "online":
    case "completed":
    case "resolved":
    case "approved":
      return "text-emerald-400 bg-emerald-500/10 border-emerald-500/30";
    case "running":
    case "investigating":
    case "in_progress":
      return "text-cyan-400 bg-cyan-500/10 border-cyan-500/30 animate-pulse";
    case "queued":
    case "pending_approval":
      return "text-amber-400 bg-amber-500/10 border-amber-500/30";
    case "failed":
    case "rejected":
    case "critical":
      return "text-rose-400 bg-rose-500/10 border-rose-500/30";
    case "cancelled":
    case "offline":
    case "closed":
      return "text-slate-400 bg-slate-500/10 border-slate-500/30";
    default:
      return "text-blue-400 bg-blue-500/10 border-blue-500/30";
  }
}
