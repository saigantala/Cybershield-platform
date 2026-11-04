"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  ShieldCheck,
  Globe,
  Terminal,
  Package,
  Container,
  AlertTriangle,
  History,
  Settings,
} from "lucide-react";
import { cn } from "@/lib/utils";

const navItems = [
  { name: "Overview", href: "/security-assurance", icon: ShieldCheck },
  { name: "App & OWASP", href: "/security-assurance/application", icon: Globe },
  { name: "API Pentest Suite", href: "/security-assurance/api", icon: Terminal },
  { name: "Dependencies", href: "/security-assurance/dependencies", icon: Package },
  { name: "Containers", href: "/security-assurance/containers", icon: Container },
  { name: "Findings Tracker", href: "/security-assurance/findings", icon: AlertTriangle },
  { name: "History & Trends", href: "/security-assurance/history", icon: History },
  { name: "Settings & Scopes", href: "/security-assurance/settings", icon: Settings },
];

export function SecurityAssuranceNav() {
  const pathname = usePathname();

  return (
    <div className="flex items-center gap-1 overflow-x-auto border-b border-slate-800/80 pb-2 mb-6 scrollbar-thin">
      {navItems.map((item) => {
        const Icon = item.icon;
        const isActive =
          item.href === "/security-assurance"
            ? pathname === "/security-assurance"
            : pathname.startsWith(item.href);

        return (
          <Link
            key={item.href}
            href={item.href}
            className={cn(
              "flex items-center gap-2 px-3 py-2 text-xs font-medium rounded-lg transition-all whitespace-nowrap",
              isActive
                ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 shadow-[0_0_15px_rgba(16,185,129,0.15)]"
                : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/40 border border-transparent"
            )}
          >
            <Icon className="w-3.5 h-3.5" />
            <span>{item.name}</span>
          </Link>
        );
      })}
    </div>
  );
}
