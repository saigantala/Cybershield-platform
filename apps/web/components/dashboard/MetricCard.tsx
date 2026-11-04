import { LucideIcon } from "lucide-react";
import { cn } from "@/lib/utils";

interface MetricCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: LucideIcon;
  trend?: {
    value: string;
    positive: boolean;
  };
  accentColor?: "blue" | "cyan" | "rose" | "amber" | "emerald";
  badge?: string;
}

export function MetricCard({
  title,
  value,
  subtitle,
  icon: Icon,
  trend,
  accentColor = "blue",
  badge,
}: MetricCardProps) {
  const colorMap = {
    blue: "text-blue-400 bg-blue-500/10 border-blue-500/20 group-hover:border-blue-500/40",
    cyan: "text-cyan-400 bg-cyan-500/10 border-cyan-500/20 group-hover:border-cyan-500/40",
    rose: "text-rose-400 bg-rose-500/10 border-rose-500/20 group-hover:border-rose-500/40",
    amber: "text-amber-400 bg-amber-500/10 border-amber-500/20 group-hover:border-amber-500/40",
    emerald: "text-emerald-400 bg-emerald-500/10 border-emerald-500/20 group-hover:border-emerald-500/40",
  };

  return (
    <div className="soc-glass rounded-xl p-4 sm:p-5 relative overflow-hidden group hover:border-blue-500/30 transition-all duration-300">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1">
            {title}
          </p>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight font-mono">
              {value}
            </span>
            {badge && (
              <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-rose-500/20 text-rose-300 border border-rose-500/30 uppercase">
                {badge}
              </span>
            )}
          </div>
        </div>

        <div className={cn("p-2.5 rounded-xl border transition-colors", colorMap[accentColor])}>
          <Icon className="h-5 w-5" />
        </div>
      </div>

      <div className="mt-3 flex items-center justify-between text-xs">
        {subtitle && <span className="text-slate-400">{subtitle}</span>}
        {trend && (
          <span
            className={cn(
              "font-mono font-medium text-[11px] px-1.5 py-0.5 rounded border",
              trend.positive
                ? "text-emerald-400 bg-emerald-500/10 border-emerald-500/20"
                : "text-rose-400 bg-rose-500/10 border-rose-500/20"
            )}
          >
            {trend.value}
          </span>
        )}
      </div>
    </div>
  );
}
