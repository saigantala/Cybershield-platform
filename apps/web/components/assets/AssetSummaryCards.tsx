import { Server, Activity, AlertOctagon, HelpCircle } from "lucide-react";
import { AssetSummaryStats } from "@/types/asset";

interface AssetSummaryCardsProps {
  stats: AssetSummaryStats;
  isLoading?: boolean;
}

export function AssetSummaryCards({ stats, isLoading }: AssetSummaryCardsProps) {
  const cards = [
    {
      title: "Total Assets",
      value: stats.total,
      subtitle: "Managed network endpoints",
      icon: Server,
      color: "text-blue-400",
      borderColor: "border-blue-500/30",
      bgColor: "bg-blue-500/10",
      pill: "Inventory",
      pillColor: "bg-blue-500/20 text-blue-300",
    },
    {
      title: "Active Assets",
      value: stats.active,
      subtitle: "Online & responding to probes",
      icon: Activity,
      color: "text-emerald-400",
      borderColor: "border-emerald-500/30",
      bgColor: "bg-emerald-500/10",
      pill: `${Math.round((stats.active / (stats.total || 1)) * 100)}% Online`,
      pillColor: "bg-emerald-500/20 text-emerald-300",
    },
    {
      title: "Critical Risk Assets",
      value: stats.critical,
      subtitle: "Requiring immediate SOC triage",
      icon: AlertOctagon,
      color: "text-rose-400",
      borderColor: "border-rose-500/30",
      bgColor: "bg-rose-500/10",
      pill: stats.critical > 0 ? "Action Required" : "Secure",
      pillColor: stats.critical > 0 ? "bg-rose-500/20 text-rose-300" : "bg-emerald-500/20 text-emerald-300",
    },
    {
      title: "Unassessed Assets",
      value: stats.unassessed,
      subtitle: "Pending baseline vulnerability sweep",
      icon: HelpCircle,
      color: "text-purple-400",
      borderColor: "border-purple-500/30",
      bgColor: "bg-purple-500/10",
      pill: "Scan Queue",
      pillColor: "bg-purple-500/20 text-purple-300",
    },
  ];

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      {cards.map((card, idx) => {
        const Icon = card.icon;
        return (
          <div
            key={idx}
            className={`soc-glass rounded-xl p-4 border ${card.borderColor} relative overflow-hidden transition-all duration-300 hover:border-blue-400/50 hover:shadow-lg hover:shadow-blue-500/5`}
          >
            <div className="flex items-start justify-between">
              <div>
                <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block">
                  {card.title}
                </span>
                <div className="mt-1 flex items-baseline gap-2">
                  <span className="text-2xl font-black text-white tracking-tight font-mono">
                    {isLoading ? "—" : card.value}
                  </span>
                </div>
              </div>
              <div className={`p-2.5 rounded-lg ${card.bgColor} ${card.color} border ${card.borderColor}`}>
                <Icon className="h-5 w-5" />
              </div>
            </div>

            <div className="mt-3 flex items-center justify-between pt-2 border-t border-slate-800/80 text-xs">
              <span className="text-slate-400 text-[11px] truncate max-w-[140px]">
                {card.subtitle}
              </span>
              <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-semibold ${card.pillColor}`}>
                {card.pill}
              </span>
            </div>
          </div>
        );
      })}
    </div>
  );
}
