import { ShieldCheck, Info, ArrowUpRight } from "lucide-react";
import Link from "next/link";

interface PostureScoreCardProps {
  score: number;
  delta: number;
}

export function PostureScoreCard({ score, delta }: PostureScoreCardProps) {
  const getGrade = (s: number) => {
    if (s >= 90) return { grade: "A", label: "OPTIMAL", color: "text-emerald-400" };
    if (s >= 75) return { grade: "B+", label: "ACCEPTABLE", color: "text-cyan-400" };
    if (s >= 60) return { grade: "C", label: "ELEVATED RISK", color: "text-amber-400" };
    return { grade: "D", label: "CRITICAL ACTION", color: "text-rose-400" };
  };

  const status = getGrade(score);

  return (
    <div className="soc-glass rounded-xl p-5 sm:p-6 border border-blue-500/20 relative overflow-hidden flex flex-col justify-between">
      <div className="absolute top-0 right-0 w-48 h-48 bg-gradient-to-bl from-blue-600/10 via-cyan-500/5 to-transparent rounded-bl-full pointer-events-none" />

      <div>
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            <div className="p-1.5 rounded-lg bg-blue-500/10 text-cyan-400 border border-blue-500/20">
              <ShieldCheck className="h-5 w-5" />
            </div>
            <h3 className="text-sm font-bold uppercase tracking-wider text-slate-200">
              Security Posture Score
            </h3>
          </div>
          <span className="text-[10px] text-slate-400 flex items-center gap-1 font-mono">
            <Info className="h-3 w-3 text-cyan-400" />
            Weighted Algorithmic Index
          </span>
        </div>

        <div className="flex items-center justify-between my-4">
          <div className="flex items-baseline gap-3">
            <span className="text-5xl font-black tracking-tight text-white font-mono">
              {score}
            </span>
            <span className="text-slate-400 text-lg font-mono">/ 100</span>
          </div>

          <div className="text-right">
            <span className={`text-3xl font-extrabold ${status.color} font-mono block`}>
              {status.grade}
            </span>
            <span className="text-[10px] uppercase font-bold tracking-wider text-slate-400">
              {status.label}
            </span>
          </div>
        </div>

        {/* Progress Bar */}
        <div className="w-full bg-[#080D18] h-2.5 rounded-full overflow-hidden p-0.5 border border-slate-800">
          <div
            className="h-full rounded-full bg-gradient-to-r from-blue-500 via-cyan-400 to-emerald-400 transition-all duration-1000"
            style={{ width: `${score}%` }}
          />
        </div>
      </div>

      <div className="mt-5 pt-4 border-t border-slate-800/80 flex items-center justify-between text-xs">
        <span className="text-slate-400">
          Prioritization Delta:{" "}
          <span className="text-emerald-400 font-semibold font-mono">
            +{delta}% vs last week
          </span>
        </span>
        <Link
          href="/vulnerabilities"
          className="text-cyan-400 hover:text-cyan-300 font-medium flex items-center gap-1 hover:underline"
        >
          View Formula <ArrowUpRight className="h-3.5 w-3.5" />
        </Link>
      </div>
    </div>
  );
}
