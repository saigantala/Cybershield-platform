import { ShieldAlert } from "lucide-react";
import Link from "next/link";

export default function AuthLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <div className="min-h-screen bg-[#080D18] soc-grid-bg flex flex-col justify-between p-6">
      {/* Top Header */}
      <header className="flex items-center justify-between max-w-6xl w-full mx-auto">
        <Link href="/" className="flex items-center gap-3">
          <div className="h-9 w-9 rounded-xl bg-gradient-to-br from-blue-600 to-cyan-500 flex items-center justify-center shadow-lg shadow-blue-500/25">
            <ShieldAlert className="h-5 w-5 text-white" />
          </div>
          <span className="font-bold text-lg text-white tracking-tight">
            Cyber<span className="text-cyan-400">Shield</span>
          </span>
        </Link>

        <div className="text-xs text-slate-400 font-mono">
          SOC Enterprise Auth Gateway
        </div>
      </header>

      {/* Main Form Center */}
      <main className="flex-1 flex items-center justify-center py-10">
        <div className="w-full max-w-md">{children}</div>
      </main>

      {/* Footer */}
      <footer className="text-center text-xs text-slate-500 max-w-6xl w-full mx-auto border-t border-slate-900 pt-4">
        © 2026 CyberShield Security Platform. Protected under strict organizational access policies.
      </footer>
    </div>
  );
}
