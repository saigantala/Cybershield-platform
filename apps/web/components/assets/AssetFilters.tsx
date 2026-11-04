import { Search, RotateCcw } from "lucide-react";
import { DeviceType, RiskLevel, AssetStatus } from "@/types/asset";

interface AssetFiltersProps {
  searchTerm: string;
  onSearchChange: (value: string) => void;
  selectedDeviceType: string;
  onDeviceTypeChange: (value: string) => void;
  selectedRisk: string;
  onRiskChange: (value: string) => void;
  selectedStatus: string;
  onStatusChange: (value: string) => void;
  onReset: () => void;
  totalFiltered: number;
}

export function AssetFilters({
  searchTerm,
  onSearchChange,
  selectedDeviceType,
  onDeviceTypeChange,
  selectedRisk,
  onRiskChange,
  selectedStatus,
  onStatusChange,
  onReset,
  totalFiltered,
}: AssetFiltersProps) {
  const deviceTypes: { label: string; value: string }[] = [
    { label: "All Device Types", value: "all" },
    { label: "Laptops", value: "Laptop" },
    { label: "Desktops", value: "Desktop" },
    { label: "Servers", value: "Server" },
    { label: "Routers / Switches", value: "Router" },
    { label: "Mobile Devices", value: "Mobile" },
    { label: "IoT Controllers", value: "IoT" },
    { label: "Other Devices", value: "Other" },
  ];

  const riskLevels: { label: string; value: string }[] = [
    { label: "All Risk Levels", value: "all" },
    { label: "Critical Risk", value: "Critical" },
    { label: "High Risk", value: "High" },
    { label: "Medium Risk", value: "Medium" },
    { label: "Low Risk", value: "Low" },
    { label: "Unassessed", value: "Unassessed" },
  ];

  const statuses: { label: string; value: string }[] = [
    { label: "All Statuses", value: "all" },
    { label: "Active", value: "Active" },
    { label: "Inactive", value: "Inactive" },
    { label: "Unknown", value: "Unknown" },
  ];

  const hasActiveFilters =
    searchTerm !== "" ||
    selectedDeviceType !== "all" ||
    selectedRisk !== "all" ||
    selectedStatus !== "all";

  return (
    <div className="soc-glass rounded-xl p-4 border border-blue-500/20 flex flex-col lg:flex-row items-center justify-between gap-3">
      {/* Search Input */}
      <div className="relative w-full lg:w-96">
        <Search className="h-4 w-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
        <input
          type="text"
          placeholder="Search by device name, IP, MAC or hostname..."
          value={searchTerm}
          onChange={(e) => onSearchChange(e.target.value)}
          className="w-full bg-[#111C2D] border border-blue-500/20 rounded-lg pl-9 pr-4 py-2 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-400 transition-colors"
        />
      </div>

      {/* Dropdown Filters */}
      <div className="flex flex-wrap items-center gap-2.5 w-full lg:w-auto">
        <select
          value={selectedDeviceType}
          onChange={(e) => onDeviceTypeChange(e.target.value)}
          className="bg-[#111C2D] border border-blue-500/20 text-xs text-slate-300 rounded-lg px-3 py-2 focus:outline-none focus:border-cyan-400 cursor-pointer"
        >
          {deviceTypes.map((t) => (
            <option key={t.value} value={t.value} className="bg-[#111C2D]">
              {t.label}
            </option>
          ))}
        </select>

        <select
          value={selectedRisk}
          onChange={(e) => onRiskChange(e.target.value)}
          className="bg-[#111C2D] border border-blue-500/20 text-xs text-slate-300 rounded-lg px-3 py-2 focus:outline-none focus:border-cyan-400 cursor-pointer"
        >
          {riskLevels.map((r) => (
            <option key={r.value} value={r.value} className="bg-[#111C2D]">
              {r.label}
            </option>
          ))}
        </select>

        <select
          value={selectedStatus}
          onChange={(e) => onStatusChange(e.target.value)}
          className="bg-[#111C2D] border border-blue-500/20 text-xs text-slate-300 rounded-lg px-3 py-2 focus:outline-none focus:border-cyan-400 cursor-pointer"
        >
          {statuses.map((s) => (
            <option key={s.value} value={s.value} className="bg-[#111C2D]">
              {s.label}
            </option>
          ))}
        </select>

        {hasActiveFilters && (
          <button
            onClick={onReset}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-slate-800/80 hover:bg-slate-800 text-xs text-slate-300 hover:text-white border border-slate-700 transition-colors"
            title="Reset Filters"
          >
            <RotateCcw className="h-3 w-3" />
            <span>Reset</span>
          </button>
        )}

        <div className="text-xs text-slate-400 font-mono px-2 py-1 rounded bg-[#0B1220] border border-slate-800 shrink-0">
          <strong className="text-cyan-400">{totalFiltered}</strong> matching
        </div>
      </div>
    </div>
  );
}
