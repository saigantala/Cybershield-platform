import {
  Server,
  Laptop,
  Monitor,
  Smartphone,
  Cpu,
  Layers,
  HardDrive,
  ArrowUpDown,
  ChevronLeft,
  ChevronRight,
  Eye,
  Edit2,
  Trash2,
} from "lucide-react";
import { AssetRecord, DeviceType } from "@/types/asset";
import { formatDateTime } from "@/lib/utils";

interface AssetTableProps {
  assets: AssetRecord[];
  totalCount: number;
  currentPage: number;
  pageSize: number;
  onPageChange: (page: number) => void;
  sortField: string;
  sortDirection: "asc" | "desc";
  onSort: (field: string) => void;
  onInspect: (asset: AssetRecord) => void;
  onEdit: (asset: AssetRecord) => void;
  onDelete: (asset: AssetRecord) => void;
  userRole?: string | null;
  isLoading?: boolean;
}

export function AssetTable({
  assets,
  totalCount,
  currentPage,
  pageSize,
  onPageChange,
  sortField,
  sortDirection,
  onSort,
  onInspect,
  onEdit,
  onDelete,
  userRole,
  isLoading,
}: AssetTableProps) {
  const isViewer = userRole === "viewer";
  const totalPages = Math.ceil(totalCount / pageSize) || 1;

  const getDeviceIcon = (deviceType: DeviceType) => {
    switch (deviceType) {
      case "Laptop":
        return Laptop;
      case "Desktop":
        return Monitor;
      case "Server":
        return Server;
      case "Router":
        return Layers;
      case "Mobile":
        return Smartphone;
      case "IoT":
        return Cpu;
      default:
        return HardDrive;
    }
  };

  const getRiskBadge = (risk: string) => {
    switch (risk) {
      case "Critical":
        return "bg-rose-500/10 text-rose-300 border-rose-500/30";
      case "High":
        return "bg-amber-500/10 text-amber-300 border-amber-500/30";
      case "Medium":
        return "bg-sky-500/10 text-sky-300 border-sky-500/30";
      case "Low":
        return "bg-emerald-500/10 text-emerald-300 border-emerald-500/30";
      default:
        return "bg-slate-500/10 text-slate-400 border-slate-700";
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case "Active":
        return "bg-emerald-500/10 text-emerald-400 border-emerald-500/30";
      case "Inactive":
        return "bg-slate-500/10 text-slate-400 border-slate-700";
      default:
        return "bg-amber-500/10 text-amber-400 border-amber-500/30";
    }
  };

  return (
    <div className="soc-glass rounded-xl overflow-hidden border border-blue-500/20">
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs">
          <thead>
            <tr className="bg-[#0B1220]/80 border-b border-slate-800 text-slate-400 uppercase font-mono text-[10px]">
              <th
                className="py-3 px-4 cursor-pointer hover:text-white transition-colors"
                onClick={() => onSort("name")}
              >
                <div className="flex items-center gap-1.5">
                  <span>Device</span>
                  <ArrowUpDown className="h-3 w-3" />
                </div>
              </th>

              <th
                className="py-3 px-4 cursor-pointer hover:text-white transition-colors"
                onClick={() => onSort("ip_address")}
              >
                <div className="flex items-center gap-1.5">
                  <span>IP Address</span>
                  <ArrowUpDown className="h-3 w-3" />
                </div>
              </th>

              <th className="py-3 px-4">MAC Address</th>

              <th
                className="py-3 px-4 cursor-pointer hover:text-white transition-colors"
                onClick={() => onSort("device_type")}
              >
                <div className="flex items-center gap-1.5">
                  <span>Device Type</span>
                  <ArrowUpDown className="h-3 w-3" />
                </div>
              </th>

              <th className="py-3 px-4">Operating System</th>

              <th
                className="py-3 px-4 cursor-pointer hover:text-white transition-colors"
                onClick={() => onSort("risk_level")}
              >
                <div className="flex items-center gap-1.5">
                  <span>Risk Level</span>
                  <ArrowUpDown className="h-3 w-3" />
                </div>
              </th>

              <th
                className="py-3 px-4 cursor-pointer hover:text-white transition-colors"
                onClick={() => onSort("status")}
              >
                <div className="flex items-center gap-1.5">
                  <span>Status</span>
                  <ArrowUpDown className="h-3 w-3" />
                </div>
              </th>

              <th
                className="py-3 px-4 cursor-pointer hover:text-white transition-colors"
                onClick={() => onSort("updated_at")}
              >
                <div className="flex items-center gap-1.5">
                  <span>Last Updated</span>
                  <ArrowUpDown className="h-3 w-3" />
                </div>
              </th>

              <th className="py-3 px-4 text-right">Actions</th>
            </tr>
          </thead>

          <tbody className="divide-y divide-slate-800/60 font-medium">
            {isLoading ? (
              <tr>
                <td colSpan={9} className="py-12 text-center text-slate-400">
                  <div className="flex flex-col items-center justify-center gap-2">
                    <div className="h-6 w-6 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin" />
                    <span>Loading assets...</span>
                  </div>
                </td>
              </tr>
            ) : assets.length === 0 ? (
              <tr>
                <td colSpan={9} className="py-12 text-center text-slate-400">
                  <div className="flex flex-col items-center justify-center gap-2">
                    <Server className="h-8 w-8 text-slate-600" />
                    <p className="font-semibold text-slate-300">No assets discovered</p>
                    <p className="text-xs text-slate-500">
                      Try adjusting your search criteria or register a new asset.
                    </p>
                  </div>
                </td>
              </tr>
            ) : (
              assets.map((asset) => {
                const DeviceIcon = getDeviceIcon(asset.device_type);
                return (
                  <tr
                    key={asset.id}
                    onClick={() => onInspect(asset)}
                    className="hover:bg-[#162338]/50 transition-colors cursor-pointer group"
                  >
                    {/* Device Name + Hostname */}
                    <td className="py-3 px-4">
                      <div className="flex items-center gap-2.5">
                        <div className="p-1.5 rounded-lg bg-blue-500/10 text-cyan-400 border border-blue-500/20 shrink-0">
                          <DeviceIcon className="h-4 w-4" />
                        </div>
                        <div>
                          <p className="font-bold text-white group-hover:text-cyan-300 transition-colors">
                            {asset.name}
                          </p>
                          <div className="flex items-center gap-1.5 mt-0.5">
                            <span className="text-[10px] text-slate-400 font-mono">
                              {asset.hostname || "No PTR record"}
                            </span>
                            {asset.discovery_method === "discovered" ? (
                              <span className="inline-flex items-center px-1.5 py-0.2 rounded text-[9px] font-bold bg-cyan-500/15 text-cyan-300 border border-cyan-500/30">
                                DISCOVERED{asset.confidence ? ` (${asset.confidence}%)` : ""}
                              </span>
                            ) : (
                              <span className="inline-flex items-center px-1.5 py-0.2 rounded text-[9px] font-bold bg-slate-700/40 text-slate-400 border border-slate-700">
                                MANUAL
                              </span>
                            )}
                          </div>
                        </div>
                      </div>
                    </td>

                    {/* IP Address */}
                    <td className="py-3 px-4 font-mono text-cyan-400 font-semibold">
                      {asset.ip_address}
                    </td>

                    {/* MAC Address */}
                    <td className="py-3 px-4 font-mono text-slate-400 text-[11px]">
                      {asset.mac_address || "—"}
                    </td>

                    {/* Device Type */}
                    <td className="py-3 px-4 text-slate-200">
                      {asset.device_type}
                    </td>

                    {/* Operating System */}
                    <td className="py-3 px-4 text-slate-300 truncate max-w-[130px]" title={asset.operating_system || ""}>
                      {asset.operating_system || "Unknown OS"}
                    </td>

                    {/* Risk Level */}
                    <td className="py-3 px-4">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold border ${getRiskBadge(
                          asset.risk_level
                        )}`}
                      >
                        {asset.risk_level}
                      </span>
                    </td>

                    {/* Status */}
                    <td className="py-3 px-4">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold border ${getStatusBadge(
                          asset.status
                        )}`}
                      >
                        {asset.status}
                      </span>
                    </td>

                    {/* Last Updated */}
                    <td className="py-3 px-4 font-mono text-slate-400 text-[11px]">
                      {asset.updated_at ? formatDateTime(asset.updated_at) : "Recent"}
                    </td>

                    {/* Actions */}
                    <td className="py-3 px-4 text-right">
                      <div
                        className="flex items-center justify-end gap-1.5"
                        onClick={(e) => e.stopPropagation()}
                      >
                        <button
                          onClick={() => onInspect(asset)}
                          className="p-1 rounded text-slate-400 hover:text-cyan-300 hover:bg-blue-500/10 transition-colors"
                          title="Inspect Details"
                        >
                          <Eye className="h-3.5 w-3.5" />
                        </button>

                        {!isViewer && (
                          <>
                            <button
                              onClick={() => onEdit(asset)}
                              className="p-1 rounded text-slate-400 hover:text-amber-300 hover:bg-amber-500/10 transition-colors"
                              title="Edit Asset"
                            >
                              <Edit2 className="h-3.5 w-3.5" />
                            </button>

                            <button
                              onClick={() => onDelete(asset)}
                              className="p-1 rounded text-slate-400 hover:text-rose-400 hover:bg-rose-500/10 transition-colors"
                              title="Decommission Asset"
                            >
                              <Trash2 className="h-3.5 w-3.5" />
                            </button>
                          </>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination Footer */}
      <div className="p-3 bg-[#0B1220]/80 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400">
        <div>
          Showing{" "}
          <strong className="text-white">
            {totalCount === 0 ? 0 : (currentPage - 1) * pageSize + 1}
          </strong>{" "}
          to{" "}
          <strong className="text-white">
            {Math.min(currentPage * pageSize, totalCount)}
          </strong>{" "}
          of <strong className="text-white">{totalCount}</strong> assets
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => onPageChange(Math.max(currentPage - 1, 1))}
            disabled={currentPage === 1 || isLoading}
            className="p-1.5 rounded-lg bg-[#111C2D] border border-blue-500/20 text-slate-300 hover:text-white disabled:opacity-40 transition-colors"
          >
            <ChevronLeft className="h-4 w-4" />
          </button>
          <span className="font-mono px-2">
            Page {currentPage} of {totalPages}
          </span>
          <button
            onClick={() => onPageChange(Math.min(currentPage + 1, totalPages))}
            disabled={currentPage === totalPages || isLoading}
            className="p-1.5 rounded-lg bg-[#111C2D] border border-blue-500/20 text-slate-300 hover:text-white disabled:opacity-40 transition-colors"
          >
            <ChevronRight className="h-4 w-4" />
          </button>
        </div>
      </div>
    </div>
  );
}
