"use client";

import { memo } from "react";
import { Handle, Position } from "reactflow";
import { Server, Router, Laptop, Cpu, Video, Smartphone, Layers } from "lucide-react";
import { getSeverityColor } from "@/lib/utils";

interface TopologyNodeData {
  label: string;
  ip: string;
  type: string;
  risk: string;
  status: string;
  discovery_method?: string;
  confidence?: number;
  evidence?: string[];
}

export const TopologyNode = memo(({ data }: { data: TopologyNodeData }) => {
  const getIcon = () => {
    switch (data.type) {
      case "Server":
        return <Server className="h-4 w-4 text-cyan-400" />;
      case "Router":
      case "Switch":
        return <Router className="h-4 w-4 text-blue-400" />;
      case "Laptop":
      case "Desktop":
        return <Laptop className="h-4 w-4 text-emerald-400" />;
      case "Mobile":
        return <Smartphone className="h-4 w-4 text-purple-400" />;
      case "Camera":
        return <Video className="h-4 w-4 text-amber-400" />;
      default:
        return <Cpu className="h-4 w-4 text-pink-400" />;
    }
  };

  return (
    <div className="bg-[#111C2D]/95 backdrop-blur-md border border-blue-500/30 rounded-xl p-3 shadow-xl min-w-[190px] hover:border-cyan-400/60 transition-all">
      <Handle type="target" position={Position.Top} className="!bg-cyan-400 !w-2 !h-2" />

      <div className="flex items-center justify-between gap-2 mb-1.5">
        <div className="flex items-center gap-1.5">
          <div className="p-1 rounded-md bg-blue-500/10 border border-blue-500/20">
            {getIcon()}
          </div>
          <span className="text-[10px] uppercase font-bold text-slate-400">
            {data.type}
          </span>
        </div>

        <span
          className={`px-1.5 py-0.2 rounded text-[9px] uppercase font-bold border ${getSeverityColor(
            data.risk
          )}`}
        >
          {data.risk}
        </span>
      </div>

      <div className="font-bold text-xs text-white truncate max-w-[160px]">{data.label}</div>
      <div className="font-mono text-[10px] text-cyan-400 mt-0.5">{data.ip}</div>

      <div className="mt-2 pt-1.5 border-t border-slate-800 flex items-center justify-between text-[9px]">
        <span className="text-slate-400 flex items-center gap-1">
          <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
          {data.status}
        </span>
        {data.discovery_method === "discovered" ? (
          <span className="text-cyan-300 font-mono text-[8px] bg-cyan-950/60 px-1 py-0.5 rounded border border-cyan-500/30">
            DISCOVERED
          </span>
        ) : (
          <span className="text-slate-400 font-mono text-[8px]">
            {data.discovery_method === "manual" ? "MANUAL" : "SAMPLE"}
          </span>
        )}
      </div>

      <Handle type="source" position={Position.Bottom} className="!bg-blue-400 !w-2 !h-2" />
    </div>
  );
});

TopologyNode.displayName = "TopologyNode";
