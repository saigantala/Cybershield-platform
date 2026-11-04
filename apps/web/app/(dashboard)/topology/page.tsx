"use client";

import { useState, useCallback, useEffect } from "react";
import ReactFlow, {
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  Node,
  Edge,
} from "reactflow";
import "reactflow/dist/style.css";
import {
  Network,
  Search,
  Layers,
  RefreshCw,
  X,
  Info,
  Shield,
  Radar,
  Radio,
  Server,
} from "lucide-react";
import { TopologyNode } from "@/components/topology/TopologyNode";
import { mockTopologyData } from "@/lib/mockData";
import { getSeverityColor } from "@/lib/utils";
import { getAssets } from "@/lib/assets/asset-service";
import { AssetRecord } from "@/types/asset";

const nodeTypes = {
  custom: TopologyNode,
};

function buildTopologyFromAssets(assets: AssetRecord[]) {
  if (!assets || assets.length === 0) return null;

  const nodes: Node[] = [];
  const edges: Edge[] = [];

  // 1. Root Gateway Node
  const gatewayId = "gateway-root";
  nodes.push({
    id: gatewayId,
    type: "custom",
    position: { x: 500, y: 30 },
    data: {
      label: "Core Edge Gateway (Router)",
      ip: "10.0.0.1",
      type: "Router",
      risk: "low",
      status: "online",
      discovery_method: "manual",
    },
  });

  // 2. Identify Subnets (/24 grouping)
  const subnetMap = new Map<string, AssetRecord[]>();
  for (const asset of assets) {
    const parts = (asset.ip_address || "10.0.0.0").split(".");
    const subnetKey = parts.length === 4 ? `${parts[0]}.${parts[1]}.${parts[2]}.0/24` : "10.0.0.0/24";
    if (!subnetMap.has(subnetKey)) {
      subnetMap.set(subnetKey, []);
    }
    subnetMap.get(subnetKey)!.push(asset);
  }

  const subnets = Array.from(subnetMap.keys());
  const subnetSpacing = 360;
  const startX = 500 - ((subnets.length - 1) * subnetSpacing) / 2;

  subnets.forEach((subnet, idx) => {
    const subnetNodeId = `subnet-${idx}`;
    const subnetX = startX + idx * subnetSpacing;
    const subnetY = 180;

    nodes.push({
      id: subnetNodeId,
      type: "custom",
      position: { x: subnetX, y: subnetY },
      data: {
        label: `Subnet Gateway (${subnet})`,
        ip: subnet.replace(".0/24", ".1"),
        type: "Switch",
        risk: "low",
        status: "online",
        discovery_method: "discovered",
      },
    });

    edges.push({
      id: `edge-${gatewayId}-${subnetNodeId}`,
      source: gatewayId,
      target: subnetNodeId,
      animated: true,
      style: { stroke: "#3B82F6", strokeWidth: 2 },
    });

    // 3. Connect Assets in this subnet
    const subnetAssets = subnetMap.get(subnet)!;
    const assetSpacing = 240;
    const assetStartX = subnetX - ((subnetAssets.length - 1) * assetSpacing) / 2;

    subnetAssets.forEach((asset, aIdx) => {
      const assetNodeId = `asset-${asset.id}`;
      const assetX = assetStartX + aIdx * assetSpacing;
      const assetY = 360 + (aIdx % 2) * 50;

      nodes.push({
        id: assetNodeId,
        type: "custom",
        position: { x: assetX, y: assetY },
        data: {
          label: asset.name,
          ip: asset.ip_address,
          type: asset.device_type,
          risk: asset.risk_level.toLowerCase(),
          status: asset.status === "Active" ? "online" : "offline",
          discovery_method: asset.discovery_method || "manual",
          confidence: asset.confidence,
          evidence: asset.evidence,
          services: asset.services,
          manufacturer: asset.manufacturer,
          os: asset.operating_system,
        },
      });

      edges.push({
        id: `edge-${subnetNodeId}-${assetNodeId}`,
        source: subnetNodeId,
        target: assetNodeId,
        animated: asset.discovery_method === "discovered",
        style: {
          stroke: asset.discovery_method === "discovered" ? "#22D3EE" : "#64748B",
          strokeWidth: 1.5,
          strokeDasharray: asset.discovery_method === "discovered" ? "4,4" : undefined,
        },
      });
    });
  });

  return { nodes, edges };
}

export default function NetworkTopologyPage() {
  const [nodes, setNodes, onNodesChange] = useNodesState<any>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<any>([]);
  const [selectedNode, setSelectedNode] = useState<any>(null);
  const [searchFilter, setSearchFilter] = useState("");
  const [isLiveTopology, setIsLiveTopology] = useState(false);
  const [rawAssetsCount, setRawAssetsCount] = useState<number>(0);
  const [showDemo, setShowDemo] = useState(false);
  const [isLoading, setIsLoading] = useState(true);

  // Fetch real assets and construct topology
  useEffect(() => {
    async function loadTopology() {
      setIsLoading(true);
      try {
        const res = await getAssets({ page_size: 50 });
        const count = res.assets?.length ?? 0;
        setRawAssetsCount(count);

        if (count > 0) {
          const generated = buildTopologyFromAssets(res.assets);
          if (generated) {
            setNodes(generated.nodes);
            setEdges(generated.edges);
            setIsLiveTopology(true);
            setShowDemo(false);
          }
        } else {
          setIsLiveTopology(false);
          if (showDemo) {
            setNodes(mockTopologyData.nodes);
            setEdges(mockTopologyData.edges);
          } else {
            setNodes([]);
            setEdges([]);
          }
        }
      } catch (err) {
        console.warn("Using sample topology graph fallback:", err);
      } finally {
        setIsLoading(false);
      }
    }
    loadTopology();
  }, [setNodes, setEdges, showDemo]);

  const onNodeClick = useCallback((event: React.MouseEvent, node: Node) => {
    setSelectedNode(node);
  }, []);

  const handleSearch = (term: string) => {
    setSearchFilter(term);
    if (!term.trim()) {
      setNodes((current) =>
        current.map((n) => ({ ...n, style: { opacity: 1 } }))
      );
      return;
    }
    setNodes((current) =>
      current.map((n) => ({
        ...n,
        style: {
          opacity:
            n.data?.label?.toLowerCase().includes(term.toLowerCase()) ||
            n.data?.ip?.includes(term)
              ? 1
              : 0.2,
        },
      }))
    );
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <Network className="h-6 w-6 text-cyan-400" />
            <h1 className="text-xl sm:text-2xl font-black text-white tracking-tight">
              Interactive Network Topology
            </h1>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Visualized hierarchy: Core Gateway, Subnet Switches, Identified Endpoints, and Discovery Links
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="relative w-64">
            <Search className="h-4 w-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Locate node by IP or name..."
              value={searchFilter}
              onChange={(e) => handleSearch(e.target.value)}
              className="w-full bg-[#111C2D] border border-blue-500/20 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-400"
            />
          </div>

          <button
            onClick={() => {
              setSearchFilter("");
              setNodes((current) => current.map((n) => ({ ...n, style: { opacity: 1 } })));
            }}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-[#111C2D] border border-blue-500/30 text-xs font-semibold text-slate-200 hover:text-white transition-colors"
          >
            <RefreshCw className="h-3.5 w-3.5 text-cyan-400" />
            <span>Reset View</span>
          </button>
        </div>
      </div>

      {/* Origin Notice Banner */}
      <div className="p-3.5 rounded-xl bg-blue-950/30 border border-blue-500/30 flex items-center justify-between gap-3 text-xs">
        <div className="flex items-center gap-2.5">
          <Shield className="h-4 w-4 text-cyan-400 shrink-0" />
          <span className="text-slate-300">
            {isLiveTopology ? (
              <>
                <strong className="text-white">Live Inventory Graph ({rawAssetsCount} assets):</strong> Topology rendered from registered organizational assets and authorized discovery sweeps.
              </>
            ) : showDemo ? (
              <>
                <strong className="text-amber-400">Sample Network Topology (Demo Mode):</strong> Illustrative device hierarchy showing Core Gateway, Routers, Linux & Windows Servers, Workstations, Mobile, and IoT.
              </>
            ) : (
              <>
                <strong className="text-white">Live Topology Standby:</strong> 0 discovered endpoints. Launch an authorized subnet scan to populate your topology graph.
              </>
            )}
          </span>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {showDemo && (
            <button
              onClick={() => setShowDemo(false)}
              className="text-[10px] font-mono px-2 py-1 rounded bg-slate-800 text-slate-300 border border-slate-700 hover:text-white"
            >
              Exit Demo
            </button>
          )}
          <span className="text-[10px] font-mono text-cyan-400 font-bold uppercase">
            {isLiveTopology ? "Ground Inventory" : showDemo ? "Demo Visualization" : "Awaiting Discovery"}
          </span>
        </div>
      </div>

      {/* Topology Canvas and Detail Panel */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        <div className="lg:col-span-3 soc-glass rounded-xl h-[650px] border border-blue-500/30 overflow-hidden relative">
          {nodes.length > 0 ? (
            <>
              <ReactFlow
                nodes={nodes}
                edges={edges}
                onNodesChange={onNodesChange}
                onEdgesChange={onEdgesChange}
                onNodeClick={onNodeClick}
                nodeTypes={nodeTypes}
                fitView
              >
                <Background color="#1E293B" gap={20} size={1} />
                <Controls className="!bg-[#111C2D] !border-blue-500/30 !rounded-lg !text-white overflow-hidden shadow-lg" />
                <MiniMap
                  nodeColor={(node) => {
                    switch (node.data?.risk) {
                      case "critical":
                        return "#FB7185";
                      case "high":
                        return "#F59E0B";
                      case "medium":
                        return "#38BDF8";
                      default:
                        return "#34D399";
                    }
                  }}
                  className="!bg-[#0B1220] !border !border-blue-500/20 !rounded-lg"
                />
              </ReactFlow>

              {/* Topology Legend Overlay */}
              <div className="absolute bottom-4 left-4 p-3 rounded-lg bg-[#0B1220]/90 backdrop-blur-md border border-blue-500/20 text-[11px] space-y-1.5 z-10">
                <span className="text-slate-400 font-bold uppercase tracking-wider block text-[10px]">
                  Connection Classification
                </span>
                <div className="flex items-center gap-2 text-slate-300">
                  <span className="w-5 h-0.5 bg-blue-500 inline-block" />
                  <span>Core Backbone Trunk</span>
                </div>
                <div className="flex items-center gap-2 text-slate-300">
                  <span className="w-5 h-0.5 border-t border-dashed border-cyan-400 inline-block" />
                  <span>Discovered Network Endpoint</span>
                </div>
              </div>
            </>
          ) : (
            <div className="h-full w-full flex flex-col items-center justify-center p-8 text-center bg-[#080D18]/90">
              <div className="h-16 w-16 rounded-2xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 mb-4">
                <Network className="h-8 w-8 animate-pulse" />
              </div>
              <h3 className="text-lg font-bold text-white mb-2">
                No Network Assets Discovered
              </h3>
              <p className="text-xs text-slate-400 max-w-md mb-6">
                Your topology diagram generates dynamically as real endpoints and subnets are discovered via network scans or endpoint agent enrollment.
              </p>
              <div className="flex flex-wrap items-center justify-center gap-3">
                <a
                  href="/scans"
                  className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-xs font-semibold text-white shadow-lg shadow-blue-600/30 transition-all flex items-center gap-2"
                >
                  <Radar className="h-4 w-4" />
                  <span>Run Subnet Discovery Scan</span>
                </a>
                <button
                  onClick={() => setShowDemo(true)}
                  className="px-4 py-2 rounded-lg bg-[#111C2D] border border-cyan-500/40 hover:border-cyan-400 text-xs font-semibold text-cyan-300 transition-all"
                >
                  Preview Sample Topology
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Node Inspector Side Panel */}
        <div className="lg:col-span-1 soc-glass rounded-xl p-5 border border-blue-500/20 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <h3 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-1.5">
                <Layers className="h-4 w-4 text-cyan-400" />
                Node Inspector
              </h3>
              {selectedNode && (
                <button
                  onClick={() => setSelectedNode(null)}
                  className="text-slate-400 hover:text-white"
                >
                  <X className="h-4 w-4" />
                </button>
              )}
            </div>

            {selectedNode ? (
              <div className="space-y-4 mt-4 text-xs">
                <div>
                  <span className="text-slate-400 block text-[10px] uppercase font-bold">
                    Device Identifier
                  </span>
                  <p className="font-bold text-white text-sm">
                    {selectedNode.data.label}
                  </p>
                </div>

                <div>
                  <span className="text-slate-400 block text-[10px] uppercase font-bold">
                    IPv4 Address
                  </span>
                  <p className="font-mono text-cyan-400 font-semibold">
                    {selectedNode.data.ip}
                  </p>
                </div>

                <div className="grid grid-cols-2 gap-2">
                  <div className="p-2.5 rounded-lg bg-[#0B1220] border border-slate-800">
                    <span className="text-slate-400 block text-[10px]">Type</span>
                    <span className="font-semibold text-slate-200">
                      {selectedNode.data.type}
                    </span>
                  </div>
                  <div className="p-2.5 rounded-lg bg-[#0B1220] border border-slate-800">
                    <span className="text-slate-400 block text-[10px]">Risk</span>
                    <span
                      className={`font-semibold uppercase text-[10px] ${getSeverityColor(
                        selectedNode.data.risk
                      )}`}
                    >
                      {selectedNode.data.risk}
                    </span>
                  </div>
                </div>

                {/* Discovery Origin & Classifier */}
                <div className="p-3 rounded-lg bg-[#0B1220] border border-blue-500/20 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-slate-400 text-[10px] uppercase font-bold">
                      Discovery Origin
                    </span>
                    <span
                      className={`px-1.5 py-0.5 rounded text-[9px] font-bold uppercase border ${
                        selectedNode.data.discovery_method === "discovered"
                          ? "bg-cyan-500/10 text-cyan-300 border-cyan-500/30"
                          : "bg-slate-700/30 text-slate-400 border-slate-700"
                      }`}
                    >
                      {selectedNode.data.discovery_method === "discovered"
                        ? "Discovered Host"
                        : "Manual Host"}
                    </span>
                  </div>

                  {selectedNode.data.confidence && (
                    <div>
                      <span className="text-slate-400 text-[10px] block mb-1">
                        Classification Confidence: {selectedNode.data.confidence}%
                      </span>
                      <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                        <div
                          className="h-full bg-cyan-400 rounded-full"
                          style={{ width: `${selectedNode.data.confidence}%` }}
                        />
                      </div>
                    </div>
                  )}

                  {selectedNode.data.os && (
                    <div className="text-[11px] text-slate-300">
                      <span className="text-slate-400 block text-[10px]">OS Fingerprint:</span>
                      {selectedNode.data.os}
                    </div>
                  )}
                </div>

                {/* Evidence signals if present */}
                {selectedNode.data.evidence && selectedNode.data.evidence.length > 0 && (
                  <div className="p-3 rounded-lg bg-blue-950/20 border border-blue-500/20 space-y-1">
                    <span className="text-slate-300 font-semibold block text-[11px]">
                      Classifier Evidence Signals:
                    </span>
                    <div className="flex flex-wrap gap-1 mt-1">
                      {selectedNode.data.evidence.map((ev: string, i: number) => (
                        <span
                          key={i}
                          className="px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-[10px] font-mono text-slate-300"
                        >
                          {ev}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <div className="py-16 text-center text-slate-400 space-y-2">
                <Info className="h-8 w-8 text-blue-500/40 mx-auto" />
                <p className="text-xs">
                  Click any node in the topology canvas to inspect device metadata, discovery origin, and risk posture.
                </p>
              </div>
            )}
          </div>

          <div className="pt-4 border-t border-slate-800 text-[11px] text-slate-400">
            Interactive Layer 3 topology with automatic subnet clustering.
          </div>
        </div>
      </div>
    </div>
  );
}
