"use client";

import { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import {
  Layers,
  ArrowLeft,
  Search,
  CheckCircle2,
  ExternalLink,
  Shield,
  Send,
  Zap,
  Globe,
  Lock,
  Server,
  Cloud,
  Cpu,
  PlusCircle,
  Radio,
  FileCode,
} from "lucide-react";
import { apiIntegrations } from "@/lib/api-client";
import type { IntegrationCategory } from "@/types/integrations";

interface CatalogConnector {
  slug: string;
  name: string;
  category: IntegrationCategory;
  provider: string;
  description: string;
  capabilities: string[];
  direction: "Inbound" | "Outbound" | "Bidirectional";
  isPopular?: boolean;
  defaultConfig: Record<string, any>;
}

const CATALOG_CONNECTORS: CatalogConnector[] = [
  {
    slug: "splunk",
    name: "Splunk Enterprise SIEM",
    category: "siem",
    provider: "Splunk",
    description: "HTTP Event Collector (HEC) forwarder streaming normalized security alerts and incidents in CIM/ECS format.",
    capabilities: ["Real-time HEC Streaming", "CIM Event Mapping", "Batch Buffer"],
    direction: "Outbound",
    isPopular: true,
    defaultConfig: { endpoint_url: "https://splunk-hec.corp.internal:8088/services/collector", index: "cybershield_events" },
  },
  {
    slug: "sentinel",
    name: "Microsoft Sentinel",
    category: "siem",
    provider: "Microsoft",
    description: "Azure Log Analytics ingestion connector synchronizing anomalous threat detections and SOAR executions.",
    capabilities: ["Log Analytics Ingestion", "KQL Query Integration", "DCR Formatter"],
    direction: "Outbound",
    isPopular: true,
    defaultConfig: { workspace_id: "ws-sec-example", log_type: "CyberShieldSecurityEvents" },
  },
  {
    slug: "elastic_security",
    name: "Elastic Security SIEM",
    category: "siem",
    provider: "Elastic",
    description: "Shipper streaming security telemetry directly to Elasticsearch clusters adhering to Elastic Common Schema (ECS).",
    capabilities: ["ECS Mapping", "Bulk Indexing", "Index Lifecycle Management"],
    direction: "Outbound",
    defaultConfig: { endpoint_url: "https://elastic.corp.internal:9200", index: "cybershield-ecs" },
  },
  {
    slug: "wazuh_siem",
    name: "Wazuh Security Platform",
    category: "siem",
    provider: "Wazuh",
    description: "Open-source host and network security monitoring platform connector for agent log correlation.",
    capabilities: ["Syslog RFC 5424", "Decoders Integration", "Agent Heartbeats"],
    direction: "Bidirectional",
    defaultConfig: { endpoint_url: "https://wazuh-indexer.corp.internal:9200", port: 514 },
  },
  {
    slug: "slack",
    name: "Slack Incident War Room",
    category: "communication",
    provider: "Slack",
    description: "Real-time critical alert dispatch, incident escalation notices, and human-in-the-loop approval interactive buttons.",
    capabilities: ["Block Kit Formatting", "Interactive Containment Actions", "Severity Routing"],
    direction: "Outbound",
    isPopular: true,
    defaultConfig: { channel: "#soc-incident-war-room", alert_severity_threshold: "High" },
  },
  {
    slug: "teams",
    name: "Microsoft Teams SOC Bridge",
    category: "communication",
    provider: "Microsoft",
    description: "Adaptive cards notifications for security event correlation, SOAR containment gates, and shift handovers.",
    capabilities: ["Adaptive Cards 1.5", "Interactive Actions", "Group Webhooks"],
    direction: "Outbound",
    defaultConfig: { channel: "SOC Operations", webhook_url: "https://outlook.office.com/webhook/example" },
  },
  {
    slug: "smtp_email",
    name: "Executive Email Dispatcher",
    category: "communication",
    provider: "Generic SMTP",
    description: "Encrypted TLS SMTP notification engine for weekly compliance summaries and high-priority incident escalations.",
    capabilities: ["STARTTLS / SSL", "HTML Rich Templates", "Digest Schedules"],
    direction: "Outbound",
    defaultConfig: { host: "smtp.corp.internal", port: 587, use_tls: true },
  },
  {
    slug: "cisa_kev",
    name: "CISA Known Exploited Vulnerabilities",
    category: "threat_intelligence",
    provider: "CISA",
    description: "Automated synchronization of actively exploited zero-day and CVE catalogs curated by the Cybersecurity and Infrastructure Security Agency.",
    capabilities: ["Catalog Synchronization", "Asset Vulnerability Cross-Check", "Ransomware Flagging"],
    direction: "Inbound",
    isPopular: true,
    defaultConfig: { feed_url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", sync_interval_hours: 6 },
  },
  {
    slug: "alienvault_otx",
    name: "AlienVault OTX (Open Threat Exchange)",
    category: "threat_intelligence",
    provider: "AT&T Cybersecurity",
    description: "Community-driven threat intelligence feed importing malicious IP, domain, and hash pulses into CyberShield IOC database.",
    capabilities: ["Pulse Ingestion", "IOC Deduplication", "Confidence Scoring"],
    direction: "Inbound",
    defaultConfig: { min_pulse_subscribers: 10, sync_interval_hours: 12 },
  },
  {
    slug: "abuse_ch_threats",
    name: "abuse.ch URLhaus & MalwareBazaar",
    category: "threat_intelligence",
    provider: "abuse.ch",
    description: "Real-time threat feeds for weaponized malware distribution URLs and malicious payload SHA-256 signatures.",
    capabilities: ["URL Invalidation", "C2 Blocklists", "Malware Signatures"],
    direction: "Inbound",
    defaultConfig: { feeds: ["urlhaus", "malwarebazaar"], sync_interval_hours: 4 },
  },
  {
    slug: "aws_security",
    name: "AWS CloudTrail & GuardDuty",
    category: "cloud_security",
    provider: "Amazon Web Services",
    description: "Read-only inventory sync and GuardDuty finding correlation without destructive infrastructure modification.",
    capabilities: ["IAM Read-Only Audit", "GuardDuty Telemetry", "VPC Posture Check"],
    direction: "Inbound",
    isPopular: true,
    defaultConfig: { region: "us-east-1", iam_role_arn: "arn:aws:iam::123456789012:role/CyberShieldAudit" },
  },
  {
    slug: "azure_defender",
    name: "Microsoft Defender for Cloud",
    category: "cloud_security",
    provider: "Microsoft Azure",
    description: "Synchronizes Azure cloud security posture assessments, regulatory compliance baselines, and resource telemetry.",
    capabilities: ["Azure CSPM Sync", "Subscription Inventory", "Regulatory Score Mapping"],
    direction: "Inbound",
    defaultConfig: { tenant_id: "00000000-0000-0000-0000-000000000000", subscription_id: "sub-corp-prod" },
  },
  {
    slug: "generic_webhook",
    name: "Custom Outbound Webhook",
    category: "webhooks",
    provider: "Generic Webhook",
    description: "Dispatch event payloads to custom internal SIEM, PagerDuty, or ticketing pipelines secured with HMAC-SHA256 signatures.",
    capabilities: ["HMAC-SHA256 Signing", "Automatic Retries", "SSRF Safeguard"],
    direction: "Outbound",
    defaultConfig: { retry_limit: 3, timeout_seconds: 10 },
  },
];

export default function AvailableIntegrationsPage() {
  const router = useRouter();
  const [selectedCategory, setSelectedCategory] = useState<string>("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [installingSlug, setInstallingSlug] = useState<string | null>(null);
  const [modalConnector, setModalConnector] = useState<CatalogConnector | null>(null);
  const [connectorName, setConnectorName] = useState("");
  const [secretKey, setSecretKey] = useState("");
  const [endpointUrl, setEndpointUrl] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const filteredConnectors = CATALOG_CONNECTORS.filter((item) => {
    const matchesCategory =
      selectedCategory === "all" || item.category === selectedCategory;
    const matchesSearch =
      item.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      item.provider.toLowerCase().includes(searchQuery.toLowerCase()) ||
      item.description.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesCategory && matchesSearch;
  });

  const handleOpenInstall = (connector: CatalogConnector) => {
    setModalConnector(connector);
    setConnectorName(connector.name);
    setSecretKey("");
    setEndpointUrl(connector.defaultConfig.endpoint_url || connector.defaultConfig.webhook_url || "");
    setErrorMessage(null);
  };

  const handleCreateIntegration = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!modalConnector) return;

    setIsSubmitting(true);
    setErrorMessage(null);

    try {
      const config = { ...modalConnector.defaultConfig };
      if (endpointUrl) {
        if (config.webhook_url !== undefined) {
          config.webhook_url = endpointUrl;
        } else {
          config.endpoint_url = endpointUrl;
        }
      }

      const res = await apiIntegrations.createIntegration({
        name: connectorName,
        slug: `${modalConnector.slug}_${Date.now().toString(36)}`,
        category: modalConnector.category,
        provider: modalConnector.provider,
        description: modalConnector.description,
        config,
        secret_key: secretKey || undefined,
        is_enabled: true,
      });

      if (res.data) {
        router.push("/integrations");
      } else {
        setErrorMessage(res.error || "Failed to create integration. Please check input parameters.");
      }
    } catch (err: any) {
      setErrorMessage(err.message || "An unexpected error occurred.");
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="space-y-8 p-6 md:p-8">
      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <Link
            href="/integrations"
            className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-400 transition-colors hover:text-white"
          >
            <ArrowLeft className="h-4 w-4" />
            Back to Integration Center
          </Link>
          <div className="mt-2 flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-cyan-500/30 bg-cyan-950/40 text-cyan-400">
              <Layers className="h-6 w-6" />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-white md:text-3xl">
                Connector Catalog & Marketplace
              </h1>
              <p className="text-sm text-slate-400">
                Browse pre-built connectors for industry-standard SIEMs, communication tools, threat intel feeds, and cloud providers
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex flex-wrap gap-2">
          {[
            { id: "all", label: "All Integrations" },
            { id: "siem", label: "SIEM Platforms" },
            { id: "communication", label: "Communication" },
            { id: "threat_intelligence", label: "Threat Intel" },
            { id: "cloud_security", label: "Cloud Security" },
            { id: "webhooks", label: "Webhooks" },
          ].map((cat) => (
            <button
              key={cat.id}
              onClick={() => setSelectedCategory(cat.id)}
              className={`rounded-lg px-3.5 py-1.5 text-xs font-semibold transition-all ${
                selectedCategory === cat.id
                  ? "border border-cyan-500/50 bg-cyan-950/60 text-cyan-300 shadow-sm shadow-cyan-900/40"
                  : "border border-slate-800 bg-slate-900/40 text-slate-400 hover:bg-slate-800 hover:text-slate-200"
              }`}
            >
              {cat.label}
            </button>
          ))}
        </div>

        <div className="relative w-full sm:w-64">
          <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
          <input
            type="text"
            placeholder="Search catalog..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full rounded-lg border border-slate-800 bg-slate-900/60 py-1.5 pl-9 pr-4 text-xs text-white placeholder-slate-500 focus:border-cyan-500/50 focus:outline-none focus:ring-1 focus:ring-cyan-500/50"
          />
        </div>
      </div>

      {/* Catalog Grid */}
      <div className="grid grid-cols-1 gap-6 md:grid-cols-2 lg:grid-cols-3">
        {filteredConnectors.map((c) => (
          <div
            key={c.slug}
            className="flex flex-col justify-between rounded-xl border border-slate-800 bg-slate-900/70 p-5 shadow-lg backdrop-blur-md transition-all hover:border-slate-700"
          >
            <div>
              <div className="flex items-start justify-between gap-3">
                <div className="flex items-center gap-3">
                  <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-slate-800 bg-slate-800/80">
                    {c.category === "siem" && <Layers className="h-5 w-5 text-indigo-400" />}
                    {c.category === "communication" && <Send className="h-5 w-5 text-emerald-400" />}
                    {c.category === "threat_intelligence" && <Shield className="h-5 w-5 text-amber-400" />}
                    {c.category === "cloud_security" && <Globe className="h-5 w-5 text-sky-400" />}
                    {c.category === "webhooks" && <Zap className="h-5 w-5 text-purple-400" />}
                  </div>
                  <div>
                    <h3 className="font-semibold text-white">{c.name}</h3>
                    <div className="flex items-center gap-2 text-xs text-slate-400">
                      <span>{c.provider}</span>
                      <span>•</span>
                      <span className="capitalize">{c.category.replace("_", " ")}</span>
                    </div>
                  </div>
                </div>
                {c.isPopular && (
                  <span className="rounded-full border border-cyan-500/40 bg-cyan-950/40 px-2 py-0.5 text-[10px] font-semibold text-cyan-400">
                    Popular
                  </span>
                )}
              </div>

              <p className="mt-4 line-clamp-3 text-xs leading-relaxed text-slate-400">
                {c.description}
              </p>

              {/* Capabilities Pills */}
              <div className="mt-4 flex flex-wrap gap-1.5">
                {c.capabilities.map((cap) => (
                  <span
                    key={cap}
                    className="rounded border border-slate-800 bg-slate-950/60 px-2 py-0.5 text-[10px] font-medium text-slate-300"
                  >
                    {cap}
                  </span>
                ))}
              </div>
            </div>

            <div className="mt-6 flex items-center justify-between border-t border-slate-800/80 pt-4">
              <span className="inline-flex items-center gap-1.5 text-xs text-slate-500">
                <span className="h-1.5 w-1.5 rounded-full bg-cyan-400"></span>
                {c.direction}
              </span>
              <button
                onClick={() => handleOpenInstall(c)}
                className="flex items-center gap-1.5 rounded-lg border border-cyan-500/50 bg-cyan-600/30 px-3 py-1.5 text-xs font-semibold text-cyan-300 transition-colors hover:bg-cyan-600/50"
              >
                <PlusCircle className="h-3.5 w-3.5" />
                Configure
              </button>
            </div>
          </div>
        ))}
      </div>

      {/* Configuration Modal */}
      {modalConnector && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm">
          <div className="w-full max-w-lg rounded-2xl border border-slate-700 bg-slate-900 p-6 shadow-2xl">
            <div className="flex items-start justify-between">
              <div>
                <h3 className="text-lg font-bold text-white">
                  Configure {modalConnector.name}
                </h3>
                <p className="mt-1 text-xs text-slate-400">
                  Set connection credentials and destination endpoints for this integration.
                </p>
              </div>
              <button
                onClick={() => setModalConnector(null)}
                className="text-slate-400 hover:text-white"
              >
                &times;
              </button>
            </div>

            {errorMessage && (
              <div className="mt-4 rounded-lg border border-rose-500/40 bg-rose-950/40 p-3 text-xs text-rose-300">
                {errorMessage}
              </div>
            )}

            <form onSubmit={handleCreateIntegration} className="mt-5 space-y-4">
              <div>
                <label className="text-xs font-semibold text-slate-300">Integration Instance Name</label>
                <input
                  type="text"
                  required
                  value={connectorName}
                  onChange={(e) => setConnectorName(e.target.value)}
                  className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-white placeholder-slate-500 focus:border-cyan-500 focus:outline-none"
                />
              </div>

              {(modalConnector.defaultConfig.endpoint_url || modalConnector.defaultConfig.webhook_url) && (
                <div>
                  <label className="text-xs font-semibold text-slate-300">
                    Endpoint URL (Target Collector / Webhook)
                  </label>
                  <input
                    type="url"
                    placeholder="https://..."
                    value={endpointUrl}
                    onChange={(e) => setEndpointUrl(e.target.value)}
                    className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs font-mono text-white placeholder-slate-500 focus:border-cyan-500 focus:outline-none"
                  />
                  <span className="mt-1 block text-[10px] text-slate-500">
                    Protected by strict SSRF guards: loopback, link-local, and RFC 1918 private subnets are rejected.
                  </span>
                </div>
              )}

              <div>
                <label className="text-xs font-semibold text-slate-300">
                  API Key / HEC Secret Token / Webhook Secret
                </label>
                <input
                  type="password"
                  placeholder="Paste secret or API token..."
                  value={secretKey}
                  onChange={(e) => setSecretKey(e.target.value)}
                  className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs font-mono text-white placeholder-slate-500 focus:border-cyan-500 focus:outline-none"
                />
                <span className="mt-1 block text-[10px] text-slate-500">
                  Encrypted at rest with AES-256 and masked in all UI / API views.
                </span>
              </div>

              <div className="flex items-center justify-end gap-3 pt-3">
                <button
                  type="button"
                  onClick={() => setModalConnector(null)}
                  className="rounded-lg border border-slate-700 bg-slate-800 px-4 py-2 text-xs font-medium text-slate-300 hover:bg-slate-700"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="rounded-lg border border-cyan-500 bg-cyan-600 px-4 py-2 text-xs font-semibold text-white hover:bg-cyan-500 disabled:opacity-50"
                >
                  {isSubmitting ? "Activating..." : "Save & Activate"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
