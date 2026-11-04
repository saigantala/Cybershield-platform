import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
import httpx

from app.ai.config import ai_config
from app.ai.guardrails import AIGuardrails

logger = logging.getLogger("cybershield.ai.provider")


class BaseAIProvider(ABC):
    @abstractmethod
    async def generate_response(
        self,
        system_prompt: str,
        user_prompt: str,
        conversation_history: Optional[List[Dict[str, str]]] = None,
        temperature: float = 0.2,
        max_tokens: int = 2048,
    ) -> Dict[str, Any]:
        """
        Executes model inference and returns:
        {
            "content": str,
            "input_tokens": int,
            "output_tokens": int,
            "model": str,
            "provider": str,
            "is_mock": bool
        }
        """
        pass


# ------------------------------------------------------------------------------
# Mock AI Provider (Development & Safe Offline SOC Evaluation)
# ------------------------------------------------------------------------------
class MockAIProvider(BaseAIProvider):
    def __init__(self, model_name: str = "cybershield-soc-mock-v1"):
        self.model_name = model_name
        self.provider_name = "mock"

    async def generate_response(
        self,
        system_prompt: str,
        user_prompt: str,
        conversation_history: Optional[List[Dict[str, str]]] = None,
        temperature: float = 0.2,
        max_tokens: int = 2048,
    ) -> Dict[str, Any]:
        # Simulate slight inference latency
        await asyncio.sleep(0.05)

        q = user_prompt.lower()
        response_text = ""

        if "critical" in q and "vulnerabilit" in q:
            response_text = (
                "### Critical Vulnerability Assessment\n\n"
                "Based on the latest authorized vulnerability telemetry for your organization:\n\n"
                "- **CVE-2024-21762 (FortiOS SSL-VPN RCE)**: Detected on `PROD-EDGE-FIREWALL-01` (192.168.10.1). "
                "This is a verified **CISA KEV** vulnerability with CVSS score **9.8 (Critical)**. Active weaponization is observed in the wild. "
                "Recommendation: Apply Fortinet security advisory FG-IR-24-015 immediately.\n"
                "- **CVE-2023-48788 (FortiClient EMS SQLi)**: CVSS **9.8 (Critical)** affecting management components.\n\n"
                "**Summary**: 2 critical vulnerabilities require priority patching. Both are flagged on perimeter infrastructure."
            )
        elif "risk" in q and "asset" in q:
            response_text = (
                "### High-Risk Asset Analysis\n\n"
                "The assets currently presenting the highest risk score in your inventory are:\n\n"
                "1. **PROD-EDGE-FIREWALL-01** (`192.168.10.1` | Router/Firewall)\n"
                "   - **Risk Score**: 95/100 (Critical)\n"
                "   - **Vulnerabilities**: CVE-2024-21762 (CISA KEV listed), CVE-2024-23113\n"
                "   - **Active Services**: HTTPS (8443), SSH (22)\n\n"
                "2. **DB-POSTGRES-PRIMARY** (`192.168.10.45` | Database Server)\n"
                "   - **Risk Score**: 84/100 (High)\n"
                "   - **Exposure**: Internal VLAN with anomalous failed authentication spikes\n\n"
                "**Recommendation**: Prioritize firmware upgrade on the perimeter firewall to eliminate external RCE exposure."
            )
        elif "alert" in q or "threat" in q or "event" in q:
            response_text = (
                "### Security Alerts Summary\n\n"
                "Recent correlated alert stream reflects the following primary threat patterns:\n\n"
                "- **Repeated SSH Brute Force**: 24 failed authentication attempts detected from IP `198.51.100.23` targeting bastion hosts.\n"
                "- **Known Malicious IOC Match**: Outbound DNS request resolved to `c2-delivery.badthreat.xyz`, matching AlienVault OTX threat indicator.\n"
                "- **Severity Distribution**: 1 Critical alert, 1 High alert currently in `New` triage queue awaiting analyst investigation.\n\n"
                "**Next Steps**: Open incident review in the Incident Operations Center or trigger asset isolation via Response Approvals."
            )
        elif "incident" in q:
            response_text = (
                "### Active Incident Review\n\n"
                "- **Case CS-2026-000001**: *Unauthorized Access Attempt via SSH*\n"
                "  - **Status**: `Investigating` | **Severity**: `High` | **Priority**: `P2`\n"
                "  - **Affected Asset**: `PROD-EDGE-FIREWALL-01` (`192.168.10.1`)\n"
                "  - **ATT&CK Tactic**: Credential Access (T1110 - Brute Force)\n"
                "  - **Timeline**: 4 audit events logged, 1 analyst note recorded\n\n"
                "No unhandled critical escalation breaches detected. Response playbooks are currently active."
            )
        elif "cve" in q or "explain" in q:
            response_text = (
                "### CVE Intelligence Summary\n\n"
                "**CVE-2024-21762** is an out-of-bounds write vulnerability in Fortinet FortiOS and FortiProxy SSL-VPN components. "
                "An unauthenticated, remote attacker can execute arbitrary code or commands via specially crafted HTTP requests. "
                "CISA added this flaw to the Known Exploited Vulnerabilities catalog due to active exploitation in state-sponsored espionage campaigns."
            )
        else:
            response_text = (
                "### SOC Assistant Security Briefing\n\n"
                "I have analyzed your organization's security posture and real-time telemetry:\n\n"
                "- **Monitored Inventory**: Active endpoints and perimeter devices are operating under continuous surveillance.\n"
                "- **Vulnerabilities**: Open findings are cross-referenced with NVD and CISA KEV feeds.\n"
                "- **Operational Incidents**: Any disruptive response actions remain gated behind the human-in-the-loop Response Approval Workflow.\n\n"
                "You can ask me about specific CVEs, high-risk assets, active alerts, incident investigations, or remediation playbooks."
            )

        in_tok = AIGuardrails.estimate_tokens(system_prompt + user_prompt)
        out_tok = AIGuardrails.estimate_tokens(response_text)

        return {
            "content": response_text,
            "input_tokens": in_tok,
            "output_tokens": out_tok,
            "model": self.model_name,
            "provider": self.provider_name,
            "is_mock": True,
        }


# ------------------------------------------------------------------------------
# Live OpenAI / Gemini Provider (When Configured)
# ------------------------------------------------------------------------------
class OpenAICompatibleProvider(BaseAIProvider):
    def __init__(self, api_key: str, model_name: str, base_url: Optional[str] = None):
        self.api_key = api_key
        self.model_name = model_name
        self.base_url = (base_url or "https://api.openai.com/v1").rstrip("/")
        self.provider_name = "openai_compatible"

    async def generate_response(
        self,
        system_prompt: str,
        user_prompt: str,
        conversation_history: Optional[List[Dict[str, str]]] = None,
        temperature: float = 0.2,
        max_tokens: int = 2048,
    ) -> Dict[str, Any]:
        messages = [{"role": "system", "content": system_prompt}]
        if conversation_history:
            messages.extend(conversation_history)
        messages.append({"role": "user", "content": user_prompt})

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        body = {
            "model": self.model_name,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

        try:
            async with httpx.AsyncClient(timeout=ai_config.TIMEOUT_SECONDS) as client:
                res = await client.post(f"{self.base_url}/chat/completions", headers=headers, json=body)
                if res.status_code != 200:
                    logger.error(f"Live AI provider error {res.status_code}: {res.text}")
                    # Fall back cleanly to mock provider response if live provider fails
                    mock_fallback = MockAIProvider()
                    return await mock_fallback.generate_response(system_prompt, user_prompt, conversation_history)

                data = res.json()
                content = data["choices"][0]["message"]["content"]
                usage = data.get("usage", {})
                return {
                    "content": content,
                    "input_tokens": usage.get("prompt_tokens", 0),
                    "output_tokens": usage.get("completion_tokens", 0),
                    "model": self.model_name,
                    "provider": self.provider_name,
                    "is_mock": False,
                }
        except Exception as e:
            logger.warning(f"Error calling live AI provider: {e}. Falling back to mock engine.")
            mock_fallback = MockAIProvider()
            return await mock_fallback.generate_response(system_prompt, user_prompt, conversation_history)


# ------------------------------------------------------------------------------
# Provider Factory
# ------------------------------------------------------------------------------
def get_ai_provider() -> BaseAIProvider:
    if ai_config.is_live_provider:
        return OpenAICompatibleProvider(
            api_key=ai_config.API_KEY,
            model_name=ai_config.MODEL,
            base_url=ai_config.API_BASE_URL,
        )
    return MockAIProvider(model_name=ai_config.MODEL)
