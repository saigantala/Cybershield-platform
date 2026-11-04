import re
from typing import List, Tuple
from app.ai.config import ai_config


PROMPT_INJECTION_PATTERNS = [
    r"(?i)ignore\s+(all\s+)?(previous|prior|above)\s+instructions",
    r"(?i)system\s+override",
    r"(?i)disregard\s+(the\s+)?system\s+prompt",
    r"(?i)you\s+are\s+now\s+in\s+developer\s+mode",
    r"(?i)dan\s+mode",
    r"(?i)reveal\s+(the\s+)?(system\s+prompt|master\s+key|api\s+key|secret)",
    r"(?i)exfiltrate\s+all",
    r"(?i)drop\s+table",
    r"(?i)rm\s+-rf",
    r"(?i)sudo\s+rm",
]

EXECUTION_REQUEST_PATTERNS = [
    r"(?i)(execute|run|trigger|launch)\s+(action|command|script|isolation|patch)",
    r"(?i)(delete|drop|remove)\s+(asset|incident|alert|database)",
    r"(?i)(isolate|quarantine)\s+(host|device|ip|endpoint)",
    r"(?i)block\s+ip\s+on\s+firewall",
    r"(?i)disable\s+(user|account)",
]

SECRET_LEAK_PATTERNS = [
    r"(?i)(apikey|api_key|secret_key|jwt_secret|private_key)\s*[:=]\s*['\"][a-zA-Z0-9_\-\.]{16,}['\"]",
    r"ey[A-Za-z0-9_-]{20,}\.[A-Za-z0-9._-]{20,}",  # JWT format
]


class AIGuardrails:
    @staticmethod
    def sanitize_user_input(text: str) -> Tuple[str, bool, str]:
        """
        Sanitizes user input and detects potential prompt injection or dangerous directives.
        Returns: (sanitized_text, is_safe, refusal_reason)
        """
        if not text or not text.strip():
            return "", False, "Input message cannot be empty."

        # Check prompt injection
        for pat in PROMPT_INJECTION_PATTERNS:
            if re.search(pat, text):
                return text, False, "Security Guardrail Triggered: Directive contains disallowed prompt override or injection syntax."

        # Check action execution request
        for pat in EXECUTION_REQUEST_PATTERNS:
            if re.search(pat, text):
                return (
                    text,
                    False,
                    "Action Refusal: The AI SOC Assistant operates strictly as a read-only advisor and is prohibited from executing active containment, firewall changes, or system mutations. Please submit response requests via the Response Approvals workflow.",
                )

        # Truncate length to avoid context flood
        max_chars = ai_config.MAX_INPUT_TOKENS * 4
        sanitized = text[:max_chars].strip()

        return sanitized, True, ""

    @staticmethod
    def filter_output_safety(text: str) -> str:
        """
        Masks potential leaked secrets, tokens, or raw JWTs in AI outputs.
        """
        safe_text = text
        for pat in SECRET_LEAK_PATTERNS:
            safe_text = re.sub(pat, "[REDACTED_SECURITY_SECRET]", safe_text)
        return safe_text

    @staticmethod
    def estimate_tokens(text: str) -> int:
        """Heuristic token estimation: ~4 chars per token."""
        if not text:
            return 0
        return max(1, len(text) // 4)
