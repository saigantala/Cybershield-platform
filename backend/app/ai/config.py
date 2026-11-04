import os
from pydantic import BaseModel, Field


class AIConfig(BaseModel):
    # Provider configuration
    PROVIDER: str = Field(default_factory=lambda: os.getenv("CYBERSHIELD_AI_PROVIDER", "mock"))
    MODEL: str = Field(default_factory=lambda: os.getenv("CYBERSHIELD_AI_MODEL", "cybershield-soc-v1"))
    API_KEY: str = Field(default_factory=lambda: os.getenv("CYBERSHIELD_AI_API_KEY", ""))
    API_BASE_URL: str = Field(default_factory=lambda: os.getenv("CYBERSHIELD_AI_BASE_URL", ""))

    # Guardrails and Limits
    TIMEOUT_SECONDS: float = Field(default_factory=lambda: float(os.getenv("CYBERSHIELD_AI_TIMEOUT", "15.0")))
    MAX_INPUT_TOKENS: int = Field(default_factory=lambda: int(os.getenv("CYBERSHIELD_AI_MAX_INPUT_TOKENS", "4096")))
    MAX_OUTPUT_TOKENS: int = Field(default_factory=lambda: int(os.getenv("CYBERSHIELD_AI_MAX_OUTPUT_TOKENS", "2048")))
    TEMPERATURE: float = Field(default_factory=lambda: float(os.getenv("CYBERSHIELD_AI_TEMPERATURE", "0.2")))

    # Cost Estimation ($ per 1K tokens)
    INPUT_COST_PER_1K: float = 0.0015
    OUTPUT_COST_PER_1K: float = 0.0020

    @property
    def is_live_provider(self) -> bool:
        return self.PROVIDER.lower() in ("openai", "gemini", "anthropic") and bool(self.API_KEY.strip())


ai_config = AIConfig()
