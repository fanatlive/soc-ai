from dataclasses import dataclass, field
from ipaddress import ip_network
from pathlib import Path
from urllib.parse import urlparse
import os

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent


def csv_env(name: str, default: str) -> tuple[str, ...]:
    return tuple(value.strip() for value in os.getenv(name, default).split(",") if value.strip())


@dataclass(frozen=True)
class Settings:
    database_url: str = "sqlite:///./soc_triage.db"
    llm_api_key: str = field(default="", repr=False)
    llm_base_url: str = "https://api.openai.com/v1"
    llm_model: str = ""
    llm_fallback_models: tuple[str, ...] = ()
    llm_timeout_seconds: float = 25
    llm_max_concurrency: int = 4
    llm_queue_timeout_seconds: float = 2
    auto_seed_demo: bool = True
    trusted_networks: tuple[str, ...] = ("192.168.0.0/16",)
    allowed_origins: tuple[str, ...] = ("http://127.0.0.1:8000", "http://localhost:8000")
    allowed_hosts: tuple[str, ...] = ("127.0.0.1", "localhost", "[::1]")
    api_token: str = field(default="", repr=False)

    def __post_init__(self):
        if not self.database_url.startswith("sqlite:"):
            raise ValueError("MVP поддерживает только SQLite")
        if not 1 <= self.llm_timeout_seconds <= 120:
            raise ValueError("LLM_TIMEOUT_SECONDS: допустимо от 1 до 120 секунд")
        if len(self.llm_fallback_models) > 2:
            raise ValueError("LLM_FALLBACK_MODELS: не более двух резервных моделей")
        if self.llm_timeout_seconds * (1 + len(self.llm_fallback_models)) > 170:
            raise ValueError("LLM_TIMEOUT_SECONDS с резервными моделями не должен превышать 170 секунд (блокировка анализа — 180)")
        if not 1 <= self.llm_max_concurrency <= 16 or not 0.1 <= self.llm_queue_timeout_seconds <= 10:
            raise ValueError("LLM_MAX_CONCURRENCY: 1–16; LLM_QUEUE_TIMEOUT_SECONDS: 0.1–10")
        if self.api_token and len(self.api_token) < 24:
            raise ValueError("API_TOKEN должен содержать не менее 24 символов")
        parsed = urlparse(self.llm_base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("LLM_BASE_URL должен быть HTTP(S) URL без встроенных секретов")
        if parsed.scheme == "http" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
            raise ValueError("Для внешнего LLM требуется HTTPS")
        if parsed.query or parsed.fragment:
            raise ValueError("LLM_BASE_URL не должен содержать query или fragment")
        for network in self.trusted_networks:
            ip_network(network)

    @classmethod
    def from_env(cls):
        load_dotenv(ROOT / ".env", override=False)
        return cls(
            database_url=os.getenv("DATABASE_URL", "sqlite:///./soc_triage.db"),
            llm_api_key=os.getenv("LLM_API_KEY", ""),
            llm_base_url=os.getenv("LLM_BASE_URL", "https://api.openai.com/v1").rstrip("/"),
            llm_model=os.getenv("LLM_MODEL", ""),
            llm_fallback_models=csv_env("LLM_FALLBACK_MODELS", ""),
            llm_timeout_seconds=float(os.getenv("LLM_TIMEOUT_SECONDS", "25")),
            llm_max_concurrency=int(os.getenv("LLM_MAX_CONCURRENCY", "4")),
            llm_queue_timeout_seconds=float(os.getenv("LLM_QUEUE_TIMEOUT_SECONDS", "2")),
            auto_seed_demo=os.getenv("AUTO_SEED_DEMO", "true").lower() == "true",
            trusted_networks=csv_env("TRUSTED_NETWORKS", "192.168.0.0/16"),
            allowed_origins=csv_env("ALLOWED_ORIGINS", "http://127.0.0.1:8000,http://localhost:8000"),
            allowed_hosts=csv_env("ALLOWED_HOSTS", "127.0.0.1,localhost,[::1]"),
            api_token=os.getenv("API_TOKEN", ""),
        )
