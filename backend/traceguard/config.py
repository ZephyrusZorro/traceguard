"""Centralized application configuration for TraceGuard."""
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="TRACEGUARD_", env_file=".env", extra="ignore")

    app_name: str = "TraceGuard"
    version: str = "1.0.0"
    host: str = "127.0.0.1"
    port: int = 8000

    # Storage paths
    data_dir: Path = Path(__file__).resolve().parents[2] / "data"
    db_path: Path = Path(__file__).resolve().parents[2] / "data" / "traceguard.db"
    models_dir: Path = Path(__file__).resolve().parents[2] / "data" / "models"

    # Security & Auth (local dev defaults — override via env in production)
    admin_api_key: str = "tg-admin-local-dev-key"
    analyst_api_key: str = "tg-analyst-local-dev-key"
    viewer_api_key: str = "tg-viewer-local-dev-key"
    webhook_hmac_secret: str = "tg-webhook-hmac-dev-secret"
    rate_limit_per_minute: int = 240
    allow_localhost_webhooks: bool = True

    # Optional local Ollama narrative synthesis
    ollama_base_url: str = "http://127.0.0.1:11434"
    ollama_model: str = "llama3.2:3b"
    enable_ollama_summary: bool = False

    # Agent council resource budgets
    agent_timeout_seconds: float = 5.0
    max_counterfactual_candidates: int = 3


settings = Settings()
settings.data_dir.mkdir(parents=True, exist_ok=True)
settings.models_dir.mkdir(parents=True, exist_ok=True)
