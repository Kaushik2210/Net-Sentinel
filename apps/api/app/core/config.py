"""Application settings, loaded from environment variables (and an optional .env file).

No secret has a usable default in production: when ``ENVIRONMENT`` is anything other
than ``development``/``test`` the app refuses to start without ``JWT_SECRET``.
"""

import secrets
from functools import lru_cache
from typing import Literal

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=("../../.env", ".env"), env_file_encoding="utf-8", extra="ignore"
    )

    environment: Literal["development", "test", "production"] = "development"
    app_name: str = "NetSentinel"
    app_version: str = "0.1.0"

    # Database. SQLite is used for local development and tests; PostgreSQL is the
    # target for docker-compose / production (postgresql+psycopg://...).
    database_url: str = "sqlite:///./netsentinel.db"

    # Auth
    jwt_secret: str = ""
    jwt_algorithm: str = "HS256"
    access_token_minutes: int = 60

    # Dev seed accounts. Passwords come from the environment; nothing is hard-coded.
    seed_admin_password: str = ""
    seed_analyst_password: str = ""
    seed_viewer_password: str = ""

    cors_origins: str = "http://localhost:3000"
    rate_limit_login: str = "10/minute"
    rate_limit_default: str = "240/minute"

    # Telemetry source. "simulation" generates synthetic traffic; real adapters
    # (zeek, suricata, pcap, netflow, syslog) plug in behind the same interface.
    telemetry_mode: Literal["simulation", "idle"] = "simulation"
    simulation_seed: int = 1337
    simulation_events_per_second: float = 4.0
    event_retention: int = Field(default=20000, ge=1000)

    @model_validator(mode="after")
    def _check_secrets(self) -> "Settings":
        if not self.jwt_secret:
            if self.environment == "production":
                raise ValueError("JWT_SECRET must be set when ENVIRONMENT=production")
            # Ephemeral secret: tokens are invalidated on every restart in dev/test.
            self.jwt_secret = secrets.token_urlsafe(48)
        return self

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
