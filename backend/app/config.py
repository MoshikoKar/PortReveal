"""Process configuration from environment variables / .env.

Runtime-editable settings (schedule, SMTP, LDAP, ...) live in the database,
see app/settings_store.py. This module only holds what is needed to boot.
"""
from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Literal
from urllib.parse import quote

from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parents[2]
_SECRETS_DIR = "/run/secrets" if Path("/run/secrets").is_dir() else None


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(PROJECT_ROOT / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
        secrets_dir=_SECRETS_DIR,
    )

    app_env: Literal["development", "production", "test"] = "development"
    log_level: str = "INFO"

    database_url: str = ""
    # Alternative to DATABASE_URL (used by docker compose; avoids URL-escaping passwords)
    postgres_host: str = ""
    postgres_port: int = 5432
    postgres_db: str = "netfinder"
    postgres_user: str = "netfinder"
    postgres_password: str = ""

    data_dir: str = "./data"
    frontend_dist: str = ""

    scanner_mode: Literal["auto", "nmap", "mock"] = "auto"
    nmap_path: str = "nmap"
    nmap_privileged: Literal["auto", "true", "false"] = "auto"
    mock_scan_delay: float = 0.4

    app_secret_key: str = ""
    session_idle_minutes: int = 480
    session_max_hours: int = 24
    cookie_secure: bool = False
    login_max_failures: int = 10
    login_window_minutes: int = 15

    dev_seed: bool = True
    dev_admin_username: str = "admin"
    dev_admin_password: str = "admin"

    # Disable the background worker/scheduler (tests drive scans directly)
    background_jobs: bool = True

    @property
    def is_dev(self) -> bool:
        return self.app_env != "production"

    @property
    def data_path(self) -> Path:
        p = Path(self.data_dir)
        return p if p.is_absolute() else (PROJECT_ROOT / p).resolve()

    @property
    def frontend_dist_path(self) -> Path:
        if self.frontend_dist:
            return Path(self.frontend_dist)
        return PROJECT_ROOT / "frontend" / "dist"

    @property
    def sqlalchemy_url(self) -> str:
        url = self.database_url.strip()
        if not url and self.postgres_host:
            url = (
                f"postgresql+psycopg://{quote(self.postgres_user, safe='')}:"
                f"{quote(self.postgres_password, safe='')}@{self.postgres_host}:"
                f"{self.postgres_port}/{quote(self.postgres_db, safe='')}"
            )
        if not url:
            url = "sqlite:///./data/dev.db"
        if url.startswith("postgres://"):
            url = "postgresql://" + url[len("postgres://"):]
        if url.startswith("postgresql://"):
            url = "postgresql+psycopg://" + url[len("postgresql://"):]
        if url.startswith("sqlite:///") and not url.startswith("sqlite:////") and ":memory:" not in url:
            rel = url[len("sqlite:///"):]
            path = Path(rel)
            if not path.is_absolute():
                path = (PROJECT_ROOT / path).resolve()
            url = f"sqlite:///{path.as_posix()}"
        return url

    @property
    def db_type(self) -> str:
        return "sqlite" if self.sqlalchemy_url.startswith("sqlite") else "postgresql"


@lru_cache
def get_settings() -> Settings:
    return Settings()


def reset_settings_cache() -> None:
    get_settings.cache_clear()


def env_flag(name: str) -> bool:
    return os.environ.get(name, "").lower() in {"1", "true", "yes", "on"}
