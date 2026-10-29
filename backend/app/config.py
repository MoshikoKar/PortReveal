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


def _settings_env_file() -> str:
    """Env file for boot settings. `PORTREVEAL_ENV_FILE` overrides (used by scripts/run.ps1).

    Legacy `NETWORK_FINDER_ENV_FILE` is still accepted.
    """
    override = (
        os.environ.get("PORTREVEAL_ENV_FILE")
        or os.environ.get("NETWORK_FINDER_ENV_FILE")
        or ""
    ).strip()
    if override:
        return override
    return str(PROJECT_ROOT / ".env")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=_settings_env_file(),
        env_file_encoding="utf-8",
        extra="ignore",
        secrets_dir=_SECRETS_DIR,
    )

    app_env: Literal["development", "production", "test"] = "development"
    log_level: str = "INFO"
    log_format: Literal["text", "json"] = "text"
    # API requests slower than this are logged as warnings (logger "app.perf"); faster ones at DEBUG
    slow_request_ms: int = 1000

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
    # Comma-separated IPv4 addresses of the machine PortReveal runs on, for setups where nmap cannot see
    # them as local interfaces (bridged Docker container: the host's LAN IP). Local interface addresses
    # are detected automatically; these are only added to them.
    scanner_host_ips: str = ""
    mock_scan_delay: float = 0.4

    app_secret_key: str = ""
    session_idle_minutes: int = 480
    session_max_hours: int = 24
    cookie_secure: bool = False
    # Production override: allow Secure=false when serving plain HTTP on a trusted LAN.
    cookie_allow_http: bool = False
    login_max_failures: int = 10
    login_window_minutes: int = 15

    dev_seed: bool = True
    dev_admin_username: str = "admin"
    dev_admin_password: str = "admin"

    # Disable the background worker/scheduler (tests drive scans directly)
    background_jobs: bool = True

    # Inventory import guards (refused before the existing inventory is touched)
    import_max_upload_mb: int = 512  # compressed ZIP accepted by POST /api/data/import
    import_max_uncompressed_mb: int = 8192  # sum of the package's JSONL entries (zip-bomb guard)
    import_max_rows: int = 20_000_000  # all tables together

    # Wordlist library guards (uploads and URL imports; enforced while streaming)
    wordlist_max_upload_mb: int = 10  # bytes received (compressed, for .gz)
    wordlist_max_decompressed_mb: int = 50
    wordlist_max_entries: int = 1_000_000
    # URL imports are https-only unless this is set (plain http is open to tampering in transit).
    wordlist_allow_http: bool = False

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


# Placeholder shipped in .env.production.example; starting with it is the same as starting without a key.
SECRET_KEY_PLACEHOLDER = "replace-with-output-of-openssl-rand-hex-32"


class ConfigError(RuntimeError):
    """Boot configuration that must be fixed before the application may start."""


def check_production_config(s: Settings) -> None:
    """Fail fast on production settings that would otherwise break later or silently.

    Production requires an explicit APP_SECRET_KEY: the fallback key generated into the data
    directory is lost with that directory, and every stored SMTP/LDAP password with it.

    Production also requires COOKIE_SECURE=true unless COOKIE_ALLOW_HTTP=true is set for
    intentional plain-HTTP (trusted LAN) deployments.
    """
    if s.app_env != "production":
        return
    secret = s.app_secret_key.strip()
    if not secret or secret == SECRET_KEY_PLACEHOLDER:
        key_file = s.data_path / ".secret_key"
        hint = (f"An earlier start generated {key_file}: set APP_SECRET_KEY to its contents to keep "
                "existing encrypted SMTP/LDAP passwords readable." if key_file.is_file()
                else "Generate one with: openssl rand -hex 32")
        raise ConfigError(f"APP_SECRET_KEY must be set when APP_ENV=production. {hint} "
                          "Back the key up together with the database.")
    if not s.cookie_secure and not s.cookie_allow_http:
        raise ConfigError(
            "COOKIE_SECURE must be true when APP_ENV=production. "
            "Terminate TLS at a reverse proxy for non-localhost clients, "
            "or set COOKIE_ALLOW_HTTP=true only for trusted plain-HTTP LAN access."
        )


@lru_cache
def get_settings() -> Settings:
    return Settings()


def reset_settings_cache() -> None:
    get_settings.cache_clear()


def env_flag(name: str) -> bool:
    return os.environ.get(name, "").lower() in {"1", "true", "yes", "on"}
