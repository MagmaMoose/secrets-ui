"""Everything the server reads from its environment, parsed and checked once at startup.

A value that would make the server unsafe or useless fails startup rather than the first
request: a pod in CrashLoopBackOff with the reason in its log is found in minutes.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

_GUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_HOST = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")
_LOOPBACK = {"localhost", "127.0.0.1", "::1"}  # DevSkim: ignore DS162092 - plain http is allowed on loopback, for local development
PROVIDERS = ("azure-keyvault",)


class ConfigError(ValueError):
    """A configuration value the server refuses to start with."""


@dataclass(frozen=True)
class AzureKeyVaultConfig:
    roles: re.Pattern[str]
    suffix: str = "vault.azure.net"
    # {vault: label}, in the order to show the vaults in.
    labels: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class Config:
    tenant_id: str
    client_id: str
    origin: str
    authority: str
    session_key: bytes
    session_seconds: int
    federated_token_file: Path | None = None
    client_secret: str | None = None
    azure_keyvault: AzureKeyVaultConfig | None = None
    static_dir: Path | None = None
    port: int = 8080
    version: str = "dev"
    providers: tuple[str, ...] = field(default=PROVIDERS)

    @property
    def redirect_uri(self) -> str:
        return f"{self.origin}/auth/callback"

    @property
    def secure_cookies(self) -> bool:
        return self.origin.startswith("https://")


def _guid(env: dict[str, str], name: str) -> str:
    value = env.get(name, "").strip().lower()
    if not _GUID.match(value):
        raise ConfigError(f"{name} must be a GUID")
    return value


def _origin(value: str) -> str:
    parts = urlsplit(value.strip())
    host = (parts.hostname or "").lower()
    if parts.path not in ("", "/") or parts.query or parts.fragment or parts.username or not host:
        raise ConfigError("SECRETS_UI_PUBLIC_ORIGIN must be scheme://host[:port], with no path")
    if parts.scheme != "https" and not (parts.scheme == "http" and host in _LOOPBACK):
        raise ConfigError("SECRETS_UI_PUBLIC_ORIGIN must be https (plain http only on a loopback address)")
    return f"{parts.scheme}://{parts.netloc.lower()}"


def _authority(value: str) -> str:
    parts = urlsplit(value.strip() or "https://login.microsoftonline.com")
    if parts.scheme != "https" or not _HOST.match((parts.hostname or "").lower()) or parts.path not in ("", "/"):
        raise ConfigError("AZURE_AUTHORITY_HOST must be an https host, such as https://login.microsoftonline.com")
    return f"https://{parts.netloc.lower()}"


def _secret(env: dict[str, str], name: str) -> str:
    """NAME, or the contents of the file NAME_FILE points at."""
    value = env.get(name, "")
    if not value and env.get(f"{name}_FILE"):
        try:
            value = Path(env[f"{name}_FILE"]).read_text().strip()
        except OSError as err:
            raise ConfigError(f"cannot read {name}_FILE: {err.__class__.__name__}") from err
    return value


def _pattern(env: dict[str, str], name: str) -> re.Pattern[str]:
    try:
        return re.compile(env.get(name, ".+"))
    except re.error as err:
        raise ConfigError(f"{name} is not a valid regular expression: {err}") from err


def _stores(env: dict[str, str], name: str) -> list[dict[str, Any]]:
    """NAME as a JSON list of stores, each {"name": ..., "label": ...}, in the order to show them in."""
    raw = env.get(name, "").strip()
    if not raw:
        return []
    try:
        items = json.loads(raw)
    except ValueError as err:
        raise ConfigError(f"{name} is not valid JSON: {err}") from err
    if not isinstance(items, list) or not all(isinstance(i, dict) and isinstance(i.get("name"), str) and i["name"] for i in items):
        raise ConfigError(f'{name} must be a JSON list such as [{{"name": "team-a-keyvault-dev", "label": "Team A dev"}}]')
    names = [i["name"] for i in items]
    if len(set(names)) != len(names):
        raise ConfigError(f"{name} lists a store twice")
    for item in items:
        label = item.get("label", "")
        if not isinstance(label, str) or len(label) > 64 or not label.isprintable():
            raise ConfigError(f"{name}: the label of {item['name']} must be text of at most 64 characters")
    return items


def load_config(env: dict[str, str] | None = None) -> Config:
    env = dict(os.environ if env is None else env)

    token_file = env.get("AZURE_FEDERATED_TOKEN_FILE", "").strip()
    secret = _secret(env, "AZURE_CLIENT_SECRET")
    if not token_file and not secret:
        raise ConfigError("set AZURE_FEDERATED_TOKEN_FILE (workload identity), AZURE_CLIENT_SECRET or AZURE_CLIENT_SECRET_FILE")

    session_key = _secret(env, "SECRETS_UI_SESSION_KEY")
    if len(session_key) < 32:
        raise ConfigError("SECRETS_UI_SESSION_KEY (or SECRETS_UI_SESSION_KEY_FILE) must hold at least 32 characters")

    providers = tuple(p.strip() for p in env.get("SECRETS_UI_PROVIDERS", ",".join(PROVIDERS)).split(",") if p.strip())
    unknown = sorted(set(providers) - set(PROVIDERS))
    if unknown or not providers:
        raise ConfigError(f"SECRETS_UI_PROVIDERS takes {', '.join(PROVIDERS)}; got {', '.join(unknown) or 'none'}")

    azure_keyvault = None
    if "azure-keyvault" in providers:
        suffix = env.get("SECRETS_UI_AZURE_KEYVAULT_SUFFIX", "vault.azure.net").strip().lower()
        if not _HOST.match(suffix):
            raise ConfigError("SECRETS_UI_AZURE_KEYVAULT_SUFFIX must be a DNS suffix, such as vault.azure.net")
        labels = {s["name"]: s.get("label") or s["name"] for s in _stores(env, "SECRETS_UI_AZURE_KEYVAULT_STORES")}
        azure_keyvault = AzureKeyVaultConfig(roles=_pattern(env, "SECRETS_UI_AZURE_KEYVAULT_ROLES"), suffix=suffix, labels=labels)

    try:
        hours = int(env.get("SECRETS_UI_SESSION_HOURS", "8"))
        port = int(env.get("PORT", "8080"))
    except ValueError as err:
        raise ConfigError("SECRETS_UI_SESSION_HOURS and PORT must be whole numbers") from err
    if not 1 <= hours <= 24:
        raise ConfigError("SECRETS_UI_SESSION_HOURS must be between 1 and 24")

    if "SECRETS_UI_PUBLIC_ORIGIN" not in env:
        raise ConfigError("SECRETS_UI_PUBLIC_ORIGIN is required, such as https://secrets.example.com")
    static = env.get("SECRETS_UI_STATIC_DIR", "/app/static")

    return Config(
        tenant_id=_guid(env, "AZURE_TENANT_ID"),
        client_id=_guid(env, "AZURE_CLIENT_ID"),
        origin=_origin(env["SECRETS_UI_PUBLIC_ORIGIN"]),
        authority=_authority(env.get("AZURE_AUTHORITY_HOST", "")),
        session_key=session_key.encode(),
        session_seconds=hours * 3600,
        federated_token_file=Path(token_file) if token_file else None,
        client_secret=secret or None,
        azure_keyvault=azure_keyvault,
        static_dir=Path(static) if static and Path(static).is_dir() else None,
        port=port,
        version=env.get("APP_VERSION", "dev"),
        providers=providers,
    )
