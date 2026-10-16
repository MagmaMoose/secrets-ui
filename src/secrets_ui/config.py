"""Everything the server reads from its environment, parsed and checked once at startup.

A value that would make the server unsafe or useless fails startup rather than the first
request: a pod in CrashLoopBackOff with the reason in its log is found in minutes.
"""

from __future__ import annotations

import json
import os
import re
import ssl
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .providers.hashicorp_vault import PATH_RULE

_GUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_HOST = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")
_COLOUR = re.compile(r"^#[0-9a-fA-F]{6}$")
_STORE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_VAULT_PATH = re.compile(PATH_RULE)
_VAULT_ID = re.compile(r"^/subscriptions/[0-9a-f-]{36}/resourceGroups/[\w.()-]{1,90}/providers/Microsoft\.KeyVault/vaults/([a-z0-9-]{3,24})$", re.I)
_LOOPBACK = {"localhost", "127.0.0.1", "::1"}  # DevSkim: ignore DS162092 - plain http is allowed on loopback, for local development
PROVIDERS = ("azure-keyvault", "hashicorp-vault")


class ConfigError(ValueError):
    """A configuration value the server refuses to start with."""


@dataclass(frozen=True)
class AzureKeyVaultConfig:
    roles: re.Pattern[str]
    suffix: str = "vault.azure.net"
    # {vault: label}, in the order to show the vaults in.
    labels: dict[str, str] = field(default_factory=dict)
    # {vault: its Azure resource id}, for the vaults whose audit log the UI shows.
    resource_ids: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class HashiCorpVaultConfig:
    address: str
    # {store: (mount, folder)}, in the order to show the stores in.
    stores: dict[str, tuple[str, str]]
    labels: dict[str, str] = field(default_factory=dict)
    auth_mount: str = "jwt"
    auth_role: str = "secrets-ui"
    ca_file: Path | None = None


@dataclass(frozen=True)
class Branding:
    """Colours as #rrggbb; empty keeps the default. The dark ones fall back to the light ones."""

    accent: str = ""
    accent_text: str = ""
    accent_dark: str = ""
    accent_text_dark: str = ""


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
    hashicorp_vault: HashiCorpVaultConfig | None = None
    static_dir: Path | None = None
    port: int = 8080
    version: str = "dev"
    providers: tuple[str, ...] = ("azure-keyvault",)
    branding: Branding = field(default_factory=Branding)

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


def _origin(value: str, name: str = "SECRETS_UI_PUBLIC_ORIGIN") -> str:
    parts = urlsplit(value.strip())
    host = (parts.hostname or "").lower()
    if parts.path not in ("", "/") or parts.query or parts.fragment or parts.username or not host:
        raise ConfigError(f"{name} must be scheme://host[:port], with no path")
    if parts.scheme != "https" and not (parts.scheme == "http" and host in _LOOPBACK):
        raise ConfigError(f"{name} must be https (plain http only on a loopback address)")
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


def _hashicorp_vault(env: dict[str, str]) -> HashiCorpVaultConfig:
    name = "SECRETS_UI_HASHICORP_VAULT_STORES"
    stores = _stores(env, name)
    if not stores:
        raise ConfigError(f'{name} must list the stores, such as [{{"name": "team-a-vault-dev", "mount": "secret", "path": "dev/team-a"}}]')
    for store in stores:
        if not _STORE_NAME.match(store["name"]):
            raise ConfigError(f"{name}: {store['name']} must be letters, digits, dots, hyphens and underscores, as its app role is named")
        mount, path = store.get("mount"), store.get("path", "")
        if not isinstance(mount, str) or not _VAULT_PATH.match(mount) or not isinstance(path, str) or (path and not _VAULT_PATH.match(path)):
            raise ConfigError(f"{name}: {store['name']} needs a KV v2 mount, such as secret, and may take a folder path in it, such as dev/team-a")

    auth_mount = env.get("SECRETS_UI_HASHICORP_VAULT_AUTH_MOUNT", "jwt").strip().strip("/")
    if not _VAULT_PATH.match(auth_mount):
        raise ConfigError("SECRETS_UI_HASHICORP_VAULT_AUTH_MOUNT must be the path of a JWT auth mount, such as jwt")
    auth_role = env.get("SECRETS_UI_HASHICORP_VAULT_AUTH_ROLE", "secrets-ui").strip()
    if not _STORE_NAME.match(auth_role):
        raise ConfigError("SECRETS_UI_HASHICORP_VAULT_AUTH_ROLE must be the name of a role on that mount, such as secrets-ui")

    ca_file = env.get("SECRETS_UI_HASHICORP_VAULT_CA_FILE", "").strip()
    if ca_file:
        try:
            ssl.create_default_context(cafile=ca_file)
        except (OSError, ssl.SSLError) as err:
            raise ConfigError(f"SECRETS_UI_HASHICORP_VAULT_CA_FILE is not a readable PEM CA bundle: {err.__class__.__name__}") from err

    return HashiCorpVaultConfig(
        address=_origin(env.get("SECRETS_UI_HASHICORP_VAULT_ADDR", ""), "SECRETS_UI_HASHICORP_VAULT_ADDR"),
        stores={s["name"]: (s["mount"], s.get("path", "")) for s in stores},
        labels={s["name"]: s.get("label") or s["name"] for s in stores},
        auth_mount=auth_mount,
        auth_role=auth_role,
        ca_file=Path(ca_file) if ca_file else None,
    )


def load_config(env: dict[str, str] | None = None) -> Config:
    env = dict(os.environ if env is None else env)

    token_file = env.get("AZURE_FEDERATED_TOKEN_FILE", "").strip()
    secret = _secret(env, "AZURE_CLIENT_SECRET")
    if not token_file and not secret:
        raise ConfigError("set AZURE_FEDERATED_TOKEN_FILE (workload identity), AZURE_CLIENT_SECRET or AZURE_CLIENT_SECRET_FILE")

    session_key = _secret(env, "SECRETS_UI_SESSION_KEY")
    if len(session_key) < 32:
        raise ConfigError("SECRETS_UI_SESSION_KEY (or SECRETS_UI_SESSION_KEY_FILE) must hold at least 32 characters")

    providers = tuple(p.strip() for p in env.get("SECRETS_UI_PROVIDERS", "azure-keyvault").split(",") if p.strip())
    unknown = sorted(set(providers) - set(PROVIDERS))
    if unknown or not providers:
        raise ConfigError(f"SECRETS_UI_PROVIDERS takes {', '.join(PROVIDERS)}; got {', '.join(unknown) or 'none'}")

    azure_keyvault = None
    if "azure-keyvault" in providers:
        suffix = env.get("SECRETS_UI_AZURE_KEYVAULT_SUFFIX", "vault.azure.net").strip().lower()
        if not _HOST.match(suffix):
            raise ConfigError("SECRETS_UI_AZURE_KEYVAULT_SUFFIX must be a DNS suffix, such as vault.azure.net")
        stores = _stores(env, "SECRETS_UI_AZURE_KEYVAULT_STORES")
        resource_ids = {s["name"]: s["resource_id"] for s in stores if s.get("resource_id")}
        for name, resource_id in resource_ids.items():
            found = _VAULT_ID.match(str(resource_id))
            if not found or found.group(1).lower() != name:
                raise ConfigError(f"SECRETS_UI_AZURE_KEYVAULT_STORES: the resource_id of {name} must be /subscriptions/<id>/resourceGroups/<group>/providers/Microsoft.KeyVault/vaults/{name}")
        azure_keyvault = AzureKeyVaultConfig(
            roles=_pattern(env, "SECRETS_UI_AZURE_KEYVAULT_ROLES"),
            suffix=suffix,
            labels={s["name"]: s.get("label") or s["name"] for s in stores},
            resource_ids=resource_ids,
        )

    hashicorp_vault = None
    if "hashicorp-vault" in providers:
        hashicorp_vault = _hashicorp_vault(env)

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

    colours = {}
    for key in ("accent", "accent_text", "accent_dark", "accent_text_dark"):
        name = f"SECRETS_UI_BRAND_{key.upper()}"
        colours[key] = env.get(name, "").strip().lower()
        if colours[key] and not _COLOUR.match(colours[key]):
            raise ConfigError(f"{name} must be a colour as #rrggbb, such as #4f46e5")

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
        hashicorp_vault=hashicorp_vault,
        static_dir=Path(static) if static and Path(static).is_dir() else None,
        port=port,
        version=env.get("APP_VERSION", "dev"),
        providers=providers,
        branding=Branding(**colours),
    )
