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
_GOOGLE_CLIENT = re.compile(r"^[0-9]+-[a-z0-9]+\.apps\.googleusercontent\.com$")
_STORE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_VAULT_PATH = re.compile(PATH_RULE)
_REGION = re.compile(r"^[a-z]+(?:-[a-z]+)+-[0-9]+$")
_OCID = re.compile(r"^ocid1\.([a-z]+)\.[a-z0-9]+\.[a-z0-9.-]*\.[a-z0-9]+$")
_SECRET_STORE = re.compile(r"^(?:(?:ClusterSecretStore|SecretStore)/)?[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$")
_VAULT_ID = re.compile(r"^/subscriptions/[0-9a-f-]{36}/resourceGroups/[\w.()-]{1,90}/providers/Microsoft\.KeyVault/vaults/([a-z0-9-]{3,24})$", re.I)
_LOOPBACK = {"localhost", "127.0.0.1", "::1"}  # DevSkim: ignore DS162092 - plain http is allowed on loopback, for local development
PROVIDERS = ("azure-keyvault", "hashicorp-vault", "oci-vault")


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
    # {vault: "[<kind>/]<name>"}, the External Secrets store the examples point at.
    secret_stores: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class HashiCorpVaultConfig:
    address: str
    # {store: (mount, folder)}, in the order to show the stores in.
    stores: dict[str, tuple[str, str]]
    labels: dict[str, str] = field(default_factory=dict)
    secret_stores: dict[str, str] = field(default_factory=dict)
    auth_mount: str = "jwt"
    auth_role: str = "secrets-ui"
    ca_file: Path | None = None


@dataclass(frozen=True)
class OciVaultConfig:
    region: str
    # The identity domain that exchanges a person's ID token for an OCI session token, and the
    # OAuth app there the exchange authenticates as.
    domain: str
    client_id: str
    client_secret: str
    # {store: (compartment, vault, master key)}, in the order to show the stores in.
    stores: dict[str, tuple[str, str, str]]
    labels: dict[str, str] = field(default_factory=dict)
    secret_stores: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class Branding:
    """Colours as #rrggbb; empty keeps the default. The dark ones fall back to the light ones."""

    accent: str = ""
    accent_text: str = ""
    accent_dark: str = ""
    accent_text_dark: str = ""


@dataclass(frozen=True)
class Config:
    # The app at its identity provider: for Google, tenant_id is empty and authority is Google's.
    tenant_id: str
    client_id: str
    origin: str
    authority: str
    session_key: bytes
    session_seconds: int
    sign_in: str = "entra"
    # Google only: the Workspace domains whose accounts may sign in.
    google_domains: tuple[str, ...] = ()
    federated_token_file: Path | None = None
    client_secret: str | None = None
    azure_keyvault: AzureKeyVaultConfig | None = None
    hashicorp_vault: HashiCorpVaultConfig | None = None
    oci_vault: OciVaultConfig | None = None
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
        if "secret_store" in item and not (isinstance(item["secret_store"], str) and _SECRET_STORE.match(item["secret_store"])):
            raise ConfigError(f"{name}: the secret_store of {item['name']} must be a store name, or ClusterSecretStore/<name> or SecretStore/<name>")
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
        secret_stores={s["name"]: s["secret_store"] for s in stores if "secret_store" in s},
        auth_mount=auth_mount,
        auth_role=auth_role,
        ca_file=Path(ca_file) if ca_file else None,
    )


def _oci_vault(env: dict[str, str]) -> OciVaultConfig:
    name = "SECRETS_UI_OCI_STORES"
    stores = _stores(env, name)
    if not stores:
        raise ConfigError(f'{name} must list the stores, such as [{{"name": "team-a-oci-dev", "compartment": "ocid1.compartment...", "vault": "ocid1.vault...", "key": "ocid1.key..."}}]')
    for store in stores:
        if not _STORE_NAME.match(store["name"]):
            raise ConfigError(f"{name}: {store['name']} must be letters, digits, dots, hyphens and underscores, as its role or group is named")
        for key, kinds in (("compartment", ("compartment", "tenancy")), ("vault", ("vault",)), ("key", ("key",))):
            found = _OCID.match(str(store.get(key, "")))
            if not found or found.group(1) not in kinds:
                raise ConfigError(f"{name}: {store['name']} needs the OCID of its {key} (ocid1.{kinds[0]}...)")
    region = env.get("SECRETS_UI_OCI_REGION", "").strip()
    if not _REGION.match(region):
        raise ConfigError("SECRETS_UI_OCI_REGION must be a region identifier, such as eu-amsterdam-1")
    client_id = env.get("SECRETS_UI_OCI_CLIENT_ID", "").strip()
    client_secret = _secret(env, "SECRETS_UI_OCI_CLIENT_SECRET")
    if not client_id or not client_secret:
        raise ConfigError("set SECRETS_UI_OCI_CLIENT_ID and SECRETS_UI_OCI_CLIENT_SECRET (or _FILE): the identity domain app the token exchange runs as")
    return OciVaultConfig(
        region=region,
        domain=_origin(env.get("SECRETS_UI_OCI_DOMAIN_URL", ""), "SECRETS_UI_OCI_DOMAIN_URL"),
        client_id=client_id,
        client_secret=client_secret,
        stores={s["name"]: (s["compartment"], s["vault"], s["key"]) for s in stores},
        labels={s["name"]: s.get("label") or s["name"] for s in stores},
        secret_stores={s["name"]: s["secret_store"] for s in stores if "secret_store" in s},
    )


def _google(env: dict[str, str]) -> dict[str, Any]:
    client_id = env.get("GOOGLE_CLIENT_ID", "").strip()
    if not _GOOGLE_CLIENT.match(client_id):
        raise ConfigError("GOOGLE_CLIENT_ID must be an OAuth client id, such as 1234-abc.apps.googleusercontent.com")
    secret = _secret(env, "GOOGLE_CLIENT_SECRET")
    if not secret:
        raise ConfigError("set GOOGLE_CLIENT_SECRET or GOOGLE_CLIENT_SECRET_FILE")
    domains = tuple(d.strip().lower() for d in env.get("SECRETS_UI_GOOGLE_DOMAINS", "").split(",") if d.strip())
    # Without a domain any Google account could sign in, so there is no default.
    if not domains or not all(_HOST.match(d) for d in domains):
        raise ConfigError("SECRETS_UI_GOOGLE_DOMAINS must list the Workspace domains whose accounts may sign in, such as example.com")
    return {
        "tenant_id": "",
        "client_id": client_id,
        "authority": "https://accounts.google.com",
        "client_secret": secret,
        "google_domains": domains,
    }


def load_config(env: dict[str, str] | None = None) -> Config:
    env = dict(os.environ if env is None else env)

    sign_in = env.get("SECRETS_UI_SIGN_IN", "entra").strip()
    if sign_in not in ("entra", "google"):
        raise ConfigError("SECRETS_UI_SIGN_IN takes entra or google")
    if sign_in == "entra":
        token_file = env.get("AZURE_FEDERATED_TOKEN_FILE", "").strip()
        secret = _secret(env, "AZURE_CLIENT_SECRET")
        if not token_file and not secret:
            raise ConfigError("set AZURE_FEDERATED_TOKEN_FILE (workload identity), AZURE_CLIENT_SECRET or AZURE_CLIENT_SECRET_FILE")
        identity = {
            "tenant_id": _guid(env, "AZURE_TENANT_ID"),
            "client_id": _guid(env, "AZURE_CLIENT_ID"),
            "authority": _authority(env.get("AZURE_AUTHORITY_HOST", "")),
            "federated_token_file": Path(token_file) if token_file else None,
            "client_secret": secret or None,
        }
    else:
        identity = _google(env)

    session_key = _secret(env, "SECRETS_UI_SESSION_KEY")
    if len(session_key) < 32:
        raise ConfigError("SECRETS_UI_SESSION_KEY (or SECRETS_UI_SESSION_KEY_FILE) must hold at least 32 characters")

    default = "azure-keyvault" if sign_in == "entra" else ""
    providers = tuple(p.strip() for p in env.get("SECRETS_UI_PROVIDERS", default).split(",") if p.strip())
    unknown = sorted(set(providers) - set(PROVIDERS))
    if unknown or not providers:
        raise ConfigError(f"SECRETS_UI_PROVIDERS takes {', '.join(PROVIDERS)}; got {', '.join(unknown) or 'none'}")
    if sign_in == "google" and "azure-keyvault" in providers:
        raise ConfigError("azure-keyvault needs SECRETS_UI_SIGN_IN=entra: Key Vault takes Entra ID tokens only")

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
            secret_stores={s["name"]: s["secret_store"] for s in stores if "secret_store" in s},
        )

    hashicorp_vault = None
    if "hashicorp-vault" in providers:
        hashicorp_vault = _hashicorp_vault(env)
    oci_vault = _oci_vault(env) if "oci-vault" in providers else None

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
        origin=_origin(env["SECRETS_UI_PUBLIC_ORIGIN"]),
        session_key=session_key.encode(),
        session_seconds=hours * 3600,
        sign_in=sign_in,
        **identity,
        azure_keyvault=azure_keyvault,
        hashicorp_vault=hashicorp_vault,
        oci_vault=oci_vault,
        static_dir=Path(static) if static and Path(static).is_dir() else None,
        port=port,
        version=env.get("APP_VERSION", "dev"),
        providers=providers,
        branding=Branding(**colours),
    )
