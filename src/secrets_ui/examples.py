"""Example manifests that read one secret into Kubernetes with the External Secrets Operator.

Built from names alone: nothing here calls the store, and no value is in them.
"""

from __future__ import annotations

import json
import re
from typing import Any

_PLAIN = re.compile(r"^[A-Za-z][A-Za-z0-9._/-]*$")
# YAML 1.1 reads these as booleans or null, so they are quoted.
_WORDS = {"y", "yes", "n", "no", "true", "false", "on", "off", "null"}


def _scalar(value: Any) -> str:
    text = str(value)
    return text if _PLAIN.match(text) and text.lower() not in _WORDS else json.dumps(text)


def to_yaml(node: Any, indent: int = 0) -> list[str]:
    """Block-style YAML lines for nested dicts, lists and strings, lists indented the kubectl way."""
    pad = "  " * indent
    lines: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            if isinstance(value, (dict, list)):
                lines += [f"{pad}{key}:", *to_yaml(value, indent + 1)]
            else:
                lines.append(f"{pad}{key}: {_scalar(value)}")
        return lines
    for item in node:
        if isinstance(item, (dict, list)):
            first, *rest = to_yaml(item, indent + 1)
            lines += [f"{pad}- {first.lstrip()}", *rest]
        else:
            lines.append(f"{pad}- {_scalar(item)}")
    return lines


def k8s_name(name: str) -> str:
    """A secret's name as a Kubernetes object name: app/config becomes app-config."""
    return re.sub(r"[^a-z0-9-]+", "-", name.lower()).strip("-")[:253] or "secret"


def env_key(name: str) -> str:
    """A secret's name as an environment-style key: db-password becomes DB_PASSWORD."""
    return re.sub(r"[^A-Za-z0-9]+", "_", name).strip("_").upper() or "VALUE"


def external_secret(name: str, secret_store: str, source: dict[str, Any]) -> dict[str, str]:
    """externalsecret.yaml and the kustomization.yaml that includes it. `secret_store` is
    "<name>" (a ClusterSecretStore) or "<kind>/<name>"; `source` is the spec's data or dataFrom."""
    kind, _, store = secret_store.rpartition("/")
    manifest = {
        "apiVersion": "external-secrets.io/v1",
        "kind": "ExternalSecret",
        "metadata": {"name": k8s_name(name)},
        "spec": {
            "refreshInterval": "1h",
            "secretStoreRef": {"kind": kind or "ClusterSecretStore", "name": store},
            "target": {"name": k8s_name(name)},
            **source,
        },
    }
    kustomization = {"apiVersion": "kustomize.config.k8s.io/v1beta1", "kind": "Kustomization", "resources": ["externalsecret.yaml"]}
    return {name: "\n".join(to_yaml(body)) + "\n" for name, body in (("externalsecret.yaml", manifest), ("kustomization.yaml", kustomization))}
