"""`python -m secrets_ui`: load the config, build the app, serve it with uvicorn.

TLS ends at the ingress in front of it; this listens on plain http inside the pod.
"""

import json
import logging
import sys

import uvicorn

from .app import create_app
from .config import ConfigError, load_config


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s", stream=sys.stdout)
    # httpx logs every request at INFO, and its URLs name stores and secrets.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    try:
        cfg = load_config()
    except ConfigError as err:
        print(json.dumps({"msg": "configuration refused", "reason": str(err)}), file=sys.stderr)
        sys.exit(1)
    logging.getLogger("secrets_ui").info(
        json.dumps(
            {
                "msg": "starting",
                "version": cfg.version,
                "origin": cfg.origin,
                "sign_in": cfg.sign_in,
                "tenant": cfg.tenant_id or None,
                "client": cfg.client_id,
                "google_domains": list(cfg.google_domains) or None,
                "credential": "workload identity" if cfg.federated_token_file else "client secret",
                "providers": list(cfg.providers),
                "azure_keyvault_roles": cfg.azure_keyvault.roles.pattern if cfg.azure_keyvault else None,
                "hashicorp_vault": cfg.hashicorp_vault.address if cfg.hashicorp_vault else None,
                "hashicorp_vault_stores": len(cfg.hashicorp_vault.stores) if cfg.hashicorp_vault else None,
                "oci_vault": cfg.oci_vault.region if cfg.oci_vault else None,
                "oci_vault_stores": len(cfg.oci_vault.stores) if cfg.oci_vault else None,
            }
        )
    )
    uvicorn.run(
        create_app(cfg),
        # All interfaces: a container port, reached only through the ingress in front of it.
        host="0.0.0.0",  # noqa: S104 # nosec B104
        port=cfg.port,
        # Longer than common ingress idle timeouts, so this side never closes a keep-alive
        # connection the proxy is about to reuse (a 502).
        timeout_keep_alive=95,
        access_log=False,
        server_header=False,
        log_level="info",
    )


if __name__ == "__main__":
    main()
