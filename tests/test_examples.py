from secrets_ui.examples import env_key, external_secret, k8s_name


def test_a_key_vault_secret_becomes_an_external_secret_and_a_kustomization():
    files = external_secret("db-password", "team-a-keyvault-dev", {"data": [{"secretKey": "DB_PASSWORD", "remoteRef": {"key": "db-password"}}]})
    assert files["externalsecret.yaml"] == (
        "apiVersion: external-secrets.io/v1\n"
        "kind: ExternalSecret\n"
        "metadata:\n"
        "  name: db-password\n"
        "spec:\n"
        '  refreshInterval: "1h"\n'
        "  secretStoreRef:\n"
        "    kind: ClusterSecretStore\n"
        "    name: team-a-keyvault-dev\n"
        "  target:\n"
        "    name: db-password\n"
        "  data:\n"
        "    - secretKey: DB_PASSWORD\n"
        "      remoteRef:\n"
        "        key: db-password\n"
    )
    assert files["kustomization.yaml"] == "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n  - externalsecret.yaml\n"


def test_a_namespaced_store_and_values_yaml_would_misread_are_quoted():
    files = external_secret("yes", "SecretStore/vault", {"dataFrom": [{"extract": {"key": "on"}}]})
    assert "    kind: SecretStore\n    name: vault\n" in files["externalsecret.yaml"]
    assert '        key: "on"\n' in files["externalsecret.yaml"]
    assert '  name: "yes"\n' in files["externalsecret.yaml"]


def test_names_and_keys():
    assert k8s_name("app/config_Main") == "app-config-main" and k8s_name("__") == "secret"
    assert env_key("db-password") == "DB_PASSWORD" and env_key("app/config.v2") == "APP_CONFIG_V2"
