import json

import pytest

from secrets_ui.config import ConfigError, load_config


def test_a_complete_config_loads(env):
    cfg = load_config(env)
    assert cfg.origin == "https://kv.example.test"
    assert cfg.redirect_uri == "https://kv.example.test/auth/callback"
    assert cfg.azure_keyvault is not None and cfg.azure_keyvault.suffix == "vault.azure.net"
    assert cfg.providers == ("azure-keyvault",)
    assert cfg.session_seconds == 8 * 3600
    assert cfg.secure_cookies


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"AZURE_TENANT_ID": "contoso.onmicrosoft.com"}, "AZURE_TENANT_ID"),
        ({"AZURE_CLIENT_ID": ""}, "AZURE_CLIENT_ID"),
        ({"SECRETS_UI_PUBLIC_ORIGIN": "http://kv.example.test"}, "https"),  # DevSkim: ignore DS137138 - asserts http is refused
        ({"SECRETS_UI_PUBLIC_ORIGIN": "https://kv.example.test/app"}, "no path"),
        ({"SECRETS_UI_SESSION_KEY": "short"}, "32"),
        ({"SECRETS_UI_AZURE_KEYVAULT_ROLES": "("}, "regular expression"),
        ({"SECRETS_UI_AZURE_KEYVAULT_SUFFIX": "not a host"}, "DNS suffix"),
        ({"SECRETS_UI_SESSION_HOURS": "48"}, "between 1 and 24"),
        ({"AZURE_AUTHORITY_HOST": "http://login.example.test"}, "https host"),  # DevSkim: ignore DS137138 - asserts http is refused
        ({"SECRETS_UI_BRAND_ACCENT": "red"}, "#rrggbb"),
        ({"SECRETS_UI_BRAND_ACCENT_TEXT_DARK": "#fff;}body{display:none"}, "#rrggbb"),
    ],
)
def test_unsafe_or_broken_values_fail_startup(env, change, message):
    with pytest.raises(ConfigError, match=message):
        load_config({**env, **change})


def test_store_labels_keep_the_listed_order(env):
    cfg = load_config({**env, "SECRETS_UI_AZURE_KEYVAULT_STORES": '[{"name": "b-kv"}, {"name": "a-kv", "label": "A (dev)"}]'})
    assert cfg.azure_keyvault is not None
    assert list(cfg.azure_keyvault.labels.items()) == [("b-kv", "b-kv"), ("a-kv", "A (dev)")]


@pytest.mark.parametrize(
    "stores",
    ["[{", '{"name": "a-kv"}', '[{"label": "A"}]', '[{"name": "a-kv", "secret_store": "Bad Store"}]', '[{"name": "a-kv", "secret_store": "Pod/x"}]', '[{"name": ""}]', '[{"name": "a-kv"}, {"name": "a-kv"}]', '[{"name": "a-kv", "label": 1}]', '[{"name": "a-kv", "label": "a\\nb"}]'],
)
def test_a_broken_store_list_fails_startup(env, stores):
    with pytest.raises(ConfigError, match="SECRETS_UI_AZURE_KEYVAULT_STORES"):
        load_config({**env, "SECRETS_UI_AZURE_KEYVAULT_STORES": stores})


@pytest.mark.parametrize(
    "resource_id",
    [
        "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/other-kv",
        "/subscriptions/x/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/a-kv",
        "https://a-kv.vault.azure.net",
    ],
)
def test_a_resource_id_must_name_the_same_vault(env, resource_id):
    with pytest.raises(ConfigError, match="resource_id of a-kv"):
        load_config({**env, "SECRETS_UI_AZURE_KEYVAULT_STORES": json.dumps([{"name": "a-kv", "resource_id": resource_id}])})


def test_an_unknown_provider_fails_startup(env):
    with pytest.raises(ConfigError, match="SECRETS_UI_PROVIDERS"):
        load_config({**env, "SECRETS_UI_PROVIDERS": "azure-keyvault,gcp-secret-manager"})


def test_a_credential_is_required(env):
    env = {k: v for k, v in env.items() if k != "AZURE_FEDERATED_TOKEN_FILE"}
    with pytest.raises(ConfigError, match="AZURE_CLIENT_SECRET"):
        load_config(env)


def test_the_client_secret_can_come_from_a_file(env, tmp_path):
    secret = tmp_path / "secret"
    secret.write_text("app-secret\n")
    env = {k: v for k, v in env.items() if k != "AZURE_FEDERATED_TOKEN_FILE"} | {"AZURE_CLIENT_SECRET_FILE": str(secret)}
    cfg = load_config(env)
    assert cfg.client_secret == "app-secret" and cfg.federated_token_file is None


def test_the_origin_is_required(env):
    env = {k: v for k, v in env.items() if k != "SECRETS_UI_PUBLIC_ORIGIN"}
    with pytest.raises(ConfigError, match="SECRETS_UI_PUBLIC_ORIGIN"):
        load_config(env)


def test_http_is_allowed_on_loopback_only_and_then_cookies_are_not_secure(env):
    cfg = load_config({**env, "SECRETS_UI_PUBLIC_ORIGIN": "http://localhost:8080"})  # DevSkim: ignore DS162092
    assert cfg.origin == "http://localhost:8080" and not cfg.secure_cookies  # DevSkim: ignore DS162092


def test_the_session_key_can_come_from_a_file(env, tmp_path):
    key = tmp_path / "key"
    key.write_text("f" * 40 + "\n")
    env = {k: v for k, v in env.items() if k != "SECRETS_UI_SESSION_KEY"} | {"SECRETS_UI_SESSION_KEY_FILE": str(key)}
    assert load_config(env).session_key == b"f" * 40
