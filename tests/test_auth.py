from urllib.parse import parse_qs, urlsplit

from conftest import ASSERTION, AUTHORITY, CLIENT, ORIGIN, TENANT, cookie_attributes, make_client, sign_in, write_headers


def test_login_redirects_to_entra_with_pkce_state_and_nonce(client):
    response = client.get("/auth/login")
    assert response.status_code == 302
    url = urlsplit(response.headers["location"])
    assert f"{url.scheme}://{url.netloc}{url.path}" == f"{AUTHORITY}/{TENANT}/oauth2/v2.0/authorize"
    query = {k: v[0] for k, v in parse_qs(url.query).items()}
    assert query["client_id"] == CLIENT
    assert query["response_type"] == "code"
    assert query["redirect_uri"] == f"{ORIGIN}/auth/callback"
    assert query["code_challenge_method"] == "S256"
    assert len(query["code_challenge"]) == 43
    assert len(query["state"]) >= 32 and len(query["nonce"]) >= 32
    assert query["scope"].split() == ["openid", "profile", "offline_access", "https://vault.azure.net/user_impersonation"]
    flow = cookie_attributes(response, "__Host-secrets-ui-login").lower()
    for attribute in ("secure", "httponly", "samesite=lax", "path=/", "max-age=600"):
        assert attribute in flow


def test_sign_in_keeps_only_the_vaults_the_pattern_allows(client, world):
    me = sign_in(client, world)
    # privileged-kv-prd is assigned as a role but outside the pattern; Not_A_Vault and admin are not vault names.
    assert [(s["provider"], s["name"]) for s in me["stores"]] == [("azure-keyvault", "team-a-kv-dev"), ("azure-keyvault", "team-b-kv-dev")]
    assert me["stores"][0]["location"] == "https://team-a-kv-dev.vault.azure.net"
    assert me["stores"][0]["label"] == "team-a-kv-dev"
    (provider,) = me["providers"]
    assert provider["id"] == "azure-keyvault" and set(provider["features"]) == {"audit", "content_type", "enable", "expiry", "recover", "versions"}
    assert me["name"] == "Ada Lovelace"
    assert len(me["csrf"]) >= 32


def test_listed_stores_come_first_in_their_order_under_their_label(world, env):
    listed = '[{"name": "team-b-kv-dev", "label": "Team B dev"}, {"name": "privileged-kv-prd", "label": "Privileged"}]'
    me = sign_in(make_client(world, {**env, "SECRETS_UI_AZURE_KEYVAULT_STORES": listed}), world)
    # Listing privileged-kv-prd shows nothing: the roles and the pattern still decide.
    assert [(s["name"], s["label"]) for s in me["stores"]] == [("team-b-kv-dev", "Team B dev"), ("team-a-kv-dev", "team-a-kv-dev")]


def test_the_code_is_redeemed_with_the_workload_identity_token_and_the_pkce_verifier(client, world):
    sign_in(client, world)
    form = world.entra.token_requests[0]
    assert form["client_id"] == [CLIENT]
    assert form["client_assertion"] == [ASSERTION]
    assert form["client_assertion_type"] == ["urn:ietf:params:oauth:client-assertion-type:jwt-bearer"]
    assert "client_secret" not in form
    assert len(form["code_verifier"][0]) >= 43


def test_a_client_secret_is_used_when_there_is_no_token_file(world, env):
    env = {k: v for k, v in env.items() if k != "AZURE_FEDERATED_TOKEN_FILE"} | {"AZURE_CLIENT_SECRET": "app-secret"}
    sign_in(make_client(world, env), world)
    form = world.entra.token_requests[0]
    assert form["client_secret"] == ["app-secret"]
    assert "client_assertion" not in form


def test_session_cookies_after_sign_in(client, world):
    login = client.get("/auth/login")
    query = parse_qs(urlsplit(login.headers["location"]).query)
    world.entra.challenge, world.entra.nonce = query["code_challenge"][0], query["nonce"][0]
    callback = client.get("/auth/callback", params={"code": "good-code", "state": query["state"][0]})
    session = cookie_attributes(callback, "__Host-secrets-ui.0").lower()
    for attribute in ("secure", "httponly", "samesite=strict", "path=/"):
        assert attribute in session
    # The refresh token is sealed: it never appears in the cookie in the clear.
    assert "rt-1" not in callback.headers.get("set-cookie", "")
    assert "max-age=0" in cookie_attributes(callback, "__Host-secrets-ui-login").lower()


def test_a_state_mismatch_signs_nobody_in(client, world):
    client.get("/auth/login")
    callback = client.get("/auth/callback", params={"code": "good-code", "state": "forged"})
    assert callback.status_code == 303
    assert "auth_error=" in callback.headers["location"]
    assert "__Host-secrets-ui.0" not in callback.headers.get("set-cookie", "")
    assert world.entra.token_requests == []
    assert client.get("/api/me").status_code == 401


def test_a_callback_without_a_login_cookie_is_refused(world, env):
    fresh = make_client(world, env)
    callback = fresh.get("/auth/callback", params={"code": "good-code", "state": "anything"})
    assert "auth_error=" in callback.headers["location"]
    assert world.entra.token_requests == []


def test_a_refused_assignment_is_shown_not_swallowed(client):
    callback = client.get(
        "/auth/callback",
        params={"error": "access_denied", "error_description": "AADSTS50105: The signed in user is not assigned to a role\r\nTrace ID: x"},
    )
    location = callback.headers["location"]
    assert "AADSTS50105" in parse_qs(urlsplit(location).query)["auth_error"][0]
    assert "Trace" not in location


def test_an_id_token_for_another_sign_in_is_refused(client, world):
    login = client.get("/auth/login")
    query = parse_qs(urlsplit(login.headers["location"]).query)
    world.entra.challenge = query["code_challenge"][0]
    world.entra.nonce = "someone-elses-nonce"
    callback = client.get("/auth/callback", params={"code": "good-code", "state": query["state"][0]})
    assert "another" in parse_qs(urlsplit(callback.headers["location"]).query)["auth_error"][0]
    assert client.get("/api/me").status_code == 401


def test_an_id_token_from_another_tenant_is_refused(client, world):
    world.entra.tid = "00000000-0000-0000-0000-000000000000"
    login = client.get("/auth/login")
    query = parse_qs(urlsplit(login.headers["location"]).query)
    world.entra.challenge, world.entra.nonce = query["code_challenge"][0], query["nonce"][0]
    callback = client.get("/auth/callback", params={"code": "good-code", "state": query["state"][0]})
    assert "tenant" in parse_qs(urlsplit(callback.headers["location"]).query)["auth_error"][0]


def test_logout_needs_the_csrf_token_and_then_clears_the_session(client, world):
    me = sign_in(client, world)
    assert client.post("/auth/logout").status_code == 403
    response = client.post("/auth/logout", headers=write_headers(me))
    assert response.status_code == 200
    assert "max-age=0" in cookie_attributes(response, "__Host-secrets-ui.0").lower()
    assert client.get("/api/me").status_code == 401


def test_security_headers(client):
    response = client.get("/healthz")
    csp = response.headers["content-security-policy"]
    assert "default-src 'none'" in csp and "script-src 'self'" in csp and "frame-ancestors 'none'" in csp
    assert "unsafe-inline" not in csp and "unsafe-eval" not in csp
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["strict-transport-security"].startswith("max-age=")
