import time

from starlette.requests import Request
from starlette.responses import Response

from secrets_ui.session import Cookies, Sealer, TokenCache


def request_with(cookies: dict[str, str]) -> Request:
    header = "; ".join(f"{k}={v}" for k, v in cookies.items())
    return Request({"type": "http", "headers": [(b"cookie", header.encode())] if header else []})


def set_cookies(response: Response) -> dict[str, str]:
    jar = {}
    for raw in response.headers.getlist("set-cookie"):
        name, _, rest = raw.partition("=")
        jar[name] = rest.split(";", 1)[0]
    return jar


def test_seal_round_trip_and_purpose_binding():
    sealer = Sealer(b"x" * 40)
    token = sealer.seal("session", {"a": 1}, 60)
    assert sealer.open("session", token)["a"] == 1
    assert sealer.open("login", token) is None


def test_tampered_forged_and_expired_tokens_are_refused():
    sealer = Sealer(b"x" * 40)
    token = sealer.seal("session", {"a": 1}, 60)
    flipped = token[:-2] + ("A" if token[-2] != "A" else "B") + token[-1]
    assert sealer.open("session", flipped) is None
    assert Sealer(b"y" * 40).open("session", token) is None
    assert sealer.open("session", "not-base64!") is None
    assert sealer.open("session", sealer.seal("session", {"a": 1}, -1)) is None


def test_a_large_session_is_split_over_cookies_and_read_back():
    cookies = Cookies(Sealer(b"x" * 40), secure=True)
    response = Response()
    data = {"rt": "r" * 9000, "sid": "s"}
    cookies.write_session(request_with({}), response, data, 60)
    jar = set_cookies(response)
    assert sorted(jar) == [f"__Host-secrets-ui.{i}" for i in range(len(jar))] and len(jar) > 2
    assert all(len(v) <= 3800 for v in jar.values())
    assert cookies.read_session(request_with(jar))["rt"] == "r" * 9000


def test_a_smaller_session_clears_the_chunks_it_no_longer_needs():
    cookies = Cookies(Sealer(b"x" * 40), secure=True)
    old = {"__Host-secrets-ui.0": "a", "__Host-secrets-ui.1": "b", "__Host-secrets-ui.2": "c"}
    response = Response()
    cookies.write_session(request_with(old), response, {"sid": "s"}, 60)
    headers = response.headers.getlist("set-cookie")
    assert any(h.startswith("__Host-secrets-ui.1=") and "Max-Age=0" in h for h in headers)
    assert any(h.startswith("__Host-secrets-ui.2=") and "Max-Age=0" in h for h in headers)


def test_session_cookies_are_host_bound_secure_http_only_and_strict():
    cookies = Cookies(Sealer(b"x" * 40), secure=True)
    response = Response()
    cookies.write_session(request_with({}), response, {"sid": "s"}, 60)
    header = response.headers.getlist("set-cookie")[0].lower()
    assert header.startswith("__host-secrets-ui.0=")
    for attribute in ("secure", "httponly", "samesite=strict", "path=/"):
        assert attribute in header
    assert "domain=" not in header


def test_token_cache_expires_early_and_evicts_oldest():
    cache = TokenCache(size=2, margin=120)
    cache.put("a", "token-a", time.time() + 3600)
    cache.put("b", "token-b", time.time() + 60)  # inside the margin: treated as expired
    assert cache.get("a") == "token-a"
    assert cache.get("b") is None
    cache.put("c", "token-c", time.time() + 3600)
    cache.put("d", "token-d", time.time() + 3600)
    assert cache.get("a") is None
    assert cache.get("d") == "token-d"
