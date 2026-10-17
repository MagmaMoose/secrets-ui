from pathlib import Path

from conftest import make_client


def test_the_favicon_takes_the_accent_and_is_the_frontends_without_one(world, env, client):
    default = client.get("/favicon.svg")
    assert default.headers["content-type"].startswith("image/svg+xml")
    assert default.text == (Path(__file__).parents[1] / "frontend/public/favicon.svg").read_text().strip()
    branded = make_client(world, {**env, "SECRETS_UI_BRAND_ACCENT": "#1D4ED8", "SECRETS_UI_BRAND_ACCENT_TEXT": "#fafafa"}).get("/favicon.svg").text
    assert 'fill="#1d4ed8"' in branded and branded.count('stroke="#fafafa"') == 2
