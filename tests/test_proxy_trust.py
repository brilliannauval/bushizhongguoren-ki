from __future__ import annotations

from pathlib import Path

from starlette.requests import Request

from securebox.api.dependencies import _network


PROJECT_ROOT = Path(__file__).parents[1]


def test_rate_limit_network_subject_ignores_untrusted_forwarded_header_values():
    def request(forwarded_for: str) -> Request:
        return Request({
            "type": "http",
            "method": "GET",
            "path": "/api/v1/auth/login",
            "headers": [(b"x-forwarded-for", forwarded_for.encode("ascii"))],
            "client": ("198.51.100.24", 54000),
            "server": ("testserver", 80),
        })

    assert _network(request("203.0.113.10")) == _network(request("192.0.2.99, 203.0.113.10"))
    assert _network(request("203.0.113.10")) == "network:198.51.100.24"


def test_local_proxy_overwrites_forwarded_chain_and_render_has_no_wildcard_trust():
    compose = (PROJECT_ROOT / "compose.yaml").read_text()
    nginx = (PROJECT_ROOT / "nginx" / "nginx.conf").read_text()
    render = (PROJECT_ROOT / "render.yaml").read_text()

    assert "FORWARDED_ALLOW_IPS: ${SECUREBOX_GATEWAY_IP:-172.29.240.2}" in compose
    assert "proxy_set_header X-Forwarded-For $remote_addr;" in nginx
    assert "$proxy_add_x_forwarded_for" not in nginx
    assert "FORWARDED_ALLOW_IPS" not in render
    assert 'value: "*"' not in render
