"""Tests for the SSRF-defense helper.

Confirms ``is_public_host`` / ``is_public_url`` reject every form of
non-public address an attacker might smuggle through a bundle
manifest: literal RFC1918 IPs, loopback, link-local (including the
AWS metadata endpoint 169.254.169.254), IPv6 loopback, IPv4-mapped
IPv6, decimal-encoded IPv4, and hostnames that DNS-resolve to private
space. Also verifies the safe redirect handler refuses to follow a
``Location`` pointing into private space.
"""

from __future__ import annotations

import socket
import urllib.request

import pytest

from leak_inspector.safe_net import (
    build_safe_opener,
    is_public_host,
    is_public_url,
)


# --- literal IP rejection --------------------------------------------------


@pytest.mark.parametrize(
    "host",
    [
        "127.0.0.1",            # IPv4 loopback
        "127.255.255.1",        # IPv4 loopback (full /8)
        "10.0.0.5",             # RFC1918
        "172.16.0.1",           # RFC1918
        "192.168.1.1",          # RFC1918
        "169.254.169.254",      # AWS / GCE metadata (link-local)
        "100.64.0.1",           # CGNAT
        "0.0.0.0",              # unspecified
        "224.0.0.1",            # multicast
        "240.0.0.1",            # reserved
        "::1",                  # IPv6 loopback
        "fe80::1",              # IPv6 link-local
        "fc00::1",              # IPv6 unique local
        "::",                   # IPv6 unspecified
        "::ffff:127.0.0.1",     # IPv4-mapped IPv6 loopback
        "::ffff:10.0.0.5",      # IPv4-mapped RFC1918
    ],
)
def test_literal_private_ip_rejected(host: str) -> None:
    assert is_public_host(host) is False


def test_literal_public_ipv4_accepted() -> None:
    assert is_public_host("8.8.8.8") is True


def test_literal_public_ipv6_accepted() -> None:
    assert is_public_host("2001:4860:4860::8888") is True


def test_empty_host_rejected() -> None:
    assert is_public_host("") is False
    assert is_public_host(None) is False


# --- hostname / DNS-resolved rejection -------------------------------------


def _stub_getaddrinfo(monkeypatch: pytest.MonkeyPatch, addresses):
    """Patch ``socket.getaddrinfo`` to return AF_INET tuples for ``addresses``."""
    def fake(host, port, *args, **kwargs):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", (addr, 0))
            for addr in addresses
        ]
    monkeypatch.setattr(socket, "getaddrinfo", fake)


def test_localhost_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    """``localhost`` resolves to 127.0.0.1; must be refused."""
    _stub_getaddrinfo(monkeypatch, ["127.0.0.1"])
    assert is_public_host("localhost") is False


def test_decimal_encoded_ipv4_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    """``2130706433`` = 127.0.0.1; getaddrinfo resolves it, we must catch it."""
    _stub_getaddrinfo(monkeypatch, ["127.0.0.1"])
    assert is_public_host("2130706433") is False


def test_hostname_resolving_to_rfc1918_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_getaddrinfo(monkeypatch, ["10.0.0.5"])
    assert is_public_host("internal.corp") is False


def test_hostname_resolving_to_metadata_endpoint_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_getaddrinfo(monkeypatch, ["169.254.169.254"])
    assert is_public_host("metadata.example") is False


def test_multihomed_hostname_with_any_private_ip_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If *any* resolved IP is private, the hostname is refused."""
    _stub_getaddrinfo(monkeypatch, ["8.8.8.8", "127.0.0.1"])
    assert is_public_host("rebinding.example") is False


def test_hostname_resolving_only_to_public_accepted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_getaddrinfo(monkeypatch, ["93.184.216.34"])
    assert is_public_host("example.com") is True


def test_hostname_resolution_failure_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom(*_args, **_kwargs):
        raise socket.gaierror("nodename nor servname provided")
    monkeypatch.setattr(socket, "getaddrinfo", boom)
    assert is_public_host("nx.example") is False


# --- is_public_url scheme + host gate --------------------------------------


def test_http_and_https_to_public_ip_accepted() -> None:
    assert is_public_url("http://8.8.8.8/") is True
    assert is_public_url("https://8.8.8.8/") is True


@pytest.mark.parametrize(
    "url",
    [
        "javascript:alert(1)",
        "file:///etc/passwd",
        "ftp://example.com/",
        "gopher://127.0.0.1/",
        "data:text/html,<script>...",
    ],
)
def test_non_http_schemes_rejected(url: str) -> None:
    assert is_public_url(url) is False


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/v1/status",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.5:8500/v1/agent/self",
        "https://[::1]/",
    ],
)
def test_url_with_private_host_rejected(url: str) -> None:
    assert is_public_url(url) is False


def test_empty_url_rejected() -> None:
    assert is_public_url("") is False


def test_url_without_hostname_rejected() -> None:
    """``urlparse`` accepts gibberish; without a hostname the URL is not probeable."""
    assert is_public_url("not-a-url") is False


# --- safe redirect handler -------------------------------------------------


def test_safe_opener_blocks_redirect_to_private_host() -> None:
    """A 302 ``Location`` pointing into private space must NOT be followed.

    Returning ``None`` from ``redirect_request`` instructs urllib to
    stop following and surface the 3xx response — which for our
    callers means "server replied" without us having issued a second
    request to the attacker-controlled internal address.
    """
    handler = build_safe_opener().handlers
    # Locate the redirect handler we installed.
    redirector = next(
        h for h in handler if isinstance(h, urllib.request.HTTPRedirectHandler)
    )
    req = urllib.request.Request("https://example.com/start")
    result = redirector.redirect_request(
        req=req,
        fp=None,
        code=302,
        msg="Found",
        headers={"location": "http://169.254.169.254/latest/meta-data/"},
        newurl="http://169.254.169.254/latest/meta-data/",
    )
    assert result is None


def test_safe_opener_allows_redirect_to_public_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A redirect to a public host is followed (returns a Request, not None)."""
    _stub_getaddrinfo(monkeypatch, ["93.184.216.34"])
    handler = build_safe_opener().handlers
    redirector = next(
        h for h in handler if isinstance(h, urllib.request.HTTPRedirectHandler)
    )
    req = urllib.request.Request("https://example.com/start")
    result = redirector.redirect_request(
        req=req,
        fp=None,
        code=302,
        msg="Found",
        headers={"location": "https://example.com/landing"},
        newurl="https://example.com/landing",
    )
    assert result is not None


# --- resolve-and-pin (DNS-rebinding defense) ---------------------------------
#
# ``is_public_url`` resolves at validation time; without pinning, the
# kernel re-resolves at connect time — an attacker controlling DNS can
# flip the second answer into private space. The pinned connections
# resolve once at connect time, validate, and hand the kernel the
# already-validated IP literal, so there is no second resolution to
# attack.


class _FakeSocket:
    """Minimal socket stand-in for offline connect() tests."""

    def setsockopt(self, *args) -> None:  # TCP_NODELAY in connect()
        pass

    def close(self) -> None:
        pass


def test_resolve_pinned_addresses_returns_validated_ips(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from leak_inspector.safe_net import _resolve_pinned_addresses

    _stub_getaddrinfo(monkeypatch, ["93.184.216.34", "93.184.216.35"])
    assert _resolve_pinned_addresses("example.com") == [
        "93.184.216.34", "93.184.216.35",
    ]


def test_resolve_pinned_addresses_refuses_private_answer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The rebinding case: the connect-time answer is private → refuse."""
    from leak_inspector.safe_net import _resolve_pinned_addresses

    _stub_getaddrinfo(monkeypatch, ["10.0.0.5"])
    with pytest.raises(OSError):
        _resolve_pinned_addresses("rebinding.example")


def test_resolve_pinned_addresses_refuses_mixed_answers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Any private address in the answer poisons the whole set."""
    from leak_inspector.safe_net import _resolve_pinned_addresses

    _stub_getaddrinfo(monkeypatch, ["93.184.216.34", "127.0.0.1"])
    with pytest.raises(OSError):
        _resolve_pinned_addresses("rebinding.example")


def test_resolve_pinned_addresses_passes_public_literal_through() -> None:
    from leak_inspector.safe_net import _resolve_pinned_addresses

    assert _resolve_pinned_addresses("8.8.8.8") == ["8.8.8.8"]


def test_resolve_pinned_addresses_refuses_private_literal() -> None:
    from leak_inspector.safe_net import _resolve_pinned_addresses

    with pytest.raises(OSError):
        _resolve_pinned_addresses("169.254.169.254")


def test_pinned_connection_connects_to_validated_ip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The kernel must receive the validated IP literal, never the
    hostname — that is the pin."""
    from leak_inspector.safe_net import _PinnedHTTPConnection

    _stub_getaddrinfo(monkeypatch, ["93.184.216.34"])
    connected = []

    def fake_create_connection(address, *args, **kwargs):
        connected.append(address)
        return _FakeSocket()

    monkeypatch.setattr(socket, "create_connection", fake_create_connection)
    conn = _PinnedHTTPConnection("example.com", 80, timeout=5)
    conn.connect()
    assert connected == [("93.184.216.34", 80)]


def test_pinned_connection_refuses_connect_time_rebind(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Validation saw a public answer; the connect-time answer flips to
    private — the connection must be refused, and the kernel must never
    be handed the hostname."""
    from leak_inspector.safe_net import _PinnedHTTPConnection

    answers = iter([["93.184.216.34"], ["10.0.0.5"]])

    def flipping(host, port, *args, **kwargs):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", (addr, 0))
            for addr in next(answers)
        ]

    monkeypatch.setattr(socket, "getaddrinfo", flipping)
    assert is_public_host("rebinding.example") is True  # validation passes
    monkeypatch.setattr(
        socket, "create_connection",
        lambda *a, **k: pytest.fail("kernel reached despite private rebind"),
    )
    conn = _PinnedHTTPConnection("rebinding.example", 80, timeout=5)
    with pytest.raises(OSError):
        conn.connect()


def test_pinned_connection_falls_back_across_validated_ips(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Pinning must not lose multi-address fallback: if the first
    validated IP refuses the TCP connection, the next one is tried."""
    from leak_inspector.safe_net import _PinnedHTTPConnection

    _stub_getaddrinfo(monkeypatch, ["93.184.216.34", "93.184.216.35"])
    attempts = []

    def fake_create_connection(address, *args, **kwargs):
        attempts.append(address)
        if address[0] == "93.184.216.34":
            raise ConnectionRefusedError("first address down")
        return _FakeSocket()

    monkeypatch.setattr(socket, "create_connection", fake_create_connection)
    conn = _PinnedHTTPConnection("example.com", 80, timeout=5)
    conn.connect()
    assert attempts == [("93.184.216.34", 80), ("93.184.216.35", 80)]


def test_pinned_https_preserves_sni_hostname(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """TLS must be negotiated against the original hostname (SNI +
    certificate verification), while the TCP socket goes to the pin."""
    import ssl

    from leak_inspector.safe_net import _PinnedHTTPSConnection

    class _CapturingContext(ssl.SSLContext):
        captured: list = []

        def wrap_socket(self, sock, server_hostname=None, **kwargs):
            type(self).captured.append(server_hostname)
            return sock

    _stub_getaddrinfo(monkeypatch, ["93.184.216.34"])
    connected = []

    def fake_create_connection(address, *args, **kwargs):
        connected.append(address)
        return _FakeSocket()

    monkeypatch.setattr(socket, "create_connection", fake_create_connection)
    ctx = _CapturingContext(ssl.PROTOCOL_TLS_CLIENT)
    conn = _PinnedHTTPSConnection("example.com", 443, context=ctx)
    conn.connect()
    assert connected == [("93.184.216.34", 443)]
    assert _CapturingContext.captured == ["example.com"]


def test_safe_opener_uses_pinned_connections() -> None:
    """The opener's HTTP/HTTPS handlers must be the pinning ones, so
    every probe gets the rebinding defense without code changes."""
    from leak_inspector.safe_net import _PinnedHTTPHandler, _PinnedHTTPSHandler

    handlers = build_safe_opener().handlers
    assert any(isinstance(h, _PinnedHTTPHandler) for h in handlers)
    assert any(isinstance(h, _PinnedHTTPSHandler) for h in handlers)
    # build_opener must not also keep the stock (unpinned) handlers.
    assert not any(type(h) is urllib.request.HTTPHandler for h in handlers)
    assert not any(type(h) is urllib.request.HTTPSHandler for h in handlers)