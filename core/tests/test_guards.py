"""The test-wide guards in conftest.py: no real provider keys and no non-local network."""

from __future__ import annotations

import os
import socket

import httpx
import pytest
from conftest import CLEARED_ENV, is_local


def test_provider_keys_and_llm_selection_are_cleared() -> None:
    for name in CLEARED_ENV:
        assert name not in os.environ, name
    assert {"OPENAI_API_KEY", "ANTHROPIC_API_KEY", "ZIRAH_LLM", "OLLAMA_HOST"} <= set(CLEARED_ENV)


@pytest.mark.parametrize(
    ("host", "local"),
    [
        ("localhost", True),
        ("app.localhost", True),
        ("127.0.0.1", True),
        ("127.5.5.5", True),
        ("::1", True),
        ("[::1]", True),
        (b"127.0.0.1", True),
        ("api.openai.com", False),
        ("api.anthropic.com", False),
        ("example.invalid", False),
        ("192.0.2.1", False),
        ("10.0.0.1", False),
        (None, False),
    ],
)
def test_is_local(host: object, local: bool) -> None:
    assert is_local(host) is local


def test_non_local_lookups_and_connects_fail_the_test(no_real_network: list[str]) -> None:
    with pytest.raises(pytest.fail.Exception):
        socket.getaddrinfo("example.invalid", 443)
    with pytest.raises(pytest.fail.Exception):
        socket.create_connection(("192.0.2.1", 80), timeout=1)
    sock = socket.socket()
    try:
        with pytest.raises(pytest.fail.Exception):
            sock.connect(("192.0.2.1", 80))
        with pytest.raises(pytest.fail.Exception):
            sock.connect_ex(("192.0.2.1", 80))
    finally:
        sock.close()
    assert no_real_network == ["example.invalid", "192.0.2.1", "192.0.2.1", "192.0.2.1"]
    no_real_network.clear()  # the attempts above were the point of this test


def test_an_accidental_cloud_request_fails_before_leaving(no_real_network: list[str]) -> None:
    with httpx.Client() as client, pytest.raises(pytest.fail.Exception):
        client.post("https://api.openai.com/v1/chat/completions", json={})
    assert no_real_network == ["api.openai.com"]
    no_real_network.clear()


def test_localhost_is_allowed() -> None:
    with socket.create_server(("127.0.0.1", 0)) as server:
        port = server.getsockname()[1]
        with socket.create_connection(("127.0.0.1", port), timeout=5):
            pass
        with socket.create_connection(("localhost", port), timeout=5):
            pass
