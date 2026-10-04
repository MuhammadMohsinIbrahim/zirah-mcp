"""Shared test setup.

Tests marked ``repo_checkout`` read files from the repository root (``examples/``,
``LICENSE``, ``CHANGELOG.md``), which the sdist does not ship. They are skipped only when the
tests are not inside the Zirah repository; inside it they always run, and a missing file is
a failure, not a skip.

Terminal output is rendered at a pinned width (``COLUMNS``), so where lines wrap is the same
on every OS, checkout path and developer shell. Checks on rendered text use :func:`flat`
(phrases that may span a line break) and :func:`squashed` (secrets that must not appear,
even folded across lines).

No test may reach a real LLM provider or any other remote host. Every test starts with the
provider key variables and LLM selection variables removed from the environment, and fails if
it resolves or connects to anything but localhost. Tests that exercise the OpenAI and
Anthropic clients do so against mocked transports with fake keys built at run time.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from zirah.llm import ENV_VAR as LLM_ENV_VAR
from zirah.llm import anthropic, openai

REPO_ROOT = Path(__file__).resolve().parents[2]
TEST_COLUMNS = "100"
"""Console width for CLI output in tests; the same as ``terminal.REPORT_WIDTH``."""

CLEARED_ENV = (openai.KEY_ENV, anthropic.KEY_ENV, LLM_ENV_VAR, "OLLAMA_HOST")
"""Removed before every test: real provider keys, and variables that pick or point an LLM."""


@pytest.fixture(autouse=True)
def pinned_console_width(monkeypatch: pytest.MonkeyPatch) -> None:
    """Rich reads ``COLUMNS`` when output is not a terminal (as under ``CliRunner``)."""
    monkeypatch.setenv("COLUMNS", TEST_COLUMNS)


@pytest.fixture(autouse=True)
def no_real_llm_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    """No test can read a real API key or be pointed at a real provider by the environment."""
    for name in CLEARED_ENV:
        monkeypatch.delenv(name, raising=False)


def is_local(host: Any) -> bool:
    """Whether ``host`` (a name or an address, str or bytes) is this machine."""
    if isinstance(host, bytes):
        host = host.decode("ascii", "replace")
    if not isinstance(host, str):
        return False
    name = host.strip("[]").lower()
    if name == "localhost" or name.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(name.split("%")[0]).is_loopback
    except ValueError:
        return False


@pytest.fixture(autouse=True)
def no_real_network(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[str]]:
    """Fail the test if it resolves or connects to anything but localhost.

    Name lookups and socket connects are checked in this process; Unix sockets are allowed.
    A blocked attempt raises at once and is also reported when the test ends, so an attempt
    made in a background thread cannot be swallowed. Yields the list of blocked hosts.
    """
    blocked: list[str] = []
    real_getaddrinfo = socket.getaddrinfo
    real_connect = socket.socket.connect
    real_connect_ex = socket.socket.connect_ex

    def check(host: Any) -> None:
        if not is_local(host):
            blocked.append(str(host))
            pytest.fail(f"test tried to reach a non-local host: {host!r}", pytrace=False)

    def getaddrinfo(host: Any, *args: Any, **kwargs: Any) -> Any:
        if host is not None:
            check(host)
        return real_getaddrinfo(host, *args, **kwargs)

    def connect(self: socket.socket, address: Any) -> None:
        if isinstance(address, tuple):
            check(address[0])
        real_connect(self, address)

    def connect_ex(self: socket.socket, address: Any) -> int:
        if isinstance(address, tuple):
            check(address[0])
        return real_connect_ex(self, address)

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    monkeypatch.setattr(socket.socket, "connect", connect)
    monkeypatch.setattr(socket.socket, "connect_ex", connect_ex)
    yield blocked
    if blocked:
        pytest.fail(f"test tried to reach non-local hosts: {blocked}", pytrace=False)


def flat(text: str) -> str:
    """``text`` with every run of whitespace collapsed to one space.

    For positive checks of phrases that may wrap: ``"Trust score 100/100" in flat(out)``.
    """
    return " ".join(text.split())


def squashed(text: str) -> str:
    """``text`` with all whitespace removed.

    For negative secret checks: ``squashed(secret) not in squashed(out)`` also catches a
    secret that was folded across a line break.
    """
    return "".join(text.split())


SKIP_REASON = (
    "needs the Zirah repository checkout (examples/, LICENSE, CHANGELOG.md), which an "
    "unpacked sdist does not include"
)


def in_repo_checkout() -> bool:
    """Whether these tests sit in the Zirah repository rather than an unpacked sdist."""
    workspace = REPO_ROOT / "pyproject.toml"
    return workspace.is_file() and 'name = "zirah-workspace"' in workspace.read_text(
        encoding="utf-8"
    )


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", f"repo_checkout: {SKIP_REASON}; skipped outside it")


def pytest_runtest_setup(item: pytest.Item) -> None:
    if item.get_closest_marker("repo_checkout") is not None and not in_repo_checkout():
        pytest.skip(SKIP_REASON)
