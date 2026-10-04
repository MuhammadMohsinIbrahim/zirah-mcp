"""The LLM client interface shared by every provider.

A client sends one system prompt and one user message and gets back JSON text that follows a
given schema. Temperature is always 0. Requests have a timeout and a response size limit, and
errors never include request headers or response bodies, so API keys cannot leak into logs or
reports.

Every request goes through :meth:`LlmClient._post`, which providers cannot override. It
replaces secret values in the request body with ``[REDACTED:<type>]`` before anything is sent,
and if that fails, nothing is sent (see :mod:`zirah.llm.redact`).
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import Any, ClassVar, Final, final

import httpx

from zirah.llm.redact import redact_payload
from zirah.models import LlmInfo, LlmProvider

TEMPERATURE: Final = 0.0
"""Every provider is called with temperature 0 so results are as repeatable as it allows."""

DEFAULT_TIMEOUT_S: Final = 60.0
"""Seconds allowed for one LLM request, connection included."""

MAX_RESPONSE_BYTES: Final = 1024 * 1024
"""Larger responses are refused: the judge only needs a small JSON verdict."""

MAX_OUTPUT_TOKENS: Final = 2048
"""Upper bound on tokens the model may generate per request."""


class LlmError(Exception):
    """An LLM call failed. The message is for the user and never contains secrets."""


class LlmRateLimitError(LlmError):
    """The provider refused the request because of rate or quota limits (HTTP 429)."""


class LlmClient(ABC):
    """One configured model at one provider."""

    provider: ClassVar[LlmProvider]

    def __init__(
        self,
        model: str,
        *,
        timeout: float = DEFAULT_TIMEOUT_S,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        if not model:
            raise LlmError(f"{self.provider}: a model name is required")
        self.model = model
        self._timeout = timeout
        self._transport = transport

    @property
    def temperature(self) -> float | None:
        """The temperature sent with each request, or ``None`` when the model takes none."""
        return TEMPERATURE

    @property
    def info(self) -> LlmInfo:
        return LlmInfo(provider=self.provider, model=self.model, temperature=self.temperature)

    @abstractmethod
    def complete_json(self, system: str, user: str, schema: dict[str, Any]) -> str:
        """Send ``system`` and ``user`` and return the model's reply: JSON text meant to match
        ``schema``. Callers must still validate it."""

    @final
    def _post(self, url: str, payload: dict[str, Any], headers: dict[str, str]) -> Any:
        """POST ``payload`` as JSON and return the decoded JSON response.

        The one way a provider sends anything. Secret values in ``payload`` are redacted first;
        if redaction fails for any reason, nothing is sent (fail closed). ``headers`` carry the
        provider's own API key and are sent as given.
        """
        try:
            body = redact_payload(payload)
        except Exception:  # fail closed: an unredacted body must never be sent
            raise LlmError(
                f"{self.provider}: could not redact secrets from the request; nothing was sent"
            ) from None
        try:
            with httpx.Client(timeout=self._timeout, transport=self._transport) as client:
                response = client.post(url, json=body, headers=headers)
        except httpx.TimeoutException:
            raise LlmError(f"{self.provider}: no response within {self._timeout:g} s") from None
        except httpx.HTTPError as exc:
            reason = type(exc).__name__
            raise LlmError(f"{self.provider}: cannot reach {_origin(url)} ({reason})") from None

        if response.status_code == 429:
            raise LlmRateLimitError(f"{self.provider}: rate limited (HTTP 429); try again later")
        if response.status_code >= 400:
            raise LlmError(f"{self.provider}: request failed with HTTP {response.status_code}")
        if len(response.content) > MAX_RESPONSE_BYTES:
            raise LlmError(f"{self.provider}: response larger than {MAX_RESPONSE_BYTES} bytes")
        try:
            return json.loads(response.content)
        except ValueError:
            raise LlmError(f"{self.provider}: response is not valid JSON") from None


def _origin(url: str) -> str:
    parsed = httpx.URL(url)
    return f"{parsed.scheme}://{parsed.host}" + (f":{parsed.port}" if parsed.port else "")


def dig(data: Any, *path: str | int) -> Any:
    """``data[path[0]][path[1]]...``, or ``None`` when any step is missing or the wrong type."""
    for key in path:
        if isinstance(key, int):
            if not isinstance(data, list) or not -len(data) <= key < len(data):
                return None
        elif not isinstance(data, dict) or key not in data:
            return None
        data = data[key]
    return data
