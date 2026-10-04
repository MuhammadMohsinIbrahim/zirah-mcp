"""OpenAI and Anthropic clients over mocked HTTP. No test here touches the network."""

from __future__ import annotations

import ast
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest
from conftest import squashed

from zirah.llm import LlmError, LlmRateLimitError, resolve
from zirah.llm.anthropic import (
    API_VERSION,
    FALLBACK_BETA,
    AnthropicClient,
)
from zirah.llm.anthropic import DEFAULT_MODEL as ANTHROPIC_DEFAULT
from zirah.llm.openai import DEFAULT_MODEL as OPENAI_DEFAULT
from zirah.llm.openai import SCHEMA_NAME, OpenAIClient
from zirah.models import LlmInfo, LlmProvider

SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {"ok": {"type": "boolean"}},
    "required": ["ok"],
    "additionalProperties": False,
}
KEY = "zirah" + "_fake_" + "key_" + "4c8e1a93d07b52f6"
"""A fake provider key, assembled at run time; never a real one."""
Handler = Callable[[httpx.Request], httpx.Response]


def openai(handler: Handler, model: str = "gpt-4.1-mini") -> OpenAIClient:
    return OpenAIClient(KEY, model, transport=httpx.MockTransport(handler))


def anthropic(handler: Handler, model: str = "claude-haiku-4-5") -> AnthropicClient:
    return AnthropicClient(KEY, model, transport=httpx.MockTransport(handler))


def openai_reply(content: Any, **message: Any) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "choices": [
                {
                    "message": {"role": "assistant", "content": content, **message},
                    "finish_reason": "stop",
                }
            ]
        },
    )


def anthropic_reply(*blocks: dict[str, Any], stop_reason: str = "end_turn") -> httpx.Response:
    return httpx.Response(
        200, json={"type": "message", "content": list(blocks), "stop_reason": stop_reason}
    )


# --- resolve ---------------------------------------------------------------------------------


def test_resolve_reads_keys_only_from_env() -> None:
    client = resolve("openai", env={"OPENAI_API_KEY": KEY})
    assert isinstance(client, OpenAIClient)
    assert client.info == LlmInfo(
        provider=LlmProvider.OPENAI, model=OPENAI_DEFAULT, temperature=0.0
    )
    client = resolve("anthropic:claude-sonnet-5", env={"ANTHROPIC_API_KEY": KEY})
    assert isinstance(client, AnthropicClient)
    assert client.model == "claude-sonnet-5"
    assert isinstance(resolve("anthropic", env={"ANTHROPIC_API_KEY": KEY}), AnthropicClient)
    assert resolve("anthropic", env={"ANTHROPIC_API_KEY": KEY}).model == ANTHROPIC_DEFAULT  # type: ignore[union-attr]


@pytest.mark.parametrize(
    ("spec", "variable"), [("openai", "OPENAI_API_KEY"), ("anthropic", "ANTHROPIC_API_KEY")]
)
def test_missing_key_is_a_clear_error(spec: str, variable: str) -> None:
    with pytest.raises(LlmError, match=f"set {variable}"):
        resolve(spec, env={})


def test_repr_never_shows_the_key() -> None:
    for client in (openai(lambda _: httpx.Response(200)), anthropic(lambda _: httpx.Response(200))):
        assert KEY not in squashed(repr(client))
        assert KEY not in squashed(str(vars(client).get("model")))


# --- OpenAI ----------------------------------------------------------------------------------


def test_openai_success() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return openai_reply('{"ok": true}')

    assert openai(handler).complete_json("sys", "user", SCHEMA) == '{"ok": true}'
    (request,) = seen
    assert str(request.url) == "https://api.openai.com/v1/chat/completions"
    assert request.headers["authorization"] == f"Bearer {KEY}"
    body = json.loads(request.content)
    assert body["temperature"] == 0.0
    assert body["messages"] == [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "user"},
    ]
    assert body["response_format"] == {
        "type": "json_schema",
        "json_schema": {"name": SCHEMA_NAME, "schema": SCHEMA, "strict": True},
    }


@pytest.mark.parametrize(
    ("response", "error", "message"),
    [
        (
            httpx.Response(429, json={"error": {"message": f"slow down {KEY}"}}),
            LlmRateLimitError,
            "rate limited",
        ),
        (httpx.Response(401, json={"error": {"message": f"bad key {KEY}"}}), LlmError, "HTTP 401"),
        (httpx.Response(200, text="<html>"), LlmError, "not valid JSON"),
        (httpx.Response(200, json={"choices": []}), LlmError, "no message content"),
        (openai_reply(None), LlmError, "no message content"),
        (openai_reply(None, refusal="I can't help"), LlmError, "declined"),
        (
            httpx.Response(
                200, json={"choices": [{"message": {"content": "{"}, "finish_reason": "length"}]}
            ),
            LlmError,
            "cut off",
        ),
    ],
    ids=["429", "401", "not-json", "no-choices", "null-content", "refusal", "truncated"],
)
def test_openai_error_paths(response: httpx.Response, error: type[LlmError], message: str) -> None:
    with pytest.raises(error, match=message) as info:
        openai(lambda _: response).complete_json("s", "u", SCHEMA)
    assert KEY not in squashed(str(info.value))


# --- Anthropic -------------------------------------------------------------------------------


def test_anthropic_success_on_a_model_that_takes_temperature() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return anthropic_reply({"type": "text", "text": '{"ok": true}'})

    client = anthropic(handler, "claude-haiku-4-5")
    assert client.complete_json("sys", "user", SCHEMA) == '{"ok": true}'
    (request,) = seen
    assert str(request.url) == "https://api.anthropic.com/v1/messages"
    assert request.headers["x-api-key"] == KEY
    assert request.headers["anthropic-version"] == API_VERSION
    assert "authorization" not in request.headers
    assert "anthropic-beta" not in request.headers
    body = json.loads(request.content)
    assert body["system"] == "sys"
    assert body["messages"] == [{"role": "user", "content": "user"}]
    assert body["output_config"] == {"format": {"type": "json_schema", "schema": SCHEMA}}
    assert body["temperature"] == 0.0
    assert "fallbacks" not in body


@pytest.mark.parametrize(
    ("model", "temperature", "fallbacks"),
    [
        ("claude-opus-5", False, True),
        ("claude-fable-5-1", False, True),
        ("claude-sonnet-5", False, False),
        ("claude-opus-4-8", False, False),
        ("claude-haiku-4-5", True, False),
        ("claude-sonnet-4-6", True, False),
    ],
)
def test_anthropic_model_specific_fields(model: str, temperature: bool, fallbacks: bool) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return anthropic_reply({"type": "text", "text": "{}"})

    anthropic(handler, model).complete_json("s", "u", SCHEMA)
    body = json.loads(seen[0].content)
    assert ("temperature" in body) is temperature
    assert (body.get("fallbacks") == "default") is fallbacks
    assert (seen[0].headers.get("anthropic-beta") == FALLBACK_BETA) is fallbacks


def test_anthropic_skips_thinking_and_fallback_blocks() -> None:
    response = anthropic_reply(
        {"type": "thinking", "thinking": ""},
        {"type": "fallback", "from": {"model": "a"}, "to": {"model": "b"}},
        {"type": "text", "text": '{"ok":'},
        {"type": "text", "text": " false}"},
    )
    assert anthropic(lambda _: response).complete_json("s", "u", SCHEMA) == '{"ok": false}'


@pytest.mark.parametrize(
    ("response", "error", "message"),
    [
        (
            httpx.Response(429, json={"type": "error", "error": {"type": "rate_limit_error"}}),
            LlmRateLimitError,
            "rate limited",
        ),
        (
            httpx.Response(529, json={"type": "error", "error": {"type": "overloaded_error"}}),
            LlmError,
            "HTTP 529",
        ),
        (httpx.Response(401, text=f"invalid x-api-key {KEY}"), LlmError, "HTTP 401"),
        (httpx.Response(200, text="not json"), LlmError, "not valid JSON"),
        (anthropic_reply(), LlmError, "no text content"),
        (httpx.Response(200, json={"content": "text"}), LlmError, "no text content"),
        (anthropic_reply({"type": "text", "text": 5}), LlmError, "no text content"),
        (anthropic_reply(stop_reason="refusal"), LlmError, "declined"),
        (
            anthropic_reply({"type": "text", "text": "{"}, stop_reason="max_tokens"),
            LlmError,
            "cut off",
        ),
    ],
    ids=[
        "429",
        "529",
        "401",
        "not-json",
        "empty",
        "wrong-shape",
        "non-string",
        "refusal",
        "truncated",
    ],
)
def test_anthropic_error_paths(
    response: httpx.Response, error: type[LlmError], message: str
) -> None:
    with pytest.raises(error, match=message) as info:
        anthropic(lambda _: response).complete_json("s", "u", SCHEMA)
    assert KEY not in squashed(str(info.value))


# --- Boundaries --------------------------------------------------------------------------------


def test_no_provider_imports_outside_llm() -> None:
    package = Path(__file__).parents[1] / "zirah"
    offenders = []
    for path in package.rglob("*.py"):
        if path.parent.name == "llm":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            for name in names:
                if name.split(".")[0] in {"openai", "anthropic", "ollama"} or name in {
                    "zirah.llm.openai",
                    "zirah.llm.anthropic",
                    "zirah.llm.ollama",
                }:
                    offenders.append(f"{path.name}: {name}")
    assert offenders == []
