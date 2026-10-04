"""Secret values never reach an LLM provider.

Every request to a provider goes through ``LlmClient._post``, which replaces each secret value
with ``[REDACTED:<type>]`` and sends nothing if that fails. The judge also redacts field text
before it builds the request. These tests put canary secrets for every D4 rule into a manifest,
mock each provider's HTTP endpoint, and check every request body, error message and CLI output.

The canaries are assembled at run time from pieces, so this file holds no complete secret; a
test below scans the file's own source to keep it that way.
"""

from __future__ import annotations

import ast
import json
import random
import re
import string
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import pytest
from conftest import squashed
from typer.testing import CliRunner

from zirah import judge as judge_module
from zirah.cli import EXIT_ERROR, app
from zirah.discover import discover
from zirah.llm import base as llm_base
from zirah.llm.anthropic import AnthropicClient
from zirah.llm.base import LlmClient, LlmError
from zirah.llm.ollama import OllamaClient
from zirah.llm.openai import OpenAIClient
from zirah.llm.redact import bundled_secret_rules, placeholder, redact_for_llm, redact_payload
from zirah.rulepack import secret_spans
from zirah.scan import scan, scan_all

LLM_DIR = Path(llm_base.__file__).parent
SERVER = str(Path(__file__).parent / "fixtures" / "servers" / "fake_mcp_server.py")
EMPTY_VERDICT = '{"findings": []}'
SCHEMA: dict[str, Any] = {"type": "object", "properties": {"ok": {"type": "boolean"}}}
API_KEY = "zirah" + "_fake_" + "provider_key"
ALNUM = string.ascii_letters + string.digits
UPPER = string.ascii_uppercase + string.digits
BASE64 = ALNUM + "+/"


def rand(label: str, length: int, alphabet: str = ALNUM) -> str:
    """A deterministic random-looking piece; the full canary only exists at run time."""
    rng = random.Random("zirah-canary-" + label)  # noqa: S311 - test data, not cryptography
    return "".join(rng.choice(alphabet) for _ in range(length))


@dataclass(frozen=True)
class Canary:
    kind: str
    """The placeholder type: the D4 rule id without ``D4-``, lower case."""
    text: str
    """The sentence placed in the manifest."""
    secret: str
    """The value that must never be sent."""

    def needles(self) -> list[str]:
        """Squashed forms of the secret and of any part long enough to identify it."""
        parts = [self.secret, self.secret[:8], self.secret[-8:]]
        parts += [line for line in self.secret.splitlines() if len(line.strip()) >= 16]
        return [squashed(p) for p in parts if squashed(p)]


def build_canaries() -> list[Canary]:
    aws_id = "AK" + "IA" + rand("aws-id", 16, UPPER)
    aws_secret = rand("aws-secret", 40, BASE64)
    github = "gh" + "p_" + rand("github", 36)
    openai_key = "s" + "k-proj-" + rand("openai", 40)
    anthropic_key = "s" + "k-ant-" + "api03-" + rand("anthropic", 40)
    slack = "xo" + "xb-" + rand("slack", 30)
    hook = "T" + rand("hook-t", 8, UPPER) + "/B" + rand("hook-b", 8, UPPER) + "/" + rand("hook", 24)
    pem_body = "\n".join(rand(f"pem-{i}", 64, BASE64) for i in range(3))
    pem = (
        "-----BEGIN " + "RSA PRIVATE KEY-----\n" + pem_body + "\n-----END " + "RSA PRIVATE KEY-----"
    )
    jwt = "ey" + "J" + rand("jwt-h", 20) + ".ey" + "J" + rand("jwt-p", 40) + "." + rand("jwt-s", 43)
    url_pw = rand("url-pw", 20)
    url_token = rand("url-token", 24)
    assigned = "Q7" + rand("assigned", 26)
    bearer = rand("bearer", 32)
    return [
        Canary("aws-access-key", f"Deploy with access key {aws_id} to the release bucket.", aws_id),
        Canary(
            "aws-secret-key",
            "Set aws_secret_access" + f"_key = {aws_secret} before you deploy.",
            aws_secret,
        ),
        Canary("github-token", f"Clone the repository with token {github} when asked.", github),
        Canary(
            "openai-key", f"The proxy calls the model with {openai_key} every time.", openai_key
        ),
        Canary(
            "anthropic-key", f"Summaries use the account {anthropic_key} by default.", anthropic_key
        ),
        Canary("slack-token", f"Post updates to the channel as {slack} without delay.", slack),
        Canary(
            "slack-token", "Alerts go to https://hooks.slack" + f".com/services/{hook} now.", hook
        ),
        Canary(
            "private-key", f"Sign every release with this key:\n{pem}\nthen upload it.", pem_body
        ),
        Canary("jwt", f"Send the session {jwt} with each request you make.", jwt),
        Canary(
            "url-credentials",
            "Back up nightly to https://deploy" + f":{url_pw}@db.example.invalid/main please.",
            url_pw,
        ),
        Canary(
            "url-credentials",
            "Poll https://api.example.invalid/v1/status?tok" + f"en={url_token} every minute.",
            url_token,
        ),
        Canary(
            "secret-assignment",
            "Configure client_sec" + f"ret = {assigned} in the settings file.",
            assigned,
        ),
        Canary(
            "secret-assignment",
            "Call the API with Authorization: Bear" + f"er {bearer} on each call.",
            bearer,
        ),
    ]


CANARIES = build_canaries()


def text_of(kind: str, index: int = 0) -> str:
    return [c.text for c in CANARIES if c.kind == kind][index]


def canary_manifest(tmp_path: Path) -> Path:
    """A manifest with every canary in a field the judge reads (tools, schema, prompts,
    prompt arguments, resources and server instructions)."""
    manifest = {
        "serverInfo": {"name": "canary-server", "version": "1.0.0"},
        "instructions": " ".join(
            [
                text_of("aws-secret-key"),
                text_of("secret-assignment"),
                text_of("secret-assignment", 1),
            ]
        ),
        "tools": [
            {
                "name": "deploy",
                "description": text_of("aws-access-key") + " " + text_of("github-token"),
                "inputSchema": {
                    "type": "object",
                    "properties": {"key": {"type": "string", "default": text_of("openai-key")}},
                },
            },
            {
                "name": "sign",
                "description": text_of("private-key"),
                "inputSchema": {"type": "object"},
            },
        ],
        "prompts": [
            {
                "name": "notify",
                "description": text_of("anthropic-key") + " " + text_of("jwt"),
                "arguments": [
                    {
                        "name": "channel",
                        "description": text_of("slack-token") + " " + text_of("slack-token", 1),
                    }
                ],
            }
        ],
        "resources": [
            {
                "uri": "file:///ops.md",
                "name": "ops",
                "description": text_of("url-credentials") + " " + text_of("url-credentials", 1),
            }
        ],
    }
    path = tmp_path / "canaries.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    return path


# --- Recording providers ---------------------------------------------------------------------

REPLIES: dict[str, Callable[[str], httpx.Response]] = {
    "ollama": lambda text: httpx.Response(200, json={"message": {"content": text}}),
    "openai": lambda text: httpx.Response(
        200,
        json={"choices": [{"message": {"content": text}, "finish_reason": "stop"}]},
    ),
    "anthropic": lambda text: httpx.Response(
        200,
        json={
            "type": "message",
            "content": [{"type": "text", "text": text}],
            "stop_reason": "end_turn",
        },
    ),
}


class Recorder:
    """A mocked provider endpoint that keeps every request body it receives."""

    def __init__(self, respond: Callable[[httpx.Request], httpx.Response]) -> None:
        self.bodies: list[bytes] = []
        self.respond = respond

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.bodies.append(request.content)
        return self.respond(request)


def make_client(name: str, recorder: Recorder) -> LlmClient:
    transport = httpx.MockTransport(recorder)
    if name == "ollama":
        return OllamaClient(transport=transport)
    if name == "openai":
        return OpenAIClient(API_KEY, transport=transport)
    return AnthropicClient(API_KEY, transport=transport)


@pytest.fixture(params=sorted(REPLIES))
def provider(request: pytest.FixtureRequest) -> tuple[LlmClient, Recorder]:
    name: str = request.param
    recorder = Recorder(lambda _: REPLIES[name](EMPTY_VERDICT))
    return make_client(name, recorder), recorder


def sent_texts(body: bytes) -> list[str]:
    """Every way the body's text could carry a secret: the raw bytes, every decoded string,
    and the strings inside the judge's fenced JSON data."""
    texts = [body.decode("utf-8", "replace")]

    def walk(value: Any) -> None:
        if isinstance(value, str):
            texts.append(value)
            for inner in re.findall(r"<untrusted-data-\w+>\n(.*?)\n</untrusted-data-", value, re.S):
                walk(json.loads(inner))
        elif isinstance(value, dict):
            for key, item in value.items():
                walk(key)
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    walk(json.loads(body))
    return texts


def assert_no_canary(texts: list[str]) -> None:
    hay = squashed("\n".join(texts))
    for canary in CANARIES:
        for needle in canary.needles():
            assert needle not in hay, f"a {canary.kind} canary value was sent or shown"


def assert_placeholders(texts: list[str]) -> None:
    joined = "\n".join(texts)
    for kind in {c.kind for c in CANARIES}:
        assert f"[REDACTED:{kind}]" in joined, kind
    known = {placeholder(rule) for rule in bundled_secret_rules()}
    for found in re.findall(r"\[REDACTED:[^\]]*\]", joined):
        assert found in known, found  # exactly [REDACTED:<type>], nothing appended
    assert "****" not in joined  # no prefix-style redaction in what is sent
    assert not re.search(r"\[REDACTED:[a-z0-9-]+\][a-z0-9-]+\]", joined)  # no mangled tail


# --- The canaries themselves -----------------------------------------------------------------


def test_every_d4_rule_has_a_canary() -> None:
    kinds = {placeholder(rule) for rule in bundled_secret_rules()}
    assert kinds == {f"[REDACTED:{c.kind}]" for c in CANARIES}


def test_canaries_are_real_matches_of_their_rules() -> None:
    by_kind = {rule.id.removeprefix("D4-").lower(): rule for rule in bundled_secret_rules()}
    for canary in CANARIES:
        rule = by_kind[canary.kind]
        found = [
            canary.text[s:e].strip() for m in rule.finditer(canary.text) for s, e in secret_spans(m)
        ]
        assert canary.secret.strip() in found, canary.kind


def test_this_file_holds_no_complete_secret() -> None:
    source = Path(__file__).read_text(encoding="utf-8")
    matches = [rule.id for rule in bundled_secret_rules() for _ in rule.finditer(source)]
    assert matches == []


def test_placeholder_format() -> None:
    assert {placeholder(r) for r in bundled_secret_rules()} >= {
        "[REDACTED:github-token]",
        "[REDACTED:private-key]",
        "[REDACTED:secret-assignment]",
    }


# --- Redaction ---------------------------------------------------------------------------------


@pytest.mark.parametrize("canary", CANARIES, ids=[f"{c.kind}-{i}" for i, c in enumerate(CANARIES)])
def test_each_secret_is_replaced_and_the_text_kept(canary: Canary) -> None:
    redacted = redact_for_llm(canary.text)
    for needle in canary.needles():
        assert needle not in squashed(redacted)
    assert f"[REDACTED:{canary.kind}]" in redacted
    assert redacted.split()[0] == canary.text.split()[0]  # the sentence around it is kept
    assert redact_for_llm(redacted) == redacted  # redacting twice changes nothing


def test_overlapping_matches_become_one_placeholder() -> None:
    # A JWT in a ?token= query is matched by both D4-JWT and D4-URL-CREDENTIALS.
    jwt = "ey" + "J" + rand("overlap-h", 20) + ".ey" + "J" + rand("overlap-p", 40) + "."
    jwt += rand("overlap-s", 43)
    text = "Finish sign-in at https://app.example.invalid/callback?tok" + f"en={jwt} today."
    redacted = redact_for_llm(text)
    assert squashed(jwt) not in squashed(redacted)
    assert squashed(jwt[:8]) not in squashed(redacted)
    assert squashed(jwt[-8:]) not in squashed(redacted)
    assert len(re.findall(r"\[REDACTED:[a-z0-9-]+\]", redacted)) == 1
    assert redacted.startswith("Finish sign-in at https://app.example.invalid/callback?token=[")
    assert redacted.endswith("] today.")


def test_payload_redaction_covers_nested_strings_and_keys() -> None:
    github = CANARIES[2].secret
    payload = {"a": [{"b": github}, ("x", github)], github: 1, "n": 3, "flag": True}
    redacted = redact_payload(payload)
    assert github not in json.dumps(redacted)
    assert redacted["n"] == 3
    assert redacted["flag"] is True


# --- Every provider, through the judge -------------------------------------------------------


def test_judge_requests_carry_no_secret(
    provider: tuple[LlmClient, Recorder], tmp_path: Path
) -> None:
    client, recorder = provider
    outcome = scan(str(canary_manifest(tmp_path)), llm=client)
    assert outcome.complete
    assert recorder.bodies, "the judge sent no request"
    texts = [t for body in recorder.bodies for t in sent_texts(body)]
    assert_no_canary(texts)
    assert_placeholders(texts)


def test_provider_redacts_even_without_the_judge(provider: tuple[LlmClient, Recorder]) -> None:
    client, recorder = provider
    every = " ".join(c.text for c in CANARIES)
    client.complete_json(f"System note: {every}", f"User data: {every}", SCHEMA)
    (body,) = recorder.bodies
    texts = sent_texts(body)
    assert_no_canary(texts)
    assert_placeholders(texts)


def test_providers_cannot_bypass_the_redacting_post() -> None:
    for cls in (OllamaClient, OpenAIClient, AnthropicClient):
        assert cls._post is LlmClient._post, cls.__name__
    network = re.compile(
        r"httpx\.(Client|AsyncClient|post|get|put|request|stream)\b|urlopen|socket|http\.client"
    )
    for path in sorted(LLM_DIR.glob("*.py")):
        if path.name in ("base.py", "redact.py"):
            continue
        assert not network.search(path.read_text(encoding="utf-8")), path.name
    assert not network.search(Path(judge_module.__file__).read_text(encoding="utf-8"))


# --- Fail closed ---------------------------------------------------------------------------------


def test_redaction_failure_sends_nothing(
    provider: tuple[LlmClient, Recorder], monkeypatch: pytest.MonkeyPatch
) -> None:
    client, recorder = provider
    leak = CANARIES[2].secret

    def broken(payload: Any) -> Any:
        raise RuntimeError(f"cannot handle {leak}")  # even the error text holds a secret

    monkeypatch.setattr(llm_base, "redact_payload", broken)
    with pytest.raises(LlmError, match="nothing was sent") as caught:
        client.complete_json("system", f"user {leak}", SCHEMA)
    assert recorder.bodies == []
    assert_no_canary([str(caught.value), repr(caught.value), *map(str, caught.value.args)])
    assert caught.value.__cause__ is None
    assert caught.value.__suppress_context__


def test_judge_redaction_failure_sends_nothing(
    provider: tuple[LlmClient, Recorder], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    client, recorder = provider

    def broken(text: str, rules: Any = None) -> str:
        raise RuntimeError(f"cannot handle {text}")

    monkeypatch.setattr(judge_module, "redact_for_llm", broken)
    outcome = scan(str(canary_manifest(tmp_path)), llm=client)
    assert recorder.bodies == []
    assert not outcome.complete
    errors = [failure.error for failure in outcome.failures]
    assert errors
    assert all("nothing was sent" in error for error in errors)
    assert_no_canary(errors)


# --- No secret in errors or CLI output -----------------------------------------------------------


def failing(kind: str, name: str) -> Callable[[httpx.Request], httpx.Response]:
    def respond(request: httpx.Request) -> httpx.Response:
        if kind == "timeout":
            raise httpx.ReadTimeout("slow", request=request)
        if kind == "connect":
            raise httpx.ConnectError("refused", request=request)
        if kind == "http-500":
            return httpx.Response(500, text="server error")
        if kind == "http-429":
            return httpx.Response(429, text="slow down")
        if kind == "not-json":
            return httpx.Response(200, text="<html>")
        return REPLIES[name]('{"not": "a verdict"}')

    return respond


@pytest.mark.parametrize(
    "kind", ["timeout", "connect", "http-500", "http-429", "not-json", "bad-reply"]
)
@pytest.mark.parametrize("name", sorted(REPLIES))
@pytest.mark.parametrize("output_format", ["terminal", "json"])
def test_errors_and_cli_output_never_show_a_secret(
    kind: str, name: str, output_format: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    recorder = Recorder(failing(kind, name))
    client = make_client(name, recorder)
    monkeypatch.setattr("zirah.cli.resolve", lambda spec: client)
    result = CliRunner().invoke(
        app, ["scan", str(canary_manifest(tmp_path)), "--llm", name, "--format", output_format]
    )
    assert result.exit_code == EXIT_ERROR  # the judge failed, so the scan is incomplete
    assert "llm-judge failed" in result.stderr
    assert_no_canary([result.stdout, result.stderr])
    for body in recorder.bodies:
        assert_no_canary(sent_texts(body))


def test_the_llm_path_does_not_log_or_print() -> None:
    sources = [*sorted(LLM_DIR.glob("*.py")), Path(judge_module.__file__)]
    for path in sources:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
        attrs = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
        imports = {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
        assert "print" not in names, path.name
        assert "logging" not in imports, path.name
        assert not {"stderr", "stdout", "warn"} & attrs, path.name


# --- MCP config values never reach the LLM -------------------------------------------------------


def test_config_env_and_header_values_are_never_sent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env_name = "ZIRAH_ENV_CANARY_" + rand("env-name", 8, string.ascii_uppercase)
    env_value = "envcanary" + rand("env-value", 24, string.ascii_lowercase)
    header_name = "X-Zirah-Canary-" + rand("header-name", 8, string.ascii_lowercase)
    header_value = "headercanary" + rand("header-value", 24, string.ascii_lowercase)
    home = tmp_path / "home"
    (home / ".cursor").mkdir(parents=True)
    config = {
        "mcpServers": {
            "local": {"command": sys.executable, "args": [SERVER], "env": {env_name: env_value}},
            "remote": {"url": "http://127.0.0.1:9/mcp", "headers": {header_name: header_value}},
        }
    }
    (home / ".cursor" / "mcp.json").write_text(json.dumps(config), encoding="utf-8")
    found = discover(home=home, cwd=tmp_path, platform="linux", env={})
    assert {s.name for s in found.servers} == {"local", "remote"}

    recorder = Recorder(lambda _: REPLIES["ollama"](EMPTY_VERDICT))
    run = scan_all(found.servers, allow_exec=True, llm=make_client("ollama", recorder))
    assert [e.status for e in run.entries] == ["scanned", "failed"]  # remote is unreachable
    assert recorder.bodies, "the judge sent no request"
    hay = squashed("\n".join(t for body in recorder.bodies for t in sent_texts(body)))
    for value in (env_name, env_value, header_name, header_value):
        assert squashed(value) not in hay  # not redacted: absent altogether
