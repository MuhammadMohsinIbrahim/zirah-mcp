"""Shared machinery for analyzers driven by YAML rules.

:func:`iter_text` flattens a manifest (and the target, for secrets) into strings, each with a
JSON Pointer to where it came from. :class:`RuleAnalyzer` runs a module's rules over those
strings and turns matches into findings, so a module's analyzer holds only what is special
about that module.
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from zirah.analyzers.base import Analyzer, ScanContext
from zirah.models import Engine, Evidence, Finding, Manifest, Module, Target
from zirah.rulepack import Rule, Surface, secret_spans

CONTEXT_CHARS = 60
"""Characters of surrounding text kept on each side of a match in a finding's snippet."""

TARGET_PREFIX = "target:"
"""Locations outside the manifest start with this, e.g. ``target:/args``."""


@dataclass(frozen=True, slots=True)
class TextField:
    """One string from the scan target, with where it was found."""

    location: str
    """JSON Pointer into the manifest (``/tools/0/description``), or ``target:/...``."""
    text: str
    surface: Surface


def json_pointer(*parts: str | int) -> str:
    """Build a JSON Pointer (RFC 6901) from path segments."""
    return "".join("/" + str(part).replace("~", "~0").replace("/", "~1") for part in parts)


def iter_text(manifest: Manifest, target: Target | None = None) -> Iterator[TextField]:
    """Every non-empty string in ``manifest``, in document order.

    Schemas and annotations are walked recursively, keys included: a property name is text
    the model reads too. A key's location is the pointer to its member. When ``target`` is
    given, its location and its arguments (joined into one command line, so ``--token VALUE``
    reads as one phrase) come last.
    """
    fields: list[tuple[tuple[str | int, ...], Any, Surface]] = [
        (("server_name",), manifest.server_name, Surface.SERVER),
        (("server_version",), manifest.server_version, Surface.SERVER),
        (("instructions",), manifest.instructions, Surface.INSTRUCTIONS),
    ]
    for i, tool in enumerate(manifest.tools):
        base: tuple[str | int, ...] = ("tools", i)
        fields += [
            ((*base, "name"), tool.name, Surface.TOOLS),
            ((*base, "title"), tool.title, Surface.TOOLS),
            ((*base, "description"), tool.description, Surface.TOOLS),
            ((*base, "input_schema"), tool.input_schema, Surface.TOOLS),
            ((*base, "output_schema"), tool.output_schema, Surface.TOOLS),
            ((*base, "annotations"), tool.annotations, Surface.TOOLS),
        ]
    for i, prompt in enumerate(manifest.prompts):
        base = ("prompts", i)
        fields += [
            ((*base, "name"), prompt.name, Surface.PROMPTS),
            ((*base, "title"), prompt.title, Surface.PROMPTS),
            ((*base, "description"), prompt.description, Surface.PROMPTS),
        ]
        for j, argument in enumerate(prompt.arguments):
            fields += [
                ((*base, "arguments", j, "name"), argument.name, Surface.PROMPTS),
                ((*base, "arguments", j, "description"), argument.description, Surface.PROMPTS),
            ]
    for i, resource in enumerate(manifest.resources):
        base = ("resources", i)
        fields += [
            ((*base, "uri"), resource.uri, Surface.RESOURCES),
            ((*base, "name"), resource.name, Surface.RESOURCES),
            ((*base, "title"), resource.title, Surface.RESOURCES),
            ((*base, "description"), resource.description, Surface.RESOURCES),
            ((*base, "mime_type"), resource.mime_type, Surface.RESOURCES),
        ]

    for path, value, surface in fields:
        yield from _walk(value, path, surface)

    if target is not None:
        yield TextField(f"{TARGET_PREFIX}/location", target.location, Surface.TARGET)
        if target.args:
            yield TextField(f"{TARGET_PREFIX}/args", " ".join(target.args), Surface.TARGET)


def _walk(value: Any, path: tuple[str | int, ...], surface: Surface) -> Iterator[TextField]:
    if isinstance(value, str):
        if value:
            yield TextField(json_pointer(*path), value, surface)
    elif isinstance(value, Mapping):
        for key, item in value.items():
            child = (*path, str(key))
            if key:
                yield TextField(json_pointer(*child), str(key), surface)
            yield from _walk(item, child, surface)
    elif isinstance(value, Sequence):
        for index, item in enumerate(value):
            yield from _walk(item, (*path, index), surface)


Span = tuple[int, int]


def context_snippet(text: str, start: int, end: int, keep_whole: Sequence[Span] = ()) -> str:
    """``text[start:end]`` with up to ``CONTEXT_CHARS`` of context on each side.

    The window grows to take in any span of ``keep_whole`` it overlaps, so a secret is never
    cut in half (a half secret would no longer match, and so escape redaction). The text is
    kept verbatim, invisible characters included; reports escape it for display.
    """
    lo = max(0, start - CONTEXT_CHARS)
    hi = min(len(text), end + CONTEXT_CHARS)
    for span_start, span_end in keep_whole:
        if span_start < hi and span_end > lo:
            lo, hi = min(lo, span_start), max(hi, span_end)
    return ("…" if lo > 0 else "") + text[lo:hi] + ("…" if hi < len(text) else "")


# --- Secrets -------------------------------------------------------------------------------

REDACT_KEEP = 4
"""Most characters of a secret shown in evidence; the rest becomes ``****``."""


def redact(value: str) -> str:
    """A short prefix of ``value`` plus ``****``, never more than a quarter of it.

    Already redacted values are returned unchanged, so redacting twice is harmless.
    """
    if value.endswith("****"):
        return value
    return value[: min(REDACT_KEEP, len(value) // 4)] + "****"


def redact_match(match: re.Match[str]) -> str:
    """The matched text with every secret in it redacted."""
    text, pos, parts = match.string, match.start(), []
    for start, end in secret_spans(match):
        value = text[start:end]
        stripped = value.lstrip()
        parts += [text[pos:start], value[: len(value) - len(stripped)], redact(stripped.strip())]
        pos = end
    parts.append(text[pos : match.end()])
    return "".join(parts)


def redact_secrets(text: str, rules: Sequence[Rule]) -> str:
    """``text`` with every match of the secret ``rules`` (module D4) redacted."""
    for rule in rules:
        text = rule.pattern.sub(redact_match, text)
    return text


def redact_target(target: Target, rules: Sequence[Rule]) -> Target:
    """``target`` with secrets in its location and arguments redacted.

    Arguments are matched as one command line (so ``--token VALUE`` is seen as a pair); an
    argument that holds part of a secret but no whole one is redacted as a whole.
    """
    starts, pos = [], 0
    for arg in target.args:
        starts.append(pos)
        pos += len(arg) + 1
    joined = " ".join(target.args)
    spans = [span for rule in rules for m in rule.finditer(joined) for span in secret_spans(m)]
    args = []
    for arg, start in zip(target.args, starts, strict=True):
        cleaned = redact_secrets(arg, rules)
        overlaps = any(s < start + len(arg) and e > start for s, e in spans)
        args.append(cleaned if cleaned != arg or not overlaps else redact(arg))
    return target.model_copy(
        update={"location": redact_secrets(target.location, rules), "args": tuple(args)}
    )


class RuleAnalyzer(Analyzer):
    """An analyzer whose detections all come from its module's YAML rules.

    Each rule reports at most one finding per location: the first accepted match, shown in
    context. Subclasses implement ``analyze`` as ``return self.match_rules(manifest, ctx)``
    and override :meth:`accept` or :meth:`snippet` for module-specific handling.

    Whatever the module, secrets matched by the D4 rules are redacted in every snippet, so
    an API key sitting next to a hidden character does not leak through a D1 finding.
    """

    engine = Engine.STATIC

    def match_rules(self, manifest: Manifest, ctx: ScanContext) -> list[Finding]:
        rules = ctx.rules.for_module(self.module)
        secret_rules = ctx.rules.for_module(Module.D4)
        findings: list[Finding] = []
        for field in iter_text(manifest, ctx.target):
            for rule in rules:
                if field.surface not in rule.surfaces:
                    continue
                for match in rule.finditer(field.text):
                    if self.accept(rule, match, field, manifest):
                        secrets = [m.span() for r in secret_rules for m in r.finditer(field.text)]
                        snippet = redact_secrets(self.snippet(rule, match, secrets), secret_rules)
                        findings.append(self._finding(rule, field, snippet))
                        break
        return findings

    def accept(
        self, rule: Rule, match: re.Match[str], field: TextField, manifest: Manifest
    ) -> bool:
        """Whether ``match`` is a real detection. Every match is, unless overridden."""
        return True

    def snippet(self, rule: Rule, match: re.Match[str], secrets: Sequence[Span]) -> str:
        """The evidence shown for ``match``: the match in context, unless overridden.

        ``secrets`` are the spans of secrets in the same text; the context must not cut one.
        """
        return context_snippet(match.string, match.start(), match.end(), keep_whole=secrets)

    def _finding(self, rule: Rule, field: TextField, snippet: str) -> Finding:
        return Finding(
            module=rule.module,
            rule_id=rule.id,
            severity=rule.severity,
            confidence=rule.confidence,
            owasp=rule.owasp,
            title=rule.title,
            evidence=Evidence(location=field.location, snippet=snippet),
            remediation=rule.remediation,
            engine=self.engine,
        )
