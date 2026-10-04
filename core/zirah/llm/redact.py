"""Secret redaction for everything sent to an LLM provider.

Secret values must never leave the machine. Before any request body goes to a provider,
:meth:`zirah.llm.base.LlmClient._post` (the only place that sends) passes it through
:func:`redact_payload`. Every string in it is checked with the D4 secret rules, and each secret
value is replaced with ``[REDACTED:<type>]``, where the type is the rule id without ``D4-`` in
lower case (``D4-GITHUB-TOKEN`` -> ``[REDACTED:github-token]``). Nothing of the secret is kept:
no prefix, no length. The text around it is kept, so the judge can still read what a tool says.

Unlike the D4 analyzer, this does not skip low-entropy matches: redacting a placeholder that
only looks like a key costs nothing, while missing a real key is a leak.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from functools import lru_cache
from typing import Any, Final

from zirah.models import Module
from zirah.rulepack import Rule, load_rulepack, secret_spans

PLACEHOLDER: Final = re.compile(r"\[REDACTED:[a-z0-9-]+\]")
"""A placeholder already in the text. Redacting it again would only mangle it."""


def placeholder(rule: Rule) -> str:
    """The text that replaces a value found by ``rule``: ``[REDACTED:<type>]``."""
    return f"[REDACTED:{rule.id.removeprefix('D4-').lower()}]"


@lru_cache(maxsize=1)
def bundled_secret_rules() -> tuple[Rule, ...]:
    """The D4 rules of the bundled rule pack (loaded once)."""
    return tuple(load_rulepack().for_module(Module.D4))


def redact_for_llm(text: str, rules: Sequence[Rule] | None = None) -> str:
    """``text`` with every secret value found by ``rules`` (default: the bundled D4 rules)
    replaced by its placeholder. Overlapping matches are replaced once, as one span, and a
    match made only of existing placeholders is left alone, so redacting twice is harmless."""
    covered = [m.span() for m in PLACEHOLDER.finditer(text)]

    def only_placeholders(start: int, end: int) -> bool:
        return all(
            text[i].isspace() or any(a <= i < b for a, b in covered) for i in range(start, end)
        )

    spans: list[tuple[int, int, str]] = []
    for rule in bundled_secret_rules() if rules is None else rules:
        for match in rule.finditer(text):
            spans += [
                (s, e, placeholder(rule))
                for s, e in secret_spans(match)
                if e > s and not only_placeholders(s, e)
            ]
    if not spans:
        return text
    merged: list[tuple[int, int, str]] = []
    for start, end, label in sorted(spans):
        if merged and start < merged[-1][1]:
            first, last, kept = merged[-1]
            merged[-1] = (first, max(last, end), kept)
        else:
            merged.append((start, end, label))
    parts: list[str] = []
    pos = 0
    for start, end, label in merged:
        parts += [text[pos:start], label]
        pos = end
    parts.append(text[pos:])
    return "".join(parts)


def redact_payload(value: Any, rules: Sequence[Rule] | None = None) -> Any:
    """A copy of a JSON-like request body with every string (keys included) redacted."""
    if isinstance(value, str):
        return redact_for_llm(value, rules)
    if isinstance(value, dict):
        return {redact_payload(k, rules): redact_payload(v, rules) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [redact_payload(item, rules) for item in value]
    return value
