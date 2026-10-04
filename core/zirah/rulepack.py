"""Load and validate YAML rule packs.

A rule pack is a directory with ``pack.yaml`` (holding the pack ``version``) and any number of
other ``*.yaml`` files, each holding a list of ``rules``. The bundled pack lives in
``zirah/rules/``; users can point Zirah at their own directory.

Every rule compiles to one regular expression at load time, whatever its ``kind``, so a broken
rule fails when the pack loads rather than in the middle of a scan.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from enum import StrEnum
from importlib.resources import as_file, files
from pathlib import Path
from typing import Annotated, Any, Literal

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    PrivateAttr,
    StringConstraints,
    ValidationError,
    model_validator,
)

from zirah.models import Confidence, Module, Owasp, Severity

PACK_FILE = "pack.yaml"

RuleId = Annotated[str, StringConstraints(pattern=r"^D\d{1,2}-[A-Z0-9]+(?:-[A-Z0-9]+)*$")]
NonEmptyStr = Annotated[str, StringConstraints(min_length=1)]

_CODEPOINT = re.compile(r"^U\+([0-9A-F]{4,6})$")
_CATEGORY = re.compile(r"[a-z][a-z0-9_]*")


class RulePackError(Exception):
    """A rule pack is missing, malformed, or contains an invalid rule."""


class Surface(StrEnum):
    """The parts of a scan target a rule can look at."""

    TOOLS = "tools"
    """Tool names, titles, descriptions, schemas and annotations."""
    PROMPTS = "prompts"
    """Prompt names, titles, descriptions and arguments."""
    RESOURCES = "resources"
    """Resource URIs, names, titles, descriptions and MIME types."""
    INSTRUCTIONS = "instructions"
    """The server's ``instructions`` text."""
    SERVER = "server"
    """The server name and version."""
    TARGET = "target"
    """The target's location and arguments (not part of the manifest)."""


MANIFEST_SURFACES: tuple[Surface, ...] = (
    Surface.TOOLS,
    Surface.PROMPTS,
    Surface.RESOURCES,
    Surface.INSTRUCTIONS,
    Surface.SERVER,
)
"""What a rule looks at when it does not list ``surfaces``: everything in the manifest."""


class Rule(BaseModel):
    """One detection rule.

    ``kind`` decides how ``patterns`` are read:

    - ``regex``: each entry is a Python regular expression.
    - ``keywords``: each entry is a literal phrase, matched on word boundaries.
    - ``codepoints``: each entry is ``U+XXXX`` or a range ``U+XXXX-U+YYYY``.
    - ``llm``: each entry is a category the optional LLM judge may report (``snake_case``).
      These rules never match text themselves; they give the judge's findings their id,
      severity, confidence ceiling, OWASP mapping and remediation.

    ``surfaces`` limits where the rule looks, e.g. only tool descriptions and schemas, so a
    phrase judged by two modules in different places is reported once.

    ``min_entropy`` (bits per character) is for secret rules: a match only counts when the
    secret it captured is at least that random, which keeps placeholders like
    ``sk-xxxxxxxxxxxxxxxxxxxxxxxx`` out of the findings.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: RuleId
    module: Module
    severity: Severity
    confidence: Confidence
    owasp: Annotated[tuple[Owasp, ...], Field(min_length=1)]
    title: NonEmptyStr
    remediation: NonEmptyStr
    kind: Literal["regex", "keywords", "codepoints", "llm"]
    patterns: Annotated[tuple[NonEmptyStr, ...], Field(min_length=1)]
    ignore_case: bool = True
    surfaces: Annotated[tuple[Surface, ...], Field(min_length=1)] = MANIFEST_SURFACES
    min_entropy: Annotated[float, Field(gt=0)] | None = None
    references: tuple[str, ...] = ()

    _pattern: re.Pattern[str] = PrivateAttr()

    @model_validator(mode="after")
    def _check_and_compile(self) -> Rule:
        prefix = self.id.split("-", 1)[0]
        if prefix != self.module.value:
            raise ValueError(f"id prefix {prefix!r} does not match module {self.module.value!r}")
        self._pattern = _compile(self)
        return self

    @property
    def pattern(self) -> re.Pattern[str]:
        return self._pattern

    def finditer(self, text: str) -> Iterator[re.Match[str]]:
        """All non-overlapping matches of this rule in ``text``."""
        return self._pattern.finditer(text)


SECRET_GROUP = re.compile(r"secret(?:_\d+)?")
"""Regex groups holding the secret itself in a D4 rule; text around them is shown as is."""


def secret_spans(match: re.Match[str]) -> list[tuple[int, int]]:
    """Where the secret is in ``match``: its secret groups, or the whole match."""
    spans = [
        match.span(name)
        for name, value in match.groupdict().items()
        if value is not None and SECRET_GROUP.fullmatch(name)
    ]
    return sorted(spans) or [match.span()]


def _compile(rule: Rule) -> re.Pattern[str]:
    flags = re.IGNORECASE if rule.ignore_case else 0
    if rule.kind == "llm":
        bad = [p for p in rule.patterns if not _CATEGORY.fullmatch(p)]
        if bad:
            raise ValueError(f"llm categories must be snake_case, got {bad[0]!r}")
        return re.compile(r"(?!)")  # matches nothing: the judge reports these, not a regex
    if rule.kind == "regex":
        source = "|".join(f"(?:{p})" for p in rule.patterns)
    elif rule.kind == "keywords":
        # \b only makes sense next to word characters; keep phrases like "<IMPORTANT>" exact.
        parts = []
        for phrase in rule.patterns:
            start = r"\b" if re.match(r"\w", phrase) else ""
            end = r"\b" if re.search(r"\w$", phrase) else ""
            parts.append(f"{start}{re.escape(phrase)}{end}")
        source = "|".join(parts)
    else:
        source = "[" + "".join(_codepoint_range(p) for p in rule.patterns) + "]+"
        flags = 0
    try:
        return re.compile(source, flags)
    except re.error as exc:
        raise ValueError(f"invalid regex: {exc}") from exc


def _codepoint_range(spec: str) -> str:
    bounds = [_parse_codepoint(part, spec) for part in spec.split("-")]
    if len(bounds) == 1:
        return _escape_codepoint(bounds[0])
    if len(bounds) == 2 and bounds[0] <= bounds[1]:
        return f"{_escape_codepoint(bounds[0])}-{_escape_codepoint(bounds[1])}"
    raise ValueError(f"invalid codepoint range {spec!r}")


def _parse_codepoint(part: str, spec: str) -> int:
    match = _CODEPOINT.match(part.strip().upper())
    if not match or int(match.group(1), 16) > 0x10FFFF:
        raise ValueError(f"invalid codepoint {spec!r}: expected U+XXXX or U+XXXX-U+YYYY")
    return int(match.group(1), 16)


def _escape_codepoint(value: int) -> str:
    return f"\\U{value:08x}"


class RulePack(BaseModel):
    """A validated set of rules plus the version recorded in every ScanResult."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    version: NonEmptyStr
    rules: tuple[Rule, ...] = ()

    def for_module(self, module: Module) -> tuple[Rule, ...]:
        """The text-matching rules of ``module`` (``llm`` rules are left out)."""
        return tuple(r for r in self.rules if r.module is module and r.kind != "llm")

    def llm_rules(self) -> tuple[Rule, ...]:
        """The rules the LLM judge reports under, every module."""
        return tuple(rule for rule in self.rules if rule.kind == "llm")


def load_rulepack(path: Path | None = None) -> RulePack:
    """Load the rule pack in directory ``path``, or the bundled pack when ``path`` is None."""
    if path is None:
        with as_file(files("zirah") / "rules") as bundled:
            return _load_dir(Path(bundled))
    return _load_dir(path)


def _load_dir(directory: Path) -> RulePack:
    if not directory.is_dir():
        raise RulePackError(f"{directory}: rule pack directory not found")

    pack_file = directory / PACK_FILE
    pack = _read_yaml(pack_file) if pack_file.is_file() else None
    if not isinstance(pack, dict) or set(pack) != {"version"}:
        raise RulePackError(f"{pack_file}: must contain exactly one key, 'version'")

    rules: list[Rule] = []
    origin: dict[str, Path] = {}
    for rule_file in sorted(directory.glob("*.yaml")):
        if rule_file.name == PACK_FILE:
            continue
        for rule in _load_rule_file(rule_file):
            if rule.id in origin:
                raise RulePackError(
                    f"{rule_file}: duplicate rule id {rule.id!r} (first defined in "
                    f"{origin[rule.id].name})"
                )
            origin[rule.id] = rule_file
            rules.append(rule)

    try:
        return RulePack(version=str(pack["version"]), rules=tuple(rules))
    except ValidationError as exc:
        raise RulePackError(f"{pack_file}: {_first_error(exc)}") from exc


def _load_rule_file(rule_file: Path) -> list[Rule]:
    data = _read_yaml(rule_file)
    if not isinstance(data, dict) or set(data) != {"rules"} or not isinstance(data["rules"], list):
        raise RulePackError(f"{rule_file}: must contain exactly one key, 'rules', holding a list")

    rules = []
    for index, raw in enumerate(data["rules"]):
        label = raw.get("id") if isinstance(raw, dict) else None
        where = f"rule {label!r}" if label else f"rule #{index + 1}"
        try:
            rules.append(Rule.model_validate(raw))
        except ValidationError as exc:
            raise RulePackError(f"{rule_file}: {where}: {_first_error(exc)}") from exc
    return rules


def _read_yaml(path: Path) -> Any:
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise RulePackError(f"{path}: invalid YAML: {exc}") from exc


def _first_error(exc: ValidationError) -> str:
    error = exc.errors()[0]
    field = ".".join(str(part) for part in error["loc"])
    message = error["msg"].removeprefix("Value error, ")
    return f"{field}: {message}" if field else message
