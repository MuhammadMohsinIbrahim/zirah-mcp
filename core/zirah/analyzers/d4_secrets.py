"""D4 secrets: keys and tokens in the manifest and in the target's location and arguments.

The detections live in ``zirah/rules/d4_secrets.yaml``. Evidence never holds a whole
secret: each finding shows the match with the secret cut to a short prefix plus ``****``.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Sequence

from zirah.analyzers.base import ScanContext
from zirah.analyzers.common import RuleAnalyzer, Span, TextField, redact_match
from zirah.models import Finding, Manifest, Module
from zirah.rulepack import Rule, secret_spans


def shannon_entropy(value: str) -> float:
    """Bits of entropy per character of ``value``; 0 for empty or single-character text."""
    counts = Counter(value)
    total = len(value)
    return -sum(n / total * math.log2(n / total) for n in counts.values()) if total else 0.0


class Secrets(RuleAnalyzer):
    name = "d4-secrets"
    module = Module.D4

    def analyze(self, manifest: Manifest, ctx: ScanContext) -> list[Finding]:
        return self.match_rules(manifest, ctx)

    def accept(
        self, rule: Rule, match: re.Match[str], field: TextField, manifest: Manifest
    ) -> bool:
        if rule.min_entropy is None:
            return True
        return all(
            shannon_entropy(match.string[start:end]) >= rule.min_entropy
            for start, end in secret_spans(match)
        )

    def snippet(self, rule: Rule, match: re.Match[str], secrets: Sequence[Span]) -> str:
        return redact_match(match)
