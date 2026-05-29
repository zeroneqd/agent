"""Structured result types that agents can act on programmatically.

Replaces raw dict returns with dataclasses that have actionable methods.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ValidationResult:
    """Output from CrossAgentValidator with actionable methods."""
    passed: bool
    checks: list[dict] = field(default_factory=list)
    discrepancies: list[str] = field(default_factory=list)
    rule: dict = field(default_factory=dict)

    def halt_message(self) -> Optional[str]:
        """Return natural language halt reason if validation failed.
        LLM includes this directly in its response."""
        if self.passed:
            return None
        lines = ["**VALIDATION HALTED — discrepancies found:**"]
        for d in self.discrepancies:
            lines.append(f"- {d}")
        lines.append("\nResolve these before finalizing the rule.")
        return "\n".join(lines)

    def summary(self) -> str:
        """One-line summary for logging."""
        status = "PASS" if self.passed else "FAIL"
        n = len(self.checks)
        d = len(self.discrepancies)
        return f"Validation {status} ({n} checks, {d} discrepancies)"


@dataclass
class TelemetryResult:
    """Structured output from TelemetryResolver.resolve()."""
    action: str
    tables: list[str] = field(default_factory=list)
    action_types: list[str] = field(default_factory=list)
    columns: list[str] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)
    confidence: str = ""  # L1-L5

    def has_gap_for_platform(self, platform: str) -> bool:
        return any(platform.lower() in g.lower() for g in self.gaps)
