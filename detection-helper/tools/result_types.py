"""Structured result types that agents can act on programmatically.

Replaces raw dict returns with dataclasses that have actionable methods.

New: PrimitiveMatchResult — output from the LLM primitive identification layer.
     TelemetryResult now includes rationale for LLM explainability.
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

    @staticmethod
    def batch_summary(results: list[ValidationResult]) -> str:
        """Summarize a batch of validation results."""
        passed = sum(1 for r in results if r.passed)
        total = len(results)
        all_disc = [d for r in results for d in r.discrepancies]
        return (
            f"Batch validation: {passed}/{total} passed | "
            f"{len(all_disc)} total discrepancies"
        )


@dataclass
class PrimitiveMatchResult:
    """Output from the LLM primitive identification layer.

    The LLM receives a list of telemetry primitives (from
    TelemetryPrimitiveResolver.format_for_prompt()) and returns this
    structure indicating which primitives match the user prompt.

    The rationale field captures the LLM's reasoning for debugging and
    audit — essential when the selection is unexpected.
    """
    selected_primitives: list[str] = field(default_factory=list)
    rationale: str = ""
    mapped_actions: list[str] = field(default_factory=list)
    rejected_primitives: list[str] = field(default_factory=list)
    confidence: str = ""  # L1-L5

    def summary(self) -> str:
        """One-line summary for logging."""
        n = len(self.selected_primitives)
        actions = ", ".join(self.mapped_actions[:3])
        if len(self.mapped_actions) > 3:
            actions += f" +{len(self.mapped_actions) - 3} more"
        return f"PrimitiveMatch ({n} primitives → {actions})"

    def to_prompt_context(self) -> str:
        """Format as concise context for downstream LLM prompts."""
        lines = [f"Selected telemetry primitives: {', '.join(self.selected_primitives)}"]
        if self.rationale:
            lines.append(f"Rationale: {self.rationale}")
        if self.mapped_actions:
            lines.append(f"Mapped actions: {', '.join(self.mapped_actions)}")
        return "\n".join(lines)


@dataclass
class TelemetryResult:
    """Structured output from TelemetryResolver after primitive resolution.

    Represents a single telemetry action with its full schema details.
    For batch results, use a list[TelemetryResult] or the convenience
    batch_summary() method.
    """
    action: str
    tables: list[str] = field(default_factory=list)
    action_types: list[str] = field(default_factory=list)
    columns: list[str] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)
    confidence: str = ""  # L1-L5
    rationale: str = ""  # NEW: why this action was selected from primitives

    def has_gap_for_platform(self, platform: str) -> bool:
        return any(platform.lower() in g.lower() for g in self.gaps)

    @staticmethod
    def batch_summary(results: list[TelemetryResult]) -> str:
        """Summarize a batch of results for logging or LLM context."""
        if not results:
            return "No telemetry results."
        actions = ", ".join(r.action for r in results)
        tables = sorted({t for r in results for t in r.tables})
        return (
            f"Telemetry: {len(results)} action(s) → {actions} | "
            f"Tables: {', '.join(tables)}"
        )
