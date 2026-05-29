"""Confidence Engine — deterministic L1-L5 calculation.

Replaces in LLM prompt: 59 lines of shared-confidence.md prose.
Every factual claim gets a computable confidence level.

Auto-detects tenant data freshness from filesystem if tenant_date not provided.

Usage:
    from tools.confidence import Evidence, compute_level, format_level, compute_rule_level
    e = Evidence(schema_confirmed=True)
    level = compute_level(e)
    # → ConfidenceLevel.L3_SCHEMA
    rule_level = compute_rule_level([e1, e2, e3])
    # → min of all levels
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from tools._base import ConfidenceLevel, DOCS_DIR


@dataclass
class Evidence:
    """Evidence supporting a factual claim.
    
    Auto-detects tenant data age from filesystem when tenant_date not set.
    """
    schema_confirmed: bool = False
    tenant_observed: bool = False
    tenant_date: Optional[str] = None
    live_validated: bool = False
    basis: str = ""
    freshness_days: int = 14

    def level(self) -> ConfidenceLevel:
        if self.live_validated:
            return ConfidenceLevel.L5_LIVE
        if self.tenant_observed:
            date = self.tenant_date or self._detect_tenant_date()
            if date:
                try:
                    parsed = datetime.strptime(date, "%Y-%m-%d")
                    age = (datetime.now() - parsed).days
                    if age < self.freshness_days:
                        return ConfidenceLevel.L4_TENANT
                except ValueError:
                    pass
            return ConfidenceLevel.L3_SCHEMA  # stale or undated tenant data
        if self.schema_confirmed:
            return ConfidenceLevel.L3_SCHEMA
        if self.basis:
            return ConfidenceLevel.L2_DOCUMENTED
        return ConfidenceLevel.L1_INFERRED

    @staticmethod
    def _detect_tenant_date() -> Optional[str]:
        """Read tenant data file mtime as fallback date."""
        tenant_path = DOCS_DIR / "tenant" / "all-actiontypes.md"
        try:
            mtime = datetime.fromtimestamp(tenant_path.stat().st_mtime)
            return mtime.strftime("%Y-%m-%d")
        except (FileNotFoundError, OSError):
            return None


def compute_level(evidence: Evidence) -> ConfidenceLevel:
    """Single evidence → confidence level."""
    return evidence.level()


def compute_rule_level(evidence_list: list[Evidence]) -> ConfidenceLevel:
    """Rule confidence = minimum of all element confidences."""
    if not evidence_list:
        return ConfidenceLevel.L1_INFERRED
    levels = [e.level() for e in evidence_list]
    return min(levels, key=lambda l: l.value)


def format_level(level: ConfidenceLevel, basis: str = "") -> str:
    """Consistent confidence formatting for all agents."""
    result = level.label()
    if basis and level in (ConfidenceLevel.L1_INFERRED, ConfidenceLevel.L2_DOCUMENTED):
        result += f" — {basis}"
    return result


def validate_claim(
    claim: str,
    evidence: Evidence,
    min_level: ConfidenceLevel = ConfidenceLevel.L3_SCHEMA,
) -> dict:
    """Validate a single claim against minimum confidence.

    Returns:
        {"pass": True/False, "claim": "...", "actual": "L3", "required": "L3"}
    """
    actual = evidence.level()
    return {
        "pass": actual.value >= min_level.value,
        "claim": claim,
        "actual": actual.label(),
        "required": min_level.label(),
    }


# ── CLI ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys, json

    # Parse flags: --schema, --tenant YYYY-MM-DD, --live
    evidence = Evidence()
    args = sys.argv[1:]
    if "--schema" in args:
        evidence.schema_confirmed = True
    if "--tenant" in args:
        idx = args.index("--tenant")
        evidence.tenant_observed = True
        evidence.tenant_date = args[idx + 1] if idx + 1 < len(args) else "2026-05-28"
    if "--live" in args:
        evidence.live_validated = True

    level = compute_level(evidence)
    print(json.dumps({
        "level": level.name,
        "label": level.label(),
        "evidence": {
            "schema_confirmed": evidence.schema_confirmed,
            "tenant_observed": evidence.tenant_observed,
            "tenant_date": evidence.tenant_date,
            "live_validated": evidence.live_validated,
        },
    }, indent=2))
