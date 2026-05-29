"""Cross-Agent Validator — programmatic reconciliation before rule finalization.

Replaces in LLM prompt: 98 lines of shared-validation.md prose.
Runs 5 deterministic checks, returns structured pass/fail report.

A resolver is REQUIRED for a meaningful gate: it backs the column-validity and
anti-pattern checks. Without it, those checks cannot run and the rule is treated
as not-passed (the gate refuses to vouch for an unverified rule).

Supports both single-rule and batch validation.  Use validate_batch() when
the LLM has identified multiple primitives and generated multiple rules.

Usage:
    from tools.validator import CrossAgentValidator, RuleProposal
    v = CrossAgentValidator(session, resolver)

    # Single rule
    result = v.validate(RuleProposal(table="DeviceProcessEvents", ..., confidence="L3"))
    if not result.passed:
        print(result.halt_message())

    # Batch — after LLM identifies multiple primitives
    rules = [
        RuleProposal(table="DeviceProcessEvents", ..., primitive="P1"),
        RuleProposal(table="DeviceEvents", ..., primitive="P2"),
    ]
    results = v.validate_batch(rules)
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from tools._base import ConfidenceLevel
from tools.result_types import ValidationResult


def _level_num(level: str) -> int:
    """Parse a confidence level like 'L3' or 'L4: Tenant-Observed' into its int.
    Unparseable values fall back to 1 (most conservative)."""
    m = re.search(r"[Ll]\s*(\d+)", str(level))
    return int(m.group(1)) if m else 1


@dataclass
class RuleProposal:
    """A detection rule before validation."""
    table: str
    action_type: str
    columns: list[str]
    primitive: str  # P1-P12
    confidence: str = "L3"  # the rule's own confidence (e.g. "L3", "L4")


class CrossAgentValidator:
    """5-step validation gate. Any failure halts the rule.
    Returns ValidationResult with actionable .halt_message() method.

    Pass a resolver (TelemetryResolver) so column and anti-pattern checks can
    run; without one the gate reports the rule as not-passed."""

    def __init__(self, session_data: dict, resolver=None) -> None:
        self.session = session_data or {}
        self.resolver = resolver

    def validate(self, rule: RuleProposal) -> ValidationResult:
        """Run all 5 checks. Returns ValidationResult with actionable methods."""
        checks: list[dict] = []
        discrepancies: list[str] = []
        rule_dict = {
            "table": rule.table,
            "action_type": rule.action_type,
            "columns": rule.columns,
            "primitive": rule.primitive,
            "confidence": rule.confidence,
        }

        # 1. Table matches session telemetry
        self._check_table(checks, discrepancies, rule)

        # 2. ActionType exact match
        self._check_action_type(checks, discrepancies, rule)

        # 3. Columns in schema + anti-pattern check (both require a resolver)
        self._check_columns(checks, discrepancies, rule)

        # 4. Primitive consistency
        self._check_primitive(checks, discrepancies, rule)

        # 5. Confidence reconciliation
        self._check_confidence(checks, discrepancies, rule)

        passed = len(discrepancies) == 0
        return ValidationResult(
            passed=passed,
            checks=checks,
            discrepancies=discrepancies,
            rule=rule_dict,
        )

    def validate_batch(self, rules: list[RuleProposal]) -> list[ValidationResult]:
        """Validate multiple rules.  Each rule runs independently.

        Returns results in the same order as the input list.
        """
        return [self.validate(rule) for rule in rules]

    def _check_table(self, checks: list, discrepancies: list, rule: RuleProposal) -> None:
        phase2 = self.session.get("phases", {}).get("telemetry", {})
        verified = phase2.get("data", {}).get("primitives_verified", [])
        session_tables = {v.get("table") for v in verified}

        if not session_tables:
            checks.append({
                "check": "table_matches_session",
                "status": "SKIP",
                "reason": "No telemetry phase in session",
            })
            return

        if rule.table not in session_tables:
            checks.append({
                "check": "table_matches_session",
                "status": "FAIL",
                "expected": sorted(session_tables),
                "got": rule.table,
            })
            discrepancies.append(
                f"Table '{rule.table}' not confirmed in session. "
                f"Confirmed tables: {', '.join(sorted(session_tables))}"
            )
        else:
            checks.append({
                "check": "table_matches_session",
                "status": "PASS",
            })

    def _check_action_type(self, checks: list, discrepancies: list, rule: RuleProposal) -> None:
        phase2 = self.session.get("phases", {}).get("telemetry", {})
        verified = phase2.get("data", {}).get("primitives_verified", [])
        session_ats: set[str] = set()
        for v in verified:
            session_ats.update(v.get("action_types", []))

        if not session_ats:
            if self.resolver:
                index_ats = self.resolver.list_all_action_types()
                if rule.action_type not in index_ats:
                    discrepancies.append(
                        f"ActionType '{rule.action_type}' not in telemetry index"
                    )
            checks.append({
                "check": "action_type_exact_match",
                "status": "SKIP",
                "reason": "No session ActionTypes",
            })
            return

        if rule.action_type not in session_ats:
            checks.append({
                "check": "action_type_exact_match",
                "status": "FAIL",
                "expected_in_session": sorted(session_ats),
                "got": rule.action_type,
            })
            discrepancies.append(
                f"ActionType '{rule.action_type}' not in session. "
                f"Confirmed: {', '.join(sorted(session_ats))}"
            )
        else:
            checks.append({
                "check": "action_type_exact_match",
                "status": "PASS",
            })

    def _check_columns(self, checks: list, discrepancies: list, rule: RuleProposal) -> None:
        if self.resolver:
            result = self.resolver.validate_columns(rule.columns, rule.table)
            if result["invalid"]:
                for inv in result["invalid"]:
                    discrepancies.append(
                        f"Column '{inv['column']}' not in schema "
                        f"(suggestion: {inv.get('suggestion', 'none')})"
                    )
                checks.append({
                    "check": "columns_in_schema",
                    "status": "FAIL",
                    "invalid": result["invalid"],
                })
            else:
                checks.append({
                    "check": "columns_in_schema",
                    "status": "PASS",
                    "valid": [v["column"] for v in result["valid"]],
                })

            if result["antipattern"]:
                for ap in result["antipattern"]:
                    discrepancies.append(
                        f"Column '{ap['column']}' is anti-pattern — use '{ap['use']}'"
                    )
                checks.append({
                    "check": "anti_pattern_check",
                    "status": "FAIL",
                    "matches": result["antipattern"],
                })
        else:
            checks.append({
                "check": "columns_in_schema",
                "status": "FAIL",
                "reason": "No resolver available — columns cannot be verified",
            })
            discrepancies.append(
                "No schema resolver provided — columns and anti-patterns "
                "cannot be verified. Pass a TelemetryResolver to validate the rule."
            )

    def _check_primitive(self, checks: list, discrepancies: list, rule: RuleProposal) -> None:
        phase1 = self.session.get("phases", {}).get("decomposition", {})
        session_prims = {p.get("id") for p in phase1.get("data", {}).get("primitives", [])}

        if not session_prims:
            checks.append({
                "check": "primitive_consistency",
                "status": "SKIP",
            })
            return

        if rule.primitive not in session_prims:
            discrepancies.append(
                f"Primitive '{rule.primitive}' not in decomposition phase. "
                f"Decomposed: {', '.join(sorted(session_prims))}"
            )
            checks.append({
                "check": "primitive_consistency",
                "status": "FAIL",
            })
        else:
            checks.append({
                "check": "primitive_consistency",
                "status": "PASS",
            })

    def _check_confidence(self, checks: list, discrepancies: list, rule: RuleProposal) -> None:
        phase2 = self.session.get("phases", {}).get("telemetry", {})
        telem_prims = phase2.get("data", {}).get("primitives_verified", [])

        for p in telem_prims:
            if rule.primitive == p.get("id"):
                telem_level = p.get("confidence_level", "L1")
                if _level_num(rule.confidence) > _level_num(telem_level):
                    discrepancies.append(
                        f"Rule confidence ({rule.confidence}) exceeds telemetry "
                        f"confidence ({telem_level}) for {rule.primitive} — a rule "
                        f"cannot be more confident than its underlying telemetry"
                    )
                    checks.append({
                        "check": "confidence_reconciliation",
                        "status": "FAIL",
                        "rule_confidence": rule.confidence,
                        "telemetry_confidence": telem_level,
                    })
                else:
                    checks.append({
                        "check": "confidence_reconciliation",
                        "status": "PASS",
                        "rule_confidence": rule.confidence,
                        "telemetry_confidence": telem_level,
                    })
                return

        checks.append({
            "check": "confidence_reconciliation",
            "status": "SKIP",
        })


# ── CLI ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys, json

    from tools.session import Session
    from tools.telemetry import TelemetryResolver

    s = Session()
    r = TelemetryResolver()
    v = CrossAgentValidator(s.to_dict(), r)

    if len(sys.argv) >= 5:
        rule = RuleProposal(
            table=sys.argv[1],
            action_type=sys.argv[2],
            columns=sys.argv[3].split(","),
            primitive=sys.argv[4],
            confidence=sys.argv[5] if len(sys.argv) >= 6 else "L3",
        )
        result = v.validate(rule)
        print(json.dumps({
            "passed": result.passed,
            "checks": result.checks,
            "discrepancies": result.discrepancies,
            "rule": result.rule,
        }, indent=2))
    else:
        print("Usage: python -m tools.validator <table> <action_type> <col1,col2> <primitive> [confidence]")
