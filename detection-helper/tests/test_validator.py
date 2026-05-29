"""Tests for tools.validator — CrossAgentValidator gate.

Covers the cases where bugs previously hid: a rule that is more confident than
its telemetry, schema-invalid columns, anti-patterns, and a missing resolver.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from tools.validator import CrossAgentValidator, RuleProposal, _level_num


class StubResolver:
    """Minimal resolver: columns valid unless listed, optional anti-patterns."""

    def __init__(self, invalid=None, antipattern=None, action_types=None):
        self._invalid = set(invalid or [])
        self._antipattern = antipattern or []
        self._action_types = action_types or ["ProcessCreated"]

    def validate_columns(self, columns, table):
        valid, invalid = [], []
        for c in columns:
            if c in self._invalid:
                invalid.append({"column": c, "suggestion": "none"})
            else:
                valid.append({"column": c})
        return {"valid": valid, "invalid": invalid, "antipattern": self._antipattern}

    def list_all_action_types(self):
        return self._action_types


def _session(primitive="P1", table="DeviceProcessEvents",
             action_types=("ProcessCreated",), confidence="L4"):
    return {
        "phases": {
            "decomposition": {"data": {"primitives": [{"id": primitive}]}},
            "telemetry": {"data": {"primitives_verified": [{
                "id": primitive,
                "table": table,
                "action_types": list(action_types),
                "confidence_level": confidence,
            }]}},
        }
    }


def _rule(confidence="L3", columns=("FileName",)):
    return RuleProposal(
        table="DeviceProcessEvents",
        action_type="ProcessCreated",
        columns=list(columns),
        primitive="P1",
        confidence=confidence,
    )


class TestLevelParsing:
    def test_plain(self):
        assert _level_num("L3") == 3

    def test_labelled(self):
        assert _level_num("L4: Tenant-Observed") == 4

    def test_unparseable_is_conservative(self):
        assert _level_num("unknown") == 1


class TestConfidenceReconciliation:
    def test_rule_more_confident_than_telemetry_fails(self):
        v = CrossAgentValidator(_session(confidence="L3"), StubResolver())
        result = v.validate(_rule(confidence="L4"))
        assert not result.passed
        assert any("exceeds telemetry" in d for d in result.discrepancies)

    def test_rule_within_telemetry_passes(self):
        v = CrossAgentValidator(_session(confidence="L4"), StubResolver())
        result = v.validate(_rule(confidence="L3"))
        assert result.passed, result.discrepancies

    def test_equal_confidence_passes(self):
        v = CrossAgentValidator(_session(confidence="L3"), StubResolver())
        result = v.validate(_rule(confidence="L3"))
        assert result.passed, result.discrepancies


class TestSchemaChecks:
    def test_invalid_column_fails(self):
        v = CrossAgentValidator(_session(), StubResolver(invalid=["Bogus"]))
        result = v.validate(_rule(columns=["FileName", "Bogus"]))
        assert not result.passed
        assert any("Bogus" in d for d in result.discrepancies)

    def test_antipattern_fails(self):
        ap = [{"column": "ProcessName", "use": "FileName"}]
        v = CrossAgentValidator(_session(), StubResolver(antipattern=ap))
        result = v.validate(_rule(columns=["ProcessName"]))
        assert not result.passed
        assert any("anti-pattern" in d for d in result.discrepancies)


class TestResolverRequired:
    def test_missing_resolver_not_passed(self):
        v = CrossAgentValidator(_session(), resolver=None)
        result = v.validate(_rule())
        assert not result.passed
        assert any("resolver" in d.lower() for d in result.discrepancies)


class TestSessionConsistency:
    def test_wrong_table_fails(self):
        v = CrossAgentValidator(_session(table="DeviceFileEvents"), StubResolver())
        result = v.validate(_rule())  # rule uses DeviceProcessEvents
        assert not result.passed
        assert any("not confirmed in session" in d for d in result.discrepancies)

    def test_unknown_primitive_fails(self):
        v = CrossAgentValidator(_session(primitive="P1"), StubResolver())
        rule = _rule()
        rule.primitive = "P9"
        result = v.validate(rule)
        assert not result.passed
        assert any("decomposition phase" in d for d in result.discrepancies)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
