"""Tests for tools.confidence — L1-L5 calculation."""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from tools.confidence import (
    Evidence, compute_level, compute_rule_level,
    format_level, validate_claim, ConfidenceLevel,
)


class TestEvidenceLevel:
    """Evidence → ConfidenceLevel mapping."""

    def test_live_validated_is_l5(self):
        e = Evidence(live_validated=True)
        assert compute_level(e) == ConfidenceLevel.L5_LIVE

    def test_fresh_tenant_is_l4(self):
        from datetime import datetime
        today = datetime.now().strftime("%Y-%m-%d")
        e = Evidence(tenant_observed=True, tenant_date=today)
        assert compute_level(e) == ConfidenceLevel.L4_TENANT

    def test_stale_tenant_downgrades_to_l3(self):
        e = Evidence(tenant_observed=True, tenant_date="2020-01-01")
        assert compute_level(e) == ConfidenceLevel.L3_SCHEMA

    def test_schema_only_is_l3(self):
        e = Evidence(schema_confirmed=True)
        assert compute_level(e) == ConfidenceLevel.L3_SCHEMA

    def test_documented_is_l2(self):
        e = Evidence(basis="Microsoft Docs reference")
        assert compute_level(e) == ConfidenceLevel.L2_DOCUMENTED

    def test_nothing_is_l1(self):
        e = Evidence()
        assert compute_level(e) == ConfidenceLevel.L1_INFERRED


class TestRuleLevel:
    """Rule confidence = min of all elements."""

    def test_single_element(self):
        e = Evidence(schema_confirmed=True)
        assert compute_rule_level([e]) == ConfidenceLevel.L3_SCHEMA

    def test_min_of_multiple(self):
        e1 = Evidence(schema_confirmed=True)  # L3
        e2 = Evidence(live_validated=True)     # L5
        assert compute_rule_level([e1, e2]) == ConfidenceLevel.L3_SCHEMA

    def test_empty_list_is_l1(self):
        assert compute_rule_level([]) == ConfidenceLevel.L1_INFERRED


class TestFormatLevel:
    """Output formatting."""

    def test_l5_format(self):
        assert "Live-Verified" in format_level(ConfidenceLevel.L5_LIVE)

    def test_l1_with_basis(self):
        result = format_level(ConfidenceLevel.L1_INFERRED, basis="from pattern")
        assert "L1" in result
        assert "from pattern" in result


class TestValidateClaim:
    """Claim validation against minimum level."""

    def test_passes(self):
        e = Evidence(schema_confirmed=True)
        result = validate_claim("FileName column", e, ConfidenceLevel.L3_SCHEMA)
        assert result["pass"] is True

    def test_fails(self):
        e = Evidence()  # L1
        result = validate_claim("FileName column", e, ConfidenceLevel.L3_SCHEMA)
        assert result["pass"] is False


class TestFreshness:
    """Tenant data age affects confidence."""

    def test_custom_freshness_days(self):
        e = Evidence(tenant_observed=True, tenant_date="2026-05-01")
        # With 14-day default, May 1 data is stale (today is May 28)
        assert e.level() == ConfidenceLevel.L3_SCHEMA

    def test_very_fresh_tenant(self):
        from datetime import datetime, timedelta
        yesterday = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
        e = Evidence(tenant_observed=True, tenant_date=yesterday)
        assert e.level() == ConfidenceLevel.L4_TENANT


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
