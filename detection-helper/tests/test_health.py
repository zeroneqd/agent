"""Tests for tools.health — startup validation."""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from tools.health import check


class TestHealthCheck:
    """Full system health check."""

    def test_returns_dict(self):
        result = check()
        assert isinstance(result, dict)
        assert "healthy" in result
        assert "issues" in result

    def test_has_issue_counts(self):
        result = check()
        assert isinstance(result["errors"], int)
        assert isinstance(result["warnings"], int)

    def test_issues_is_list(self):
        result = check()
        assert isinstance(result["issues"], list)

    def test_error_issues_have_severity(self):
        result = check()
        for issue in result["issues"]:
            assert "severity" in issue
            assert "component" in issue
            assert "message" in issue

    def test_resolver_initializes(self):
        """Critical: telemetry resolver must not crash."""
        result = check()
        resolver_issues = [i for i in result["issues"]
                          if i["component"] == "telemetry-resolver"]
        for issue in resolver_issues:
            assert "Failed to initialize" not in issue["message"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
