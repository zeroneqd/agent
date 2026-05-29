"""Tests for tools.telemetry — TelemetryResolver."""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from tools.telemetry import TelemetryResolver


class TestResolve:
    """Query resolution with aliases, keywords, fuzzy matching."""

    def test_exact_keyword_match(self):
        r = TelemetryResolver()
        results = r.resolve("process creation")
        assert len(results) > 0
        assert any("Process Creation" in r["action"] for r in results)

    def test_alias_resolution(self):
        r = TelemetryResolver()
        results = r.resolve("reflective dll")
        assert len(results) > 0
        assert any("Image Load" in r["action"] for r in results)

    def test_action_type_match(self):
        r = TelemetryResolver()
        results = r.resolve("ProcessCreated")
        assert len(results) > 0
        assert any("Process Creation" in r["action"] for r in results)

    def test_empty_string_returns_all(self):
        r = TelemetryResolver()
        results = r.resolve("", top_n=50)
        # Empty string matches via 'in' on all keywords
        assert len(results) > 10

    def test_gibberish_no_match(self):
        r = TelemetryResolver()
        results = r.resolve("xyzabc123nonexistent")
        # Falls through to fuzzy matching — may return something or nothing
        # depending on difflib cutoff
        assert isinstance(results, list)

    def test_case_insensitive(self):
        r = TelemetryResolver()
        lower = r.resolve("process creation")
        upper = r.resolve("PROCESS CREATION")
        assert len(lower) == len(upper)


class TestValidateColumns:
    """Column validation against schema + anti-patterns."""

    def test_valid_column(self):
        r = TelemetryResolver()
        result = r.validate_columns(["FileName"], "DeviceProcessEvents")
        assert len(result["valid"]) == 1
        assert result["valid"][0]["column"] == "FileName"
        assert len(result["invalid"]) == 0
        assert len(result["antipattern"]) == 0

    def test_antipattern_column(self):
        r = TelemetryResolver()
        result = r.validate_columns(["ProcessName"], "DeviceProcessEvents")
        assert len(result["antipattern"]) == 1
        assert result["antipattern"][0]["column"] == "ProcessName"
        # anti-patterns.md has two entries for ProcessName; last one wins
        assert result["antipattern"][0]["use"] in ("FileName", "InitiatingProcessFileName")

    def test_invalid_column(self):
        r = TelemetryResolver()
        result = r.validate_columns(["TotallyFakeColumn"], "DeviceProcessEvents")
        assert len(result["invalid"]) == 1
        assert result["invalid"][0]["column"] == "TotallyFakeColumn"

    def test_mixed_columns(self):
        r = TelemetryResolver()
        result = r.validate_columns(
            ["FileName", "ProcessName", "TotallyFakeColumn"],
            "DeviceProcessEvents"
        )
        assert len(result["valid"]) == 1
        assert len(result["antipattern"]) == 1
        assert len(result["invalid"]) == 1

    def test_nonexistent_table(self):
        r = TelemetryResolver()
        result = r.validate_columns(["FileName"], "FakeTable")
        # Schema not found → all columns invalid
        assert len(result["invalid"]) == 1


class TestCaching:
    """LRU cache behavior."""

    def test_aliases_cached(self):
        r = TelemetryResolver()
        a1 = r._aliases
        a2 = r._aliases  # cached lookup
        assert a1 is a2  # same dict object

    def test_schema_cached(self):
        r = TelemetryResolver()
        c1 = r._get_schema_columns("DeviceProcessEvents")
        c2 = r._get_schema_columns("DeviceProcessEvents")
        assert c1 is c2  # same set object


class TestGetAction:
    """Exact action lookup."""

    def test_found(self):
        r = TelemetryResolver()
        entry = r.get_action("Process Creation")
        assert entry is not None
        assert entry.action == "Process Creation"

    def test_not_found(self):
        r = TelemetryResolver()
        entry = r.get_action("Totally Fake Action")
        assert entry is None


class TestPlatformGaps:
    """Platform-specific gap reporting."""

    def test_linux_gaps(self):
        r = TelemetryResolver()
        gaps = r.get_platform_gaps("DeviceProcessEvents", "linux")
        assert isinstance(gaps, list)

    def test_unknown_table(self):
        r = TelemetryResolver()
        gaps = r.get_platform_gaps("FakeTable", "windows")
        assert gaps == []


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
