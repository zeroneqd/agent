"""Tests for tools.primitives — PrimitiveRegistry."""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from tools.primitives import PrimitiveRegistry


class TestGet:
    """Lookup by ID."""

    def test_p1(self):
        p = PrimitiveRegistry()
        info = p.get("P1")
        assert info is not None
        assert info["name"] == "Process Spawn from Exploited Parent"
        assert info["table"] == "DeviceProcessEvents"

    def test_case_insensitive(self):
        p = PrimitiveRegistry()
        assert p.get("p1")["id"] == "P1"

    def test_unknown(self):
        p = PrimitiveRegistry()
        assert p.get("P99") is None

    def test_all_12_exist(self):
        p = PrimitiveRegistry()
        for i in range(1, 13):
            assert p.get(f"P{i}") is not None, f"P{i} missing"


class TestGetByName:
    """Fuzzy name matching."""

    def test_partial_match(self):
        p = PrimitiveRegistry()
        info = p.get_by_name("process spawn")
        assert info is not None
        assert info["id"] == "P1"

    def test_no_match(self):
        p = PrimitiveRegistry()
        assert p.get_by_name("xyzabc") is None


class TestKillChainSorting:
    """Detection priority by kill-chain position."""

    def test_early_before_late(self):
        p = PrimitiveRegistry()
        ordered = p.get_detection_priority(["P10", "P1", "P7"])
        assert ordered[0] == "P1"  # early
        assert ordered[-1] == "P10"  # mid-late

    def test_single(self):
        p = PrimitiveRegistry()
        assert p.get_detection_priority(["P1"]) == ["P1"]


class TestFallback:
    """Proxy detection for blind primitives."""

    def test_p2_fallback(self):
        p = PrimitiveRegistry()
        fb = p.get_fallback("P2")
        assert fb is not None
        assert fb["id"] == "P1"

    def test_no_fallback(self):
        p = PrimitiveRegistry()
        assert p.get_fallback("P1") is None


class TestListAll:
    """Inventory."""

    def test_count(self):
        p = PrimitiveRegistry()
        assert len(p.list_all()) == 12


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
