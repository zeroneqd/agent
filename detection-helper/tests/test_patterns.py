"""Tests for tools.patterns — PatternComposer."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.patterns import PatternComposer


class TestComposeSequence:
    """compose_sequence() input handling and assembly."""

    def test_empty_returns_error(self):
        assert PatternComposer().compose_sequence([]).startswith("// ERROR")

    def test_single_primitive_returns_fragment_kql(self):
        # P1 has a fragment file; single id returns its core block (non-empty, no sequence scaffold).
        out = PatternComposer().compose_sequence(["P1"])
        assert out
        assert "let TimeWindow" not in out

    def test_two_primitives_build_sequence(self):
        out = PatternComposer().compose_sequence(["P1", "P7"], window_minutes=10)
        assert "Sequence: P1 → P7" in out
        assert "let TimeWindow = 10m;" in out
        assert "join kind=inner" in out

    def test_three_primitives_use_generic_fallback(self):
        out = PatternComposer().compose_sequence(["P1", "P7", "P11"])
        assert "Multi-primitive sequence" in out
        assert "P1 → P7 → P11" in out


class TestComposeFallback:
    """compose_fallback() works even without fragment files."""

    def test_structure(self):
        out = PatternComposer().compose_fallback("P2", "P1")
        assert "Primary: P2" in out
        assert "Fallback: P1" in out
        assert "union" in out

    def test_unknown_primitive_is_annotated(self):
        out = PatternComposer().compose_fallback("P99", "P98")
        assert "No fragment for P99" in out
        assert "No fragment for P98" in out


class TestListAvailableFragments:
    def test_returns_sorted_unique_pids(self):
        frags = PatternComposer().list_available_fragments()
        assert frags == sorted(set(frags))
        # Repo ships 12 primitive fragments (P1–P12).
        assert "P1" in frags
        assert all(f.startswith("P") for f in frags)


class TestExtractionHelpers:
    """Static parsing helpers are pure and file-independent."""

    def test_extract_where_collects_clauses_and_stops_at_project(self):
        kql = (
            "DeviceProcessEvents\n"
            "| where ActionType == \"ProcessCreated\"\n"
            "| where FileName == \"x.exe\"\n"
            "| project FileName, DeviceId"
        )
        where = PatternComposer._extract_where(kql)
        assert "ActionType" in where
        assert "x.exe" in where
        assert "project" not in where

    def test_extract_where_defaults_when_none(self):
        assert PatternComposer._extract_where("DeviceEvents\n| summarize count()") == "| where true"

    def test_extract_table_returns_first_bare_table(self):
        kql = "// comment\nDeviceNetworkEvents\n| where RemotePort == 443"
        assert PatternComposer._extract_table(kql) == "DeviceNetworkEvents"

    def test_extract_table_defaults_when_absent(self):
        assert PatternComposer._extract_table("| where true") == "DeviceEvents"

    def test_indent_prefixes_each_line(self):
        assert PatternComposer._indent("a\nb") == "    a\n    b"
