"""Tests for tools.router — route()."""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from tools.router import route, Agent


class TestCVERouting:
    """CVE IDs and URLs go to threat-translator."""

    def test_cve_id(self):
        d = route("CVE-2024-1234")
        assert d.agent == Agent.THREAT_TRANSLATOR.value

    def test_cve_lowercase(self):
        d = route("cve-2024-1234")
        assert d.agent == Agent.THREAT_TRANSLATOR.value

    def test_url(self):
        d = route("Check this https://example.com/threat-report")
        assert d.agent == Agent.THREAT_TRANSLATOR.value


class TestTelemetryRouting:
    """Telemetry questions go to defender-telemetry."""

    def test_is_logged(self):
        d = route("Is process creation logged?")
        assert d.agent == Agent.DEFENDER_TELEMETRY.value

    def test_which_table(self):
        d = route("Which table for registry changes?")
        assert d.agent == Agent.DEFENDER_TELEMETRY.value

    def test_column_lookup(self):
        d = route("Which column for command line?")
        assert d.agent == Agent.DEFENDER_TELEMETRY.value


class TestPatternRouting:
    """Known detection patterns go to detection-author."""

    def test_lsass(self):
        d = route("Detect LSASS credential dumping")
        assert d.agent == Agent.DETECTION_AUTHOR.value

    def test_task_abuse(self):
        d = route("Rule for scheduled task abuse")
        assert d.agent == Agent.DETECTION_AUTHOR.value

    def test_process_injection(self):
        d = route("KQL for process injection")
        assert d.agent == Agent.DETECTION_AUTHOR.value


class TestSessionContinuation:
    """Follow-ups with active session."""

    def test_telemetry_confirmed_followup(self):
        d = route("What about Linux?", session_status="telemetry_confirmed")
        assert "telemetry" in d.agent or "author" in d.agent

    def test_decomposed_followup(self):
        d = route("And for Splunk?", session_status="decomposed")
        assert d.agent == Agent.DEFENDER_TELEMETRY.value


class TestAmbiguous:
    """Vague queries ask for clarification."""

    def test_help(self):
        d = route("help")
        assert d.agent == Agent.ASK_CLARIFY.value

    def test_short_vague(self):
        d = route("detection")
        assert d.agent == Agent.ASK_CLARIFY.value


class TestPipelineDepth:
    """Appropriate pipeline depth for each route."""

    def test_cve_is_full_pipeline(self):
        d = route("CVE-2024-1234")
        assert d.pipeline_depth == 3

    def test_telemetry_is_single(self):
        d = route("Is X logged?")
        assert d.pipeline_depth == 1

    def test_pattern_is_single(self):
        d = route("Detect LSASS")
        assert d.pipeline_depth == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
