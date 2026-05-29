"""Tests for tools.session — Session state machine."""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import json
import pytest
from tools.session import Session, Status


class TestFreshSession:
    """New session behavior."""

    def test_starts_empty(self):
        s = Session()
        s.reset()
        assert s.get_status() == Status.EMPTY

    def test_has_session_id(self):
        s = Session()
        s.reset()
        assert len(s.get("session_id")) > 0

    def test_no_confirmed_primitives(self):
        s = Session()
        s.reset()
        assert s.get_confirmed_primitives() == []


class TestPhaseWrite:
    """Writing phases and status advancement."""

    def test_write_decomposition(self):
        s = Session()
        s.reset()
        s.write_phase("decomposition", {"primitives": [{"id": "P1"}]})
        assert s.get_status() == Status.DECOMPOSED

    def test_write_telemetry(self):
        s = Session()
        s.reset()
        s.write_phase("telemetry", {"primitives_verified": [{"id": "P1", "table": "DeviceProcessEvents"}]})
        assert s.get_status() == Status.TELEMETRY_CONFIRMED

    def test_write_rules(self):
        s = Session()
        s.reset()
        s.write_phase("rules", {"rules": [{"name": "test"}]})
        assert s.get_status() == Status.RULES_WRITTEN

    def test_confirmed_primitives(self):
        s = Session()
        s.reset()
        s.write_phase("telemetry", {
            "primitives_verified": [
                {"id": "P1", "table": "DeviceProcessEvents", "action_types": ["ProcessCreated"]},
                {"id": "P7", "table": "DeviceNetworkEvents", "action_types": ["ConnectionSuccess"]},
            ]
        })
        confirmed = s.get_confirmed_primitives()
        assert len(confirmed) == 2
        tables = s.get_confirmed_tables()
        assert "DeviceProcessEvents" in tables
        assert "DeviceNetworkEvents" in tables


class TestExpiry:
    """Session auto-expiry."""

    def test_fresh_session_not_expired(self):
        s = Session(max_age_hours=24)
        s.reset()
        assert s.get_status() == Status.EMPTY


class TestPhaseRead:
    """Reading prior phases."""

    def test_get_phase(self):
        s = Session()
        s.reset()
        s.write_phase("telemetry", {"test": True})
        phase = s.get_phase("telemetry")
        assert phase["data"]["test"] is True
        assert "timestamp" in phase


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
