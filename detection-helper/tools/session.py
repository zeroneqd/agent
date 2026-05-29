"""Session State Machine — JSON-based pipeline coordination.

Replaces in LLM prompt: All session state read/write instructions.
Agents call get()/write_phase() instead of parsing markdown.

Usage:
    from tools.session import Session
    s = Session()
    s.write_phase("telemetry", {"primitives_verified": [...]})
    confirmed = s.get_confirmed_primitives()
    status = s.get_status()
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Optional

from tools._base import DOCS_DIR

STATE_PATH = DOCS_DIR / "session" / "state.json"


class Status(Enum):
    EMPTY = "empty"
    DECOMPOSED = "decomposed"
    TELEMETRY_CONFIRMED = "telemetry_confirmed"
    RULES_WRITTEN = "rules_written"
    VALIDATED = "validated"


class Session:
    """Pipeline session state manager."""

    STATUS_ORDER = [
        Status.EMPTY, Status.DECOMPOSED, Status.TELEMETRY_CONFIRMED,
        Status.RULES_WRITTEN, Status.VALIDATED,
    ]

    def __init__(self, max_age_hours: int = 24) -> None:
        self._max_age = timedelta(hours=max_age_hours)
        self._data = self._load()

    # ── Public API ──────────────────────────────────────────────────────

    def get(self, key: str, default: Any = None) -> Any:
        """Read a top-level key."""
        return self._data.get(key, default)

    def get_status(self) -> Status:
        """Current pipeline status."""
        return Status(self._data.get("status", "empty"))

    def get_phase(self, name: str) -> dict:
        """Read a phase by name."""
        return self._data.get("phases", {}).get(name, {})

    def write_phase(self, name: str, data: dict) -> None:
        """Write a phase and auto-advance status."""
        if "phases" not in self._data:
            self._data["phases"] = {}
        self._data["phases"][name] = {
            "timestamp": datetime.now().isoformat(),
            "data": data,
        }
        self._advance_status(name)
        self._save()

    def get_confirmed_primitives(self) -> list[dict]:
        """Return primitives already verified by telemetry agent."""
        telem = self.get_phase("telemetry")
        return telem.get("data", {}).get("primitives_verified", [])

    def get_confirmed_tables(self) -> set[str]:
        """Return set of confirmed table names."""
        return {p.get("table", "") for p in self.get_confirmed_primitives()}

    def get_confirmed_action_types(self) -> set[str]:
        """Return set of confirmed ActionType strings."""
        ats: set[str] = set()
        for p in self.get_confirmed_primitives():
            ats.update(p.get("action_types", []))
        return ats

    def get_confirmed_columns(self) -> set[str]:
        """Return set of confirmed column names."""
        cols: set[str] = set()
        for p in self.get_confirmed_primitives():
            cols.update(p.get("columns", []))
        return cols

    def reset(self) -> None:
        """Start fresh session."""
        self._data = self._fresh()
        self._save()

    def to_dict(self) -> dict:
        """Export full state."""
        return self._data

    # ── Private ─────────────────────────────────────────────────────────

    def _load(self) -> dict:
        try:
            with open(STATE_PATH, encoding="utf-8") as f:
                data = json.load(f)
            created = datetime.fromisoformat(data["created"])
            if datetime.now() - created > self._max_age:
                return self._fresh()
            return data
        except (FileNotFoundError, KeyError, ValueError):
            return self._fresh()

    def _fresh(self) -> dict:
        return {
            "session_id": datetime.now().strftime("%Y%m%d-%H%M%S"),
            "created": datetime.now().isoformat(),
            "updated": datetime.now().isoformat(),
            "status": Status.EMPTY.value,
            "phases": {},
        }

    def _save(self) -> None:
        STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
        self._data["updated"] = datetime.now().isoformat()
        with open(STATE_PATH, "w", encoding="utf-8") as f:
            json.dump(self._data, f, indent=2, default=str)

    def _advance_status(self, phase_name: str) -> None:
        mapping = {
            "decomposition": Status.DECOMPOSED,
            "telemetry": Status.TELEMETRY_CONFIRMED,
            "rules": Status.RULES_WRITTEN,
            "validation": Status.VALIDATED,
        }
        new_status = mapping.get(phase_name)
        if not new_status:
            return
        current = Status(self._data.get("status", "empty"))
        try:
            if self.STATUS_ORDER.index(new_status) > self.STATUS_ORDER.index(current):
                self._data["status"] = new_status.value
        except ValueError:
            pass


# ── CLI ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys, json

    s = Session()

    if len(sys.argv) > 1 and sys.argv[1] == "reset":
        s.reset()
        print("Session reset.")
    elif len(sys.argv) > 1 and sys.argv[1] == "write":
        phase = sys.argv[2] if len(sys.argv) > 2 else "telemetry"
        # Read JSON from stdin
        data = json.load(sys.stdin)
        s.write_phase(phase, data)
        print(f"Phase '{phase}' written. Status: {s.get_status().value}")
    else:
        print(json.dumps(s.to_dict(), indent=2, default=str))
