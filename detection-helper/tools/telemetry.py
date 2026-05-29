"""Telemetry Resolver — deterministic lookup, validation, and anti-pattern checking.

Replaces in LLM prompt:
  - telemetry-index.json keyword search instructions
  - keyword-aliases.md fuzzy matching prose
  - anti-patterns.md manual checking
  - schema column verification checklist
  - platform gap lookups

Usage:
    from tools.telemetry import TelemetryResolver
    r = TelemetryResolver()
    results = r.resolve("process injection")
    valid = r.validate_columns(["FileName", "ProcessName"], "DeviceProcessEvents")
"""

from __future__ import annotations

import functools
import re
from difflib import get_close_matches
from pathlib import Path
from typing import Optional

from tools._base import (
    DOCS_DIR, TelemetryEntry, find_schema_columns, load_json, load_markdown_table,
)


class TelemetryResolver:
    """Central lookup for all telemetry-related queries."""

    def __init__(self) -> None:
        self._index = load_json(DOCS_DIR / "index" / "telemetry-index.json")
        self._actions: list[TelemetryEntry] = [
            TelemetryEntry.from_dict(a) for a in self._index.get("actions", [])
        ]
        self._aliases = self._load_aliases()
        self._antipatterns = self._load_antipatterns()
        self._schema_cache: dict[str, set[str]] = {}

    # ── Public API ──────────────────────────────────────────────────────

    def resolve(self, query: str, top_n: int = 5) -> list[dict]:
        """Resolve a user query to matching telemetry entries.

        Resolution order:
        1. Exact alias match ("reflective dll" → "Image Load")
        2. Keyword match against telemetry-index.json
        3. Action name substring match
        4. ActionType exact match
        5. Fuzzy keyword matching (difflib)
        """
        q = query.lower().strip()

        # 1. Alias resolution
        if q in self._aliases:
            q = self._aliases[q]

        matches: list[tuple[TelemetryEntry, float]] = []

        for entry in self._actions:
            score = self._score(q, entry)
            if score > 0:
                matches.append((entry, score))

        if not matches:
            # 5. Fuzzy fallback
            all_kw = [kw.lower() for a in self._actions for kw in a.keywords]
            close = get_close_matches(q, all_kw, n=top_n, cutoff=0.6)
            for entry in self._actions:
                if any(c in [k.lower() for k in entry.keywords] for c in close):
                    matches.append((entry, 0.3))

        matches.sort(key=lambda x: x[1], reverse=True)
        return [m[0].to_dict() for m in matches[:top_n]]

    def get_action(self, action_name: str) -> Optional[TelemetryEntry]:
        """Get a specific action by exact name."""
        for entry in self._actions:
            if entry.action.lower() == action_name.lower():
                return entry
        return None

    def validate_columns(
        self, columns: list[str], table: str
    ) -> dict[str, list[dict]]:
        """Validate column names against schema + anti-patterns.

        Returns:
            {
                "valid": [{"column": "FileName", "confidence": "L3"}],
                "invalid": [{"column": "ProcessName", "reason": "not in schema"}],
                "antipattern": [{"column": "ProcessName", "use": "FileName"}],
            }
        """
        schema_cols = self._get_schema_columns(table)
        result: dict[str, list[dict]] = {
            "valid": [], "invalid": [], "antipattern": [],
        }

        for col in columns:
            # Check anti-patterns first
            if col in self._antipatterns:
                result["antipattern"].append({
                    "column": col,
                    "use": self._antipatterns[col],
                    "table": table,
                })
                continue

            # Check schema
            if col in schema_cols:
                result["valid"].append({
                    "column": col,
                    "confidence": "L3",
                    "source": f"docs/advanced-hunting/{table.lower()}-table.md",
                })
                continue

            # Suggest correction via fuzzy match
            suggestion = get_close_matches(col, list(schema_cols), n=1, cutoff=0.7)
            result["invalid"].append({
                "column": col,
                "reason": "not in schema",
                "suggestion": suggestion[0] if suggestion else None,
            })

        return result

    def get_platform_gaps(self, table: str, platform: str) -> list[str]:
        """Return known gaps for a table+platform combination."""
        for entry in self._actions:
            if table in entry.tables:
                return entry.gaps if platform.lower() in [
                    "windows", "linux", "macos"
                ] else []
        return []

    def get_table_workload(self, table: str) -> str:
        """Return the workload (MDE/MDI/MDO/etc.) for a table."""
        mapping = self._index.get("quick_reference", {}).get("table_to_workload", {})
        return mapping.get(table, "Unknown")

    def list_all_tables(self) -> list[str]:
        """Return all known table names."""
        tables: set[str] = set()
        for entry in self._actions:
            tables.update(entry.tables)
        return sorted(tables)

    def list_all_action_types(self) -> list[str]:
        """Return all known ActionType strings."""
        ats: set[str] = set()
        for entry in self._actions:
            ats.update(entry.action_types)
        return sorted(ats)

    # ── Private ─────────────────────────────────────────────────────────

    def _score(self, query: str, entry: TelemetryEntry) -> float:
        """Score how well a query matches an entry. Returns 0 if no match."""
        # Exact keyword match
        for kw in entry.keywords:
            if query == kw.lower():
                return 1.0
            if query in kw.lower():
                return 0.8

        # Action name match
        if query in entry.action.lower():
            return 0.7

        # ActionType match
        for at in entry.action_types:
            if query == at.lower():
                return 0.9

        return 0.0

    def _get_schema_columns(self, table: str) -> set[str]:
        """Cached schema column extraction."""
        if table not in self._schema_cache:
            path = DOCS_DIR / "advanced-hunting" / f"advanced-hunting-{table.lower()}-table.md"
            self._schema_cache[table] = find_schema_columns(path)
        return self._schema_cache[table]

    @staticmethod
    @functools.lru_cache(maxsize=1)
    def _load_aliases() -> dict[str, str]:
        """Parse keyword-aliases.md into {alias_lower: canonical_keyword}.
        Cached — file content does not change during a session."""
        aliases: dict[str, str] = {}
        rows = load_markdown_table(DOCS_DIR / "index" / "keyword-aliases.md")
        for row in rows:
            alias = row.get("User says", "").strip('"').strip("`").lower()
            canonical = row.get("Maps to", "").strip('"').strip("`").split("(")[0].strip()
            if alias and canonical and alias not in ("user says", "-"):
                aliases[alias] = canonical
        return aliases

    @staticmethod
    @functools.lru_cache(maxsize=1)
    def _load_antipatterns() -> dict[str, str]:
        """Parse anti-patterns.md into {wrong_column: correct_column}.
        Uses load_markdown_table for robustness against formatting changes."""
        traps: dict[str, str] = {}
        rows = load_markdown_table(DOCS_DIR / "notes" / "anti-patterns.md")
        for row in rows:
            wrong = row.get("Wrong (Do NOT use)", "").strip("`").strip()
            correct = row.get("Correct", "").strip("`").strip()
            if wrong and correct:
                traps[wrong] = correct
        return traps


# ── CLI ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    r = TelemetryResolver()
    query = " ".join(sys.argv[1:]) if len(sys.argv) > 1 else "process creation"
    results = r.resolve(query)
    print(f"Query: {query!r}\nFound {len(results)} match(es):\n")
    for i, m in enumerate(results, 1):
        print(f"  {i}. {m['action']}")
        print(f"     Tables: {', '.join(m['tables'])}")
        print(f"     ActionTypes: {', '.join(m['action_types'])}")
        print(f"     Columns: {', '.join(m['columns'][:8])}{'...' if len(m['columns']) > 8 else ''}")
        print()
