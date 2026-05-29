"""Base classes and shared data models for all tools."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Optional

# Repo root relative to tools/
REPO_ROOT = Path(__file__).resolve().parent.parent
DOCS_DIR = REPO_ROOT / "docs"


class ConfidenceLevel(Enum):
    """Unified L1-L5 confidence ontology. Used by all agents identically."""
    L1_INFERRED = 1
    L2_DOCUMENTED = 2
    L3_SCHEMA = 3
    L4_TENANT = 4
    L5_LIVE = 5

    def label(self) -> str:
        return {
            ConfidenceLevel.L1_INFERRED: "L1: Inferred",
            ConfidenceLevel.L2_DOCUMENTED: "L2: Documented",
            ConfidenceLevel.L3_SCHEMA: "L3: Schema-Confirmed",
            ConfidenceLevel.L4_TENANT: "L4: Tenant-Observed",
            ConfidenceLevel.L5_LIVE: "L5: Live-Verified",
        }[self]


@dataclass
class TelemetryEntry:
    """A single action→table→columns mapping from the telemetry index.
    Ignores unknown fields from JSON to prevent crashes on schema drift."""
    action: str = ""
    keywords: list[str] = field(default_factory=list)
    tables: list[str] = field(default_factory=list)
    action_types: list[str] = field(default_factory=list)
    platforms: dict[str, str] = field(default_factory=dict)
    event_ids: dict[str, list[int]] = field(default_factory=dict)
    columns: list[str] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    prerequisites: list[str] = field(default_factory=list)
    notes: str = ""  # extra field present in some index entries

    @classmethod
    def from_dict(cls, data: dict) -> "TelemetryEntry":
        """Create from dict, ignoring unknown fields."""
        known = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in known}
        return cls(**filtered)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass  
class Evidence:
    """Evidence used to compute confidence level."""
    schema_confirmed: bool = False
    tenant_observed: bool = False
    tenant_date: Optional[str] = None
    live_validated: bool = False
    basis: str = ""

    def to_level(self, freshness_days: int = 14) -> ConfidenceLevel:
        if self.live_validated:
            return ConfidenceLevel.L5_LIVE
        if self.tenant_observed:
            if self.tenant_date:
                parsed = datetime.strptime(self.tenant_date, "%Y-%m-%d")
                if (datetime.now() - parsed) < timedelta(days=freshness_days):
                    return ConfidenceLevel.L4_TENANT
            # Tenant data stale
            return ConfidenceLevel.L3_SCHEMA
        if self.schema_confirmed:
            return ConfidenceLevel.L3_SCHEMA
        if self.basis:
            return ConfidenceLevel.L2_DOCUMENTED
        return ConfidenceLevel.L1_INFERRED


def load_json(path: Path) -> dict:
    """Load JSON file, return empty dict on failure."""
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def load_markdown_table(path: Path, start_marker: str = "|") -> list[dict]:
    """Parse a markdown table into list of dicts."""
    rows = []
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.readlines()
    except FileNotFoundError:
        return rows

    headers: list[str] = []
    for line in lines:
        line = line.strip()
        if not line.startswith("|"):
            continue
        cells = [c.strip().strip("`") for c in line.split("|")[1:-1]]
        if not cells:
            continue
        if "---" in cells[0]:
            continue
        if not headers:
            headers = cells
            continue
        if headers and len(cells) == len(headers):
            rows.append(dict(zip(headers, cells)))
    return rows


def extract_code_blocks(md_text: str, language: str = "kql") -> list[str]:
    """Extract code blocks of a specific language from markdown."""
    pattern = rf"```{language}\n(.*?)\n```"
    return re.findall(pattern, md_text, re.DOTALL)


def find_schema_columns(schema_path: Path) -> set[str]:
    """Extract column names from an advanced-hunting schema markdown file."""
    columns: set[str] = set()
    try:
        with open(schema_path, encoding="utf-8") as f:
            content = f.read()
    except FileNotFoundError:
        return columns

    # Column names appear in schema tables like:
    # | `` `FileName` `` | `` `string` `` | ... |
    # or | `FileName` | string | ... |
    # Match backtick-wrapped column name followed by type column
    pattern = r"\|\s*`{1,2}\s*`?(\w+)`?`{1,2}\s*\|\s*`{0,2}\s*`?(\w+)`?`{0,2}\s*\|"
    for match in re.finditer(pattern, content):
        col_name = match.group(1)
        col_type = match.group(2).lower()
        if col_type in ("string", "int", "long", "datetime",
                        "dynamic", "bool", "double", "guid", "uint"):
            columns.add(col_name)
    return columns
