"""Health Check — validates the entire tool chain on startup.

Replaces silent degradation with explicit diagnostics. Run before first query.

Usage:
    from tools.health import check
    report = check()
    if not report["healthy"]:
        print(report["issues"])
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from tools._base import DOCS_DIR, REPO_ROOT


@dataclass
class HealthIssue:
    severity: str  # error | warning
    component: str
    message: str


def check() -> dict:
    """Run full health check. Returns {healthy: bool, issues: list}."""
    issues: list[HealthIssue] = []

    # 1. Core JSON files exist and parse
    _check_json(issues, DOCS_DIR / "index" / "telemetry-index.json", "Telemetry index")
    _check_json(issues, DOCS_DIR / "session" / "state.json", "Session state", optional=True)

    # 2. Key markdown files exist
    _check_file(issues, DOCS_DIR / "schema-overview.md", "Schema overview")
    _check_file(issues, DOCS_DIR / "decision-matrix.md", "Decision matrix")
    _check_file(issues, DOCS_DIR / "notes" / "anti-patterns.md", "Anti-patterns")
    _check_file(issues, DOCS_DIR / "index" / "keyword-aliases.md", "Keyword aliases")

    # 3. Tenant data freshness
    _check_freshness(issues, DOCS_DIR / "tenant" / "all-actiontypes.md", days=14)

    # 4. Tools Python modules exist
    tools_dir = REPO_ROOT / "tools"
    for mod in ["telemetry", "router", "confidence", "session",
                "patterns", "validator", "primitives", "health"]:
        _check_file(issues, tools_dir / f"{mod}.py", f"tools.{mod}")

    # 5. Telemetry index has actions
    idx = _load_json_safe(DOCS_DIR / "index" / "telemetry-index.json")
    actions = idx.get("actions", [])
    if len(actions) < 10:
        issues.append(HealthIssue("error", "telemetry-index",
            f"Only {len(actions)} actions in index (expected 30+)"))
    else:
        # Check for entries with unknown fields that would crash old code
        all_keys: set[str] = set()
        for a in actions:
            all_keys.update(a.keys())
        expected = {"action", "keywords", "tables", "action_types", "platforms",
                   "event_ids", "columns", "gaps", "files", "prerequisites", "notes"}
        unknown = all_keys - expected
        if unknown:
            issues.append(HealthIssue("warning", "telemetry-index",
                f"Unknown keys in index: {unknown} (handled by from_dict)"))

    # 6. Advanced-hunting schema files
    ah_dir = DOCS_DIR / "advanced-hunting"
    schema_files = list(ah_dir.glob("advanced-hunting-*-table.md")) if ah_dir.exists() else []
    if len(schema_files) < 10:
        issues.append(HealthIssue("error", "schema-files",
            f"Only {len(schema_files)} schema files (expected 50+)"))

    # 7. Detection fragments
    frag_dir = DOCS_DIR / "detection-fragments" / "primitives"
    fragments = list(frag_dir.glob("*.md")) if frag_dir.exists() else []
    if len(fragments) < 4:
        issues.append(HealthIssue("warning", "fragments",
            f"Only {len(fragments)} primitive fragments (4 expected minimum)"))

    # 8. Pattern files match schema
    from tools.telemetry import TelemetryResolver
    try:
        resolver = TelemetryResolver()
        index_ats = set(resolver.list_all_action_types())
        if not index_ats:
            issues.append(HealthIssue("error", "telemetry-resolver",
                "No ActionTypes loaded from index"))
    except Exception as e:
        issues.append(HealthIssue("error", "telemetry-resolver",
            f"Failed to initialize: {e}"))

    errors = [i for i in issues if i.severity == "error"]
    warnings = [i for i in issues if i.severity == "warning"]

    return {
        "healthy": len(errors) == 0,
        "errors": len(errors),
        "warnings": len(warnings),
        "issues": [{"severity": i.severity, "component": i.component, "message": i.message}
                   for i in issues],
    }


def _check_json(issues: list, path: Path, name: str, optional: bool = False) -> None:
    if not path.exists():
        if optional:
            return
        issues.append(HealthIssue("error", name, f"Missing: {path}"))
        return
    try:
        with open(path, encoding="utf-8") as f:
            json.load(f)
    except json.JSONDecodeError as e:
        issues.append(HealthIssue("error", name, f"Invalid JSON: {e}"))


def _check_file(issues: list, path: Path, name: str) -> None:
    if not path.exists():
        issues.append(HealthIssue("error", name, f"Missing: {path}"))


def _check_freshness(issues: list, path: Path, days: int) -> None:
    if not path.exists():
        issues.append(HealthIssue("warning", "tenant-data",
            f"Missing tenant data: {path}"))
        return
    mtime = datetime.fromtimestamp(path.stat().st_mtime)
    age = (datetime.now() - mtime).days
    if age > days:
        issues.append(HealthIssue("warning", "tenant-data",
            f"Tenant data is {age} days old (threshold: {days})"))


def _load_json_safe(path: Path) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


# ── CLI ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import json as json_mod
    result = check()
    print(json_mod.dumps(result, indent=2))
    exit(0 if result["healthy"] else 1)
