"""Pattern Composer — programmatic detection rule assembly.

Replaces in LLM prompt: prose instructions about how to combine fragments.
LLM describes intent ("compose P1 + P7 with sequence-and"), code does assembly.

Usage:
    from tools.patterns import PatternComposer
    c = PatternComposer()
    kql = c.compose_sequence(["P1", "P7"], window_minutes=5)
    kql = c.compose_fallback("P2", "P1")
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from tools._base import DOCS_DIR, extract_code_blocks

FRAGMENTS_DIR = DOCS_DIR / "detection-fragments" / "primitives"
COMBINATORS_DIR = DOCS_DIR / "detection-fragments" / "combinators"


class PatternComposer:
    """Assemble detection rules from primitive fragments and combinators."""

    def __init__(self) -> None:
        self._fragments: dict[str, str] = {}
        self._combinators: dict[str, str] = {}
        self._load_fragments()
        self._load_combinators()

    # ── Public API ──────────────────────────────────────────────────────

    def compose_sequence(
        self,
        primitive_ids: list[str],
        window_minutes: int = 5,
        lookback: str = "24h",
    ) -> str:
        """Compose a sequence-and rule from multiple primitives.

        Returns complete KQL. LLM provides intent, this function assembles.
        """
        if not primitive_ids:
            return "// ERROR: No primitives provided"

        # Single primitive — return its core block directly
        if len(primitive_ids) == 1:
            return self._get_fragment_kql(primitive_ids[0])

        # Multiple primitives — sequence them
        blocks = []
        for pid in primitive_ids:
            kql = self._get_fragment_kql(pid)
            if kql:
                blocks.append((pid, kql))

        if len(blocks) == 1:
            return blocks[0][1]

        return self._assemble_sequence(blocks, window_minutes, lookback)

    def compose_fallback(self, primary_id: str, fallback_id: str) -> str:
        """Compose a fallback-or rule.

        Primary detection with documented gap + fallback if blind.
        """
        primary_kql = self._get_fragment_kql(primary_id) or f"// No fragment for {primary_id}"
        fallback_kql = self._get_fragment_kql(fallback_id) or f"// No fragment for {fallback_id}"

        return (
            f"// === Primary: {primary_id} ===\n"
            f"{primary_kql}\n\n"
            f"// === Fallback: {fallback_id} (if {primary_id} is blind) ===\n"
            f"{fallback_kql}\n\n"
            f"// Use union to combine both detections:\n"
            f"// union (PrimaryQuery), (FallbackQuery)\n"
        )

    def compose_cve_response(
        self,
        cve_id: str,
        primitive_ids: list[str],
        product: str = "",
        epss: float = 0.0,
    ) -> str:
        """Assemble a complete CVE response from template + fragments.

        Returns markdown with YAML frontmatter + composed KQL rules.
        """
        from tools.primitives import PrimitiveRegistry

        registry = PrimitiveRegistry()
        rules = []

        for i, pid in enumerate(primitive_ids, 1):
            kql = self._get_fragment_kql(pid)
            info = registry.get(pid) or {}
            if kql:
                rules.append(
                    f"### Rule {i}: {info.get('name', pid)}\n\n"
                    f"```kql\n{kql}\n```\n"
                )

        primitives_block = "\n".join(
            f"| {pid} | {registry.get(pid, {}).get('name', '')} | "
            f"{registry.get(pid, {}).get('kill_chain_position', '')} |"
            for pid in primitive_ids
        )

        return (
            f"---\n"
            f"cve_id: \"{cve_id}\"\n"
            f"product: \"{product}\"\n"
            f"epss_score: {epss}\n"
            f"primitives_detected: {len(primitive_ids)}\n"
            f"---\n\n"
            f"## Threat Summary\n\n"
            f"## Exploit Chain\n\n"
            f"| ID | Name | Position |\n"
            f"|---|---|---|\n"
            f"{primitives_block}\n\n"
            f"## Detection Rules\n\n"
            f"{chr(10).join(rules)}"
        )

    def list_available_fragments(self) -> list[str]:
        """Return IDs of primitives that have fragments."""
        available = []
        for key in self._fragments:
            # Extract P-number from filename like "p1-process-spawn"
            match = re.match(r"p(\d+)-", key)
            if match:
                available.append(f"P{match.group(1)}")
        return sorted(set(available))

    # ── Private ─────────────────────────────────────────────────────────

    def _load_fragments(self) -> None:
        if FRAGMENTS_DIR.exists():
            for f in FRAGMENTS_DIR.glob("*.md"):
                self._fragments[f.stem] = f.read_text(encoding="utf-8")

    def _load_combinators(self) -> None:
        if COMBINATORS_DIR.exists():
            for f in COMBINATORS_DIR.glob("*.md"):
                self._combinators[f.stem] = f.read_text(encoding="utf-8")

    def _get_fragment_kql(self, primitive_id: str) -> Optional[str]:
        """Extract KQL from a primitive fragment file."""
        pid_num = primitive_id.upper().replace("P", "")
        # Find matching fragment file
        for key, content in self._fragments.items():
            if key.startswith(f"p{pid_num}-"):
                blocks = extract_code_blocks(content, "kql")
                return blocks[0] if blocks else None
        return None

    def _assemble_sequence(
        self,
        blocks: list[tuple[str, str]],
        window_minutes: int,
        lookback: str,
    ) -> str:
        """Build sequence-and KQL from multiple primitive blocks."""
        if len(blocks) == 2:
            (pid_a, kql_a), (pid_b, kql_b) = blocks

            # Extract the core where clauses from each block
            where_a = self._extract_where(kql_a)
            where_b = self._extract_where(kql_b)

            table_a = self._extract_table(kql_a)
            table_b = self._extract_table(kql_b)

            return (
                f"// Sequence: {pid_a} → {pid_b} (within {window_minutes}m)\n"
                f"let TimeWindow = {window_minutes}m;\n"
                f"let FirstEvents = materialize (\n"
                f"    {table_a}\n"
                f"    | where Timestamp > ago({lookback})\n"
                f"    {self._indent(where_a)}\n"
                f"    | project Timestamp, DeviceId, DeviceName, Details=*\n"
                f");\n"
                f"let SecondEvents = materialize (\n"
                f"    {table_b}\n"
                f"    | where Timestamp > ago({lookback})\n"
                f"    {self._indent(where_b)}\n"
                f"    | project Timestamp, DeviceId, DeviceName, Details=*\n"
                f");\n"
                f"FirstEvents\n"
                f"| join kind=inner (SecondEvents) on DeviceId\n"
                f"| where datetime_diff('minute', Timestamp1, Timestamp) between (0 .. {window_minutes})\n"
                f"| project DeviceName, FirstTime=Timestamp, SecondTime=Timestamp1, DeviceId\n"
                f"| order by FirstTime desc"
            )

        # Generic fallback for 3+ primitives
        return (
            f"// Multi-primitive sequence: {' → '.join(p for p, _ in blocks)}\n"
            + "\n\n".join(f"// --- {pid} ---\n{kql}" for pid, kql in blocks)
            + f"\n\n// Correlate on DeviceId within {window_minutes}m window"
        )

    @staticmethod
    def _extract_where(kql: str) -> str:
        """Extract where clauses from a KQL block."""
        lines = []
        in_where = False
        for line in kql.splitlines():
            stripped = line.strip()
            if stripped.startswith("| where") or stripped.startswith("| extend"):
                in_where = True
                lines.append(stripped)
            elif in_where and stripped.startswith("|") and not stripped.startswith("| project"):
                lines.append(stripped)
            elif stripped.startswith("| project"):
                break
        return "\n".join(lines) if lines else "| where true"

    @staticmethod
    def _extract_table(kql: str) -> str:
        """Extract table name from first non-comment line."""
        for line in kql.splitlines():
            line = line.strip()
            if line and not line.startswith("//") and not line.startswith("|"):
                return line
            if line.startswith("| ") and "join" not in line.lower():
                # Might be inline
                pass
        return "DeviceEvents"

    @staticmethod
    def _indent(text: str) -> str:
        return "\n".join("    " + line for line in text.splitlines())


# ── CLI ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    c = PatternComposer()

    if len(sys.argv) > 2 and sys.argv[1] == "compose":
        ids = [p.strip() for p in sys.argv[2].split(",")]
        kql = c.compose_sequence(ids)
        print(kql)
    elif len(sys.argv) > 3 and sys.argv[1] == "fallback":
        kql = c.compose_fallback(sys.argv[2], sys.argv[3])
        print(kql)
    else:
        print("Available fragments:", ", ".join(c.list_available_fragments()))
