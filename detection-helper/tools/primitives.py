"""Exploit Primitive Lookup — P1-P12 as structured data.

Replaces in LLM prompt: 500+ lines of operation-taxonomy.md prose.
Provides programmatic access to primitive definitions, telemetry mappings,
kill-chain positions, and blind spots.

Also includes TelemetryPrimitiveResolver — maps natural-language security
concepts (~20 domain primitives) to Defender XDR action names.  Designed for
LLM prompt injection: the LLM matches user prompts to primitives, and code
resolves primitives to concrete telemetry-index.json actions.

Usage:
    from tools.primitives import PrimitiveRegistry, TelemetryPrimitiveResolver
    p = PrimitiveRegistry()
    info = p.get("P1")
    # → {"name": "Process Spawn", "table": "DeviceProcessEvents", ...}
    early = p.get_by_kill_chain_position("early")
    tables = p.get_tables_for_primitive("P1")

    t = TelemetryPrimitiveResolver()
    primitives = t.list_primitives()
    # → ["process_creation", "service_management", ...]
    actions = t.resolve(["service_management"])
    # → ["Service Installation"]
"""

from __future__ import annotations

import functools
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from tools._base import DOCS_DIR


@dataclass
class Primitive:
    """A single exploit primitive definition."""
    id: str  # P1, P2, etc.
    name: str
    description: str
    table: str
    action_types: list[str] = field(default_factory=list)
    columns: list[str] = field(default_factory=list)
    kill_chain_position: str = ""  # early, early-mid, mid, mid-late, late
    windows_events: list[str] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)
    pattern_fragment: str = ""  # path to fragment file
    common_parents: list[str] = field(default_factory=list)
    common_children: list[str] = field(default_factory=list)


# ── Primitive database ────────────────────────────────────────────────

_PRIMITIVES: list[Primitive] = [
    Primitive(
        id="P1",
        name="Process Spawn from Exploited Parent",
        description="The exploited application launches a child process — typically a shell, script interpreter, or LOLBin.",
        table="DeviceProcessEvents",
        action_types=["ProcessCreated"],
        columns=["FileName", "InitiatingProcessFileName", "InitiatingProcessParentFileName",
                 "ProcessCommandLine", "InitiatingProcessCommandLine", "SHA1"],
        kill_chain_position="early",
        windows_events=["4688"],
        gaps=["Process hollowing may skip spawn (creates then overwrites memory)"],
        pattern_fragment="docs/detection-fragments/primitives/p1-process-spawn.md",
        common_parents=["winword.exe", "excel.exe", "powerpnt.exe", "acrord32.exe",
                       "chrome.exe", "msedge.exe", "java.exe"],
        common_children=["cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe",
                        "cscript.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe",
                        "certutil.exe"],
    ),
    Primitive(
        id="P2",
        name="Code Injection",
        description="Writes shellcode or DLL into memory of an existing process via memory APIs.",
        table="DeviceEvents",
        action_types=["WriteProcessMemoryApiCall", "CreateRemoteThreadApiCall",
                      "NtAllocateVirtualMemoryRemoteApiCall", "NtMapViewOfSectionRemoteApiCall",
                      "MemoryRemoteProtect"],
        columns=["ActionType", "FileName", "InitiatingProcessFileName", "InitiatingProcessSHA1",
                 "InitiatingProcessCommandLine"],
        kill_chain_position="early",
        windows_events=["Sysmon 8", "Sysmon 10"],
        gaps=["Kernel-level injection invisible", "Some EDR self-injection",
              "Process Doppelgänging may bypass some APIs"],
        pattern_fragment="docs/detection-fragments/primitives/p2-code-injection.md",
    ),
    Primitive(
        id="P3",
        name="Payload File Drop",
        description="Exploit or malware writes a file to disk — payload, persistence, tool, or data.",
        table="DeviceFileEvents",
        action_types=["FileCreated"],
        columns=["FileName", "FolderPath", "SHA1", "SHA256", "InitiatingProcessFileName"],
        kill_chain_position="early-mid",
        windows_events=["Sysmon 11", "4663"],
        gaps=["Short-lived files (create→execute→delete within sensor poll)",
              "Paths excluded by sensor config", "ADS (Alternate Data Streams) partial visibility"],
    ),
    Primitive(
        id="P4",
        name="File Modification (Config Tampering)",
        description="Modifying system files or configuration — disabling security, changing hosts, etc.",
        table="DeviceFileEvents",
        action_types=["FileModified"],
        columns=["FileName", "FolderPath", "PreviousFolderPath", "InitiatingProcessFileName"],
        kill_chain_position="mid",
        windows_events=["4663"],
        gaps=["Linux FileModified sparse", "Direct kernel disk I/O may bypass hooks"],
    ),
    Primitive(
        id="P5",
        name="Registry Persistence",
        description="Writing to registry Run keys, Winlogon, services for persistence.",
        table="DeviceRegistryEvents",
        action_types=["RegistryValueSet", "RegistryKeyCreated"],
        columns=["RegistryKey", "RegistryValueName", "RegistryValueData",
                 "PreviousRegistryValueData", "InitiatingProcessFileName"],
        kill_chain_position="mid",
        windows_events=["Sysmon 13", "4657"],
        gaps=["Windows ONLY — no registry on Linux/macOS",
              "Transacted registry operations delayed visibility"],
    ),
    Primitive(
        id="P6",
        name="Security Tool Disablement",
        description="Registry/config modifications that disable Defender, firewall, EDR, or logging.",
        table="DeviceRegistryEvents",
        action_types=["RegistryValueSet"],
        columns=["RegistryKey", "RegistryValueName", "RegistryValueData",
                 "InitiatingProcessFileName"],
        kill_chain_position="mid",
        windows_events=["4719"],
        gaps=["Some tampering uses non-registry methods"],
    ),
    Primitive(
        id="P7",
        name="Outbound Connection (C2 / Download / Beacon)",
        description="Compromised system connects outbound for C2, staging, or exfiltration.",
        table="DeviceNetworkEvents",
        action_types=["ConnectionSuccess", "ConnectionAttempt"],
        columns=["RemoteIP", "RemotePort", "RemoteUrl", "InitiatingProcessFileName",
                 "InitiatingProcessCommandLine"],
        kill_chain_position="early-mid",
        windows_events=["Sysmon 3", "5156"],
        gaps=["DoH/DoT bypasses DNS visibility", "Encrypted C2 over 443 content invisible",
              "Short-lived connections may be sampled"],
        pattern_fragment="docs/detection-fragments/primitives/p7-outbound-connection.md",
    ),
    Primitive(
        id="P8",
        name="DNS Query (DGA / C2 Resolution)",
        description="DNS lookups for C2 domains, DGA patterns, or payload delivery.",
        table="DeviceNetworkEvents",
        action_types=["DnsConnectionInspected"],
        columns=["RemoteUrl", "InitiatingProcessFileName"],
        kill_chain_position="early",
        windows_events=["Sysmon 22"],
        gaps=["DoH/DoT completely bypasses standard DNS visibility",
              "Direct IP connections skip DNS entirely", "Cached responses"],
    ),
    Primitive(
        id="P9",
        name="WMI Event Subscription",
        description="Creating permanent WMI event subscriptions for persistence (WMI backdoor).",
        table="DeviceEvents",
        action_types=["WmiBindEventFilterToConsumer", "ProcessCreatedUsingWmiQuery",
                      "RemoteWmiOperation"],
        columns=["ActionType", "FileName", "InitiatingProcessFileName"],
        kill_chain_position="mid-late",
        windows_events=["Sysmon 19", "Sysmon 20", "Sysmon 21"],
        gaps=["Windows ONLY", "Some legitimate IT automation uses WMI"],
    ),
    Primitive(
        id="P10",
        name="Scheduled Task / Service Creation",
        description="Creating scheduled tasks or Windows services for persistence or privilege escalation.",
        table="DeviceEvents",
        action_types=["ScheduledTaskCreated", "ScheduledTaskUpdated",
                      "ScheduledTaskDeleted", "ServiceInstalled"],
        columns=["ActionType", "FileName", "FolderPath", "ProcessCommandLine",
                 "InitiatingProcessFileName", "AdditionalFields"],
        kill_chain_position="mid-late",
        windows_events=["4698", "4697", "7045"],
        gaps=["Task XML in AdditionalFields needs parsing",
              "Legitimate software installers create many tasks"],
    ),
    Primitive(
        id="P11",
        name="LSASS Memory Access",
        description="Attempting to read credential material from LSASS process memory.",
        table="DeviceEvents",
        action_types=["OpenProcessApiCall",
                      "LocalSecurityAuthoritySubsystemServiceProcessAccessDenied",
                      "UntrustedExecutableLoadedByLsass"],
        columns=["ActionType", "FileName", "InitiatingProcessFileName",
                 "InitiatingProcessCommandLine", "AdditionalFields"],
        kill_chain_position="mid",
        windows_events=["Sysmon 10"],
        gaps=["Credential Guard blocks some methods (good)",
              "Some access from legitimate EDR/AV"],
        pattern_fragment="docs/detection-fragments/primitives/p11-lsass-access.md",
    ),
    Primitive(
        id="P12",
        name="Vulnerable App Exploitation Indicator",
        description="Behavioral indicators that a specific application is being exploited.",
        table="DeviceProcessEvents",
        action_types=["ProcessCreated"],
        columns=["FileName", "InitiatingProcessFileName", "ProcessCommandLine"],
        kill_chain_position="early",
        gaps=["You detect the post-exploitation behavior, not the exploit itself"],
    ),
]


# ── Registry class ────────────────────────────────────────────────────

class PrimitiveRegistry:
    """Query interface for the primitive database."""

    def __init__(self) -> None:
        self._by_id = {p.id: p for p in _PRIMITIVES}
        self._by_position: dict[str, list[Primitive]] = {}
        for p in _PRIMITIVES:
            self._by_position.setdefault(p.kill_chain_position, []).append(p)

    def get(self, primitive_id: str) -> Optional[dict]:
        """Get a primitive by ID (e.g., 'P1')."""
        p = self._by_id.get(primitive_id.upper())
        return p.__dict__ if p else None

    def get_by_name(self, name: str) -> Optional[dict]:
        """Fuzzy match by name."""
        for p in _PRIMITIVES:
            if name.lower() in p.name.lower():
                return p.__dict__
        return None

    def get_by_kill_chain_position(self, position: str) -> list[dict]:
        """Get primitives at a kill-chain position ('early', 'mid', etc.)."""
        return [p.__dict__ for p in self._by_position.get(position, [])]

    def get_tables_for_primitive(self, primitive_id: str) -> list[str]:
        """Return tables associated with a primitive."""
        p = self._by_id.get(primitive_id.upper())
        return [p.table] if p else []

    def get_detection_priority(self, primitive_ids: list[str]) -> list[str]:
        """Sort primitives by kill-chain position (earlier = higher priority)."""
        position_order = ["early", "early-mid", "mid", "mid-late", "late"]
        scored = []
        for pid in primitive_ids:
            p = self._by_id.get(pid.upper())
            if p:
                try:
                    score = position_order.index(p.kill_chain_position)
                except ValueError:
                    score = 99
                scored.append((score, pid))
        scored.sort()
        return [pid for _, pid in scored]

    def get_fallback(self, primitive_id: str) -> Optional[dict]:
        """Get recommended fallback primitive if this one is blind."""
        fallbacks = {
            "P2": "P1",   # injection blind → process spawn
            "P8": "P7",   # DNS blind → outbound connection
            "P3": "P1",   # file drop blind → process spawn
            "P5": "P10",  # registry blind → task/service
            "P11": "P3",  # LSASS blocked → file drop (dump)
        }
        fb = fallbacks.get(primitive_id.upper())
        return self.get(fb) if fb else None

    def list_all(self) -> list[dict]:
        """Return all primitives."""
        return [p.__dict__ for p in _PRIMITIVES]


# ── Telemetry Concept Primitive Layer ─────────────────────────────────
#
#   Security-domain primitives (~20) that bridge natural language to
#   Defender XDR action names.  The LLM receives the primitive list,
#   matches the user prompt, and returns selected primitives.
#   Code then resolves those primitives to concrete telemetry actions.


class TelemetryPrimitiveResolver:
    """Map security-domain primitives to Defender XDR telemetry actions.

    Usage:
        t = TelemetryPrimitiveResolver()

        # For LLM prompt — inject the primitive list
        catalog = t.format_for_prompt()
        # → "process_creation: A new process is started or spawned
        #      service_management: Windows services are created, started, ..."

        # LLM returns selected primitives
        selected = ["service_management", "process_creation"]
        action_names = t.resolve(selected)
        # → ["Service Installation", "Process Creation"]

        # Then fetch full entries via TelemetryResolver
        entries = telemetry_resolver.get_actions(action_names)
    """

    def __init__(self, mapping_path: Path | None = None) -> None:
        path = mapping_path or DOCS_DIR / "index" / "primitive-mapping.json"
        data = self._load(path)
        self._primitives: list[dict] = data.get("primitives", [])
        self._by_primitive: dict[str, dict] = {
            p["primitive"]: p for p in self._primitives
        }
        # Build reverse index: action name → list of primitives
        self._action_to_primitives: dict[str, list[str]] = {}
        for p in self._primitives:
            for action in p.get("actions", []):
                self._action_to_primitives.setdefault(action, []).append(p["primitive"])

    # ── Public API ──────────────────────────────────────────────────────

    def list_primitives(self) -> list[str]:
        """Return all primitive names for LLM prompt injection."""
        return [p["primitive"] for p in self._primitives]

    def list_primitive_details(self) -> list[dict]:
        """Return primitive names with descriptions and indicators."""
        return [
            {
                "primitive": p["primitive"],
                "description": p["description"],
                "indicators": p.get("indicators", []),
                "actions": p.get("actions", []),
                "note": p.get("note", ""),
            }
            for p in self._primitives
        ]

    def format_for_prompt(self) -> str:
        """Format primitives as a compact string suitable for LLM prompt.

        ~60-80 tokens.  One line per primitive with description and key
        indicators in parentheses.
        """
        lines = []
        for p in self._primitives:
            indicators = ", ".join(p.get("indicators", [])[:3])
            line = f"- {p['primitive']}: {p['description']}"
            if indicators:
                line += f" ({indicators})"
            if p.get("note"):
                line += f" [{p['note']}]"
            lines.append(line)
        return "\n".join(lines)

    def resolve(self, primitives: list[str]) -> list[str]:
        """Map selected primitives to Defender XDR action names.

        Returns a deduplicated list of action names.  Each primitive may
        map to multiple actions (e.g., process_manipulation → Process
        Injection + LSASS Access).

        Unknown primitives are silently ignored — the caller should
        validate the LLM's output against list_primitives() first.
        """
        actions: set[str] = set()
        for name in primitives:
            p = self._by_primitive.get(name.lower().strip())
            if p:
                actions.update(p.get("actions", []))
        return sorted(actions)

    def explain(self, primitive: str) -> dict | None:
        """Return full details for a primitive — useful for LLM rationale."""
        p = self._by_primitive.get(primitive.lower().strip())
        if not p:
            return None
        return {
            "primitive": p["primitive"],
            "description": p["description"],
            "indicators": p.get("indicators", []),
            "actions": p.get("actions", []),
            "note": p.get("note", ""),
        }

    def primitives_for_action(self, action_name: str) -> list[str]:
        """Reverse lookup: which primitives include this action?

        Useful when a TelemetryResolver result needs to be expressed back
        to the LLM in primitive terms.
        """
        return self._action_to_primitives.get(action_name, [])

    # ── Private ─────────────────────────────────────────────────────────

    @staticmethod
    @functools.lru_cache(maxsize=1)
    def _load(path: Path) -> dict:
        try:
            with open(path, encoding="utf-8") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}


# ── CLI ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys, json

    if len(sys.argv) > 1 and sys.argv[1].startswith("T"):
        # Telemetry primitive mode
        t = TelemetryPrimitiveResolver()
        if sys.argv[1] in ("--list", "-l"):
            print(json.dumps(t.list_primitive_details(), indent=2))
        elif sys.argv[1] in ("--prompt", "-p"):
            print(t.format_for_prompt())
        elif sys.argv[1] in ("--resolve", "-r") and len(sys.argv) > 2:
            primitives = [p.strip() for p in sys.argv[2].split(",")]
            print(json.dumps(t.resolve(primitives), indent=2))
        else:
            print(f"Usage: python -m tools.primitives --{{list|prompt|resolve p1,p2}}")
    else:
        # Exploit primitive mode (original)
        p = PrimitiveRegistry()

        if len(sys.argv) > 1:
            pid = sys.argv[1].upper()
            result = p.get(pid)
            if result:
                print(json.dumps(result, indent=2))
            else:
                print(f"Unknown primitive: {pid}")
        else:
            print(json.dumps({
                "count": len(_PRIMITIVES),
                "primitives": [{"id": pr.id, "name": pr.name, "position": pr.kill_chain_position}
                              for pr in _PRIMITIVES]
            }, indent=2))
