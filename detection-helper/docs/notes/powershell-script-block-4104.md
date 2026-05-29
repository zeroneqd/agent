---
date: "2026-05-28"
source:
  - "docs/windows-events/powershell-operational.md"
  - "docs/advanced-hunting/advanced-hunting-deviceevents-table.md"
  - "docs/tenant/actiontypes/DeviceEvents.md"
scope: "PowerShell logging — Windows, MDE + native channels"
confidence: confirmed
---

# PowerShell Script Block Logging (4104) — Coverage Summary

**Q:** Is PowerShell script block logging (4104) available in MDE?

**A:** Partially. Here's the complete picture:

**MDE path:** `DeviceEvents` with `ActionType == "PowerShellCommand"` or `"ScriptContent"`
- Script content appears in `AdditionalFields` payload
- Multi-part splitting on very large blocks (same limitation as 4104)
- Cross-host correlation easier than native 4104

**Native channel (higher fidelity):** `Microsoft-Windows-PowerShell/Operational` Event 4104
- De-obfuscated script content — Base64, string concatenation, format obfuscation all decoded
- Multi-part events: correlate by `ScriptBlockId`, reassemble via `MessageNumber` / `MessageTotal`
- Two tiers: `Level 3` (Warning = auto-suspicious only, "free") vs `Level 5` (Verbose = everything)

**Critical traps:**
- **PowerShell v2 downgrade** (`powershell.exe -Version 2`) — NO 4104 logging. Detect downgrade
  via `DeviceProcessEvents`: `FileName == "powershell.exe"` + `ProcessCommandLine has "-Version 2"`
- **PowerShell 7** logs to `PowerShellCore/Operational`, NOT `Microsoft-Windows-PowerShell/Operational`
- **Requires explicit enablement:** `EnableScriptBlockLogging = 1` in registry/GPO

**Prerequisites:**
- GPO: Computer Configuration → Administrative Templates → Windows Components →
  Windows PowerShell → Turn on PowerShell Script Block Logging
- Registry: `HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging`

**Cross-source verification:**
```kql
// MDE path
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType in ("PowerShellCommand", "ScriptContent")
| summarize count(), dcount(DeviceId)

// Native 4104 (Sentinel)
Event
| where TimeGenerated > ago(7d)
| where Source == "Microsoft-Windows-PowerShell" and EventID == 4104
| summarize count(), dcount(Computer)
```
