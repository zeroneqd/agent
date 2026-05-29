---
date: "2026-05-28"
source:
  - "docs/advanced-hunting/advanced-hunting-deviceregistryevents-table.md"
  - "docs/tenant/actiontypes/DeviceRegistryEvents.md"
scope: "MDE DeviceRegistryEvents — Windows only"
confidence: confirmed
---

# Registry Value Set — Column Name Trap

**Q:** How do I query registry modifications in MDE?

**A:** DeviceRegistryEvents with ActionType == "RegistryValueSet". Verified columns:

- `RegistryKey` — the full key path (e.g., `HKEY_LOCAL_MACHINE\\SOFTWARE\\...`)
- `RegistryValueName` — the value name being set
- `RegistryValueData` — the new value data
- `PreviousRegistryValueData` — the previous value (on modifications only)

**Common traps:**
- `RegistryPath` does NOT exist — use `RegistryKey`
- `ValueName` does NOT exist — use `RegistryValueName`
- `RegistryValueSet` requires the value to actually change — reading/querying the
  registry does NOT produce an event in any Defender table

**Windows-only:** This table does not exist on Linux or macOS.

**Verification query:**
```kql
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where ActionType == "RegistryValueSet"
| project Timestamp, DeviceName, RegistryKey, RegistryValueName,
          RegistryValueData, PreviousRegistryValueData,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```
