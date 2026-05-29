---
primitive: P5
table: DeviceRegistryEvents
action_types: [RegistryValueSet, RegistryKeyCreated]
confidence: L4
tenant_observed: true
schema_validated: "2026-05-28"
schema_source: "docs/advanced-hunting/advanced-hunting-deviceregistryevents-table.md"
---

# P5: Registry Persistence

**Core detection block:**
```kql
DeviceRegistryEvents
| where Timestamp > ago({{lookback}})
| where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
| where RegistryKey contains_any ({{persistence_keys}})
| where InitiatingProcessFileName !in ({{system_processes}})
| project Timestamp, DeviceName, ActionType, RegistryKey,
    RegistryValueName, RegistryValueData,
    InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName
```

**Required columns:**
- `RegistryKey` [L3], `RegistryValueName` [L3], `RegistryValueData` [L3]
- `PreviousRegistryValueData` [L3] — previous value (forensics)
- `InitiatingProcessFileName` [L3]

**Parameters:**
- `persistence_keys`: `\Run`, `\RunOnce`, `\Winlogon\Shell`, `\Policies\Microsoft\Windows\PowerShell\`
- `system_processes`: `svchost.exe`, `services.exe`, `smss.exe`
- `lookback`: default `24h`

**Variants:**

### Run key modification by non-system
```kql
| where RegistryKey contains "\\Run" or RegistryKey contains "\\RunOnce"
| where InitiatingProcessFileName !in ("svchost.exe", "services.exe")
```

### User-writable path in registry value
```kql
| where RegistryValueData contains "\\Users\\" or RegistryValueData contains "\\Temp\\"
| where RegistryValueData endswith ".exe" or RegistryValueData endswith ".ps1"
```

**FP guidance:** Legitimate software installers write Run keys. Many enterprise
apps do this. Maintain exclusion list.

**Blind spots:** Transacted registry operations delayed; Windows ONLY.
