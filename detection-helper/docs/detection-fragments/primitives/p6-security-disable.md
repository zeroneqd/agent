---
primitive: P6
table: DeviceRegistryEvents
action_types: [RegistryValueSet]
confidence: L4
tenant_observed: true
schema_validated: "2026-05-28"
schema_source: "docs/advanced-hunting/advanced-hunting-deviceregistryevents-table.md"
---

# P6: Security Tool Disablement

**Core detection block:**
```kql
DeviceRegistryEvents
| where Timestamp > ago({{lookback}})
| where ActionType == "RegistryValueSet"
| where RegistryKey contains_any ({{security_keys}})
| project Timestamp, DeviceName, RegistryKey, RegistryValueName,
    RegistryValueData, PreviousRegistryValueData,
    InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName
```

**Required columns:**
- `RegistryKey` [L3], `RegistryValueName` [L3], `RegistryValueData` [L3]
- `PreviousRegistryValueData` [L3]
- `InitiatingProcessFileName` [L3]

**Parameters:**
- `security_keys`:
  - `SOFTWARE\\Policies\\Microsoft\\Windows Defender`
  - `SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System` (UAC)
  - `SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging`
  - `SYSTEM\\CurrentControlSet\\Services\\Sense` (Windows Defender ATP)
- `lookback`: default `24h`

**Variants:**

### Defender disablement
```kql
| where RegistryKey contains "Windows Defender"
| where RegistryValueName in ("DisableAntiSpyware", "DisableRealtimeMonitoring",
    "DisableBehaviorMonitoring", "DisableOnAccessProtection")
| where RegistryValueData == "1"
```

### UAC tampering
```kql
| where RegistryKey contains "Policies\\System"
| where RegistryValueName == "EnableLUA"
| where RegistryValueData == "0"
```

**FP guidance:** Some admin tools legitimately modify these keys. Correlate with
change management. Very high fidelity for `EnableLUA=0` (almost never legitimate).
