---
primitive: P4
table: DeviceFileEvents
action_types: [FileModified]
confidence: L3
tenant_observed: false
schema_validated: "2026-05-28"
schema_source: "docs/advanced-hunting/advanced-hunting-devicefileevents-table.md"
---

# P4: File Modification (Config Tampering)

**Core detection block:**
```kql
DeviceFileEvents
| where Timestamp > ago({{lookback}})
| where ActionType == "FileModified"
| where FileName in ({{target_files}})
| project Timestamp, DeviceName, FileName, FolderPath,
    PreviousFolderPath, PreviousFileName,
    InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName
```

**Required columns:**
- `FileName` [L3], `FolderPath` [L3]
- `PreviousFolderPath` [L3], `PreviousFileName` [L3]
- `InitiatingProcessFileName` [L3]

**Parameters:**
- `target_files`: `hosts`, `services`, `.bashrc`, `sshd_config`
- `lookback`: default `24h`

**Variants:**

### Windows hosts file tampering
```kql
| where FolderPath endswith "\\drivers\\etc\\hosts"
| where InitiatingProcessFileName !in ("svchost.exe", "System")
```

**Blind spots:** Linux FileModified coverage is sparse; kernel disk I/O invisible.
**Confidence:** L3 only — tenant observation varies by platform.
