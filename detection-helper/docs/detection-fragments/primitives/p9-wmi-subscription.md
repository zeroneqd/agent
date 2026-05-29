---
primitive: P9
table: DeviceEvents
action_types: [WmiBindEventFilterToConsumer, ProcessCreatedUsingWmiQuery, RemoteWmiOperation]
confidence: L4
tenant_observed: true
schema_validated: "2026-05-28"
schema_source: "docs/advanced-hunting/advanced-hunting-deviceevents-table.md"
---

# P9: WMI Event Subscription (WMI Backdoor)

**Core detection block:**
```kql
DeviceEvents
| where Timestamp > ago({{lookback}})
| where ActionType in ("WmiBindEventFilterToConsumer",
    "ProcessCreatedUsingWmiQuery", "RemoteWmiOperation")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath,
    ProcessCommandLine, InitiatingProcessFileName,
    InitiatingProcessCommandLine, AccountName, ReportId
```

**Required columns:**
- `ActionType` [L3], `FileName` [L3], `FolderPath` [L3]
- `InitiatingProcessFileName` [L3], `ProcessCommandLine` [L3]

**Parameters:**
- `lookback` — default `7d` (rare event, longer window)

**Variants:**

### Filter-to-consumer binding (classic WMI persistence)
```kql
| where ActionType == "WmiBindEventFilterToConsumer"
// This is the persistence mechanism — filter + consumer bound together
```

### Remote WMI operation
```kql
| where ActionType == "RemoteWmiOperation"
// WMI from remote system — lateral movement indicator
```

**FP guidance:** Rare in most environments. Some IT automation tools use WMI.
Baseline first — if < 1 event/week, alert on any occurrence.

**Blind spots:** Windows ONLY; legitimate SCCM/SCOM activity.
