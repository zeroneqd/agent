---
primitive: P10
table: DeviceEvents
action_types: [ScheduledTaskCreated, ScheduledTaskUpdated, ServiceInstalled]
confidence: L4
tenant_observed: true
schema_validated: "2026-05-28"
schema_source: "docs/advanced-hunting/advanced-hunting-deviceevents-table.md"
---

# P10: Scheduled Task / Service Creation

**Core detection block:**
```kql
DeviceEvents
| where Timestamp > ago({{lookback}})
| where ActionType in ("ScheduledTaskCreated", "ScheduledTaskUpdated", "ServiceInstalled")
| extend TaskDetails = parse_json(AdditionalFields)
| extend TaskExec = tostring(TaskDetails.TaskExec)
| where TaskExec has_any ({{suspicious_patterns}})
    or TaskExec contains_any ({{suspicious_paths}})
| project Timestamp, DeviceName, ActionType,
    TaskName=tostring(TaskDetails.TaskName),
    TaskExec, InitiatingProcessFileName,
    InitiatingProcessCommandLine, AccountName
```

**Required columns:**
- `ActionType` [L3], `AdditionalFields` [L3] — JSON with task details
- `InitiatingProcessFileName` [L3], `InitiatingProcessCommandLine` [L3]

**Parameters:**
- `suspicious_patterns`: `-enc`, `powershell`, `cmd /c`, `mshta`, `regsvr32`, `rundll32`
- `suspicious_paths`: `\Users\`, `\Temp\`, `\AppData\`
- `lookback`: default `24h`

**Variants:**

### Service installed from unusual path
```kql
| where ActionType == "ServiceInstalled"
| extend ServiceDetails = parse_json(AdditionalFields)
| where tostring(ServiceDetails.ImagePath) contains "\\Users\\"
    or tostring(ServiceDetails.ImagePath) contains "\\Temp\\"
```

### Non-system creator
```kql
| where ActionType == "ScheduledTaskCreated"
| where InitiatingProcessFileName !in ("svchost.exe", "taskhostw.exe",
    "OfficeClickToRun.exe", "GoogleUpdate.exe")
```

**FP guidance:** Software installers, OS updates. Exclude known-good creators.
**Performance:** Moderate — `parse_json()` is somewhat expensive; filter by
`ActionType` first.
