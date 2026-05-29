---
primitive: P11
table: DeviceEvents
action_types: [OpenProcessApiCall, LocalSecurityAuthoritySubsystemServiceProcessAccessDenied, UntrustedExecutableLoadedByLsass]
confidence: L4
tenant_observed: true
schema_validated: "2026-05-28"
schema_source: "docs/advanced-hunting/advanced-hunting-deviceevents-table.md"
---

# P11: LSASS Memory Access (Credential Dumping)

**Core detection block:**
```kql
DeviceEvents
| where Timestamp > ago({{lookback}})
| where ActionType in ({{lsass_action_types}})
| where FileName =~ "lsass.exe"
    or (ActionType == "CreateRemoteThreadApiCall"
        and InitiatingProcessFileName =~ "lsass.exe")
| where InitiatingProcessFileName !in ({{known_good}})
| project Timestamp, DeviceName,
    Dumper=InitiatingProcessFileName, DumperCmd=InitiatingProcessCommandLine,
    Target=FileName, ActionType,
    CallTrace=tostring(parse_json(AdditionalFields).CallTrace),
    AccountName=InitiatingProcessAccountName,
    DeviceId, ReportId
```

**Required columns:**
- `ActionType` [L3]
- `FileName` [L3] — target (lsass.exe)
- `InitiatingProcessFileName` [L3] — dumping process
- `InitiatingProcessCommandLine` [L3]
- `AdditionalFields` [L3] — JSON with CallTrace

**Parameters:**
- `lookback` — time range (default: `24h`)
- `lsass_action_types` — default: `["OpenProcessApiCall", "LocalSecurityAuthoritySubsystemServiceProcessAccessDenied", "UntrustedExecutableLoadedByLsass"]`
- `known_good` — default: `["svchost.exe", "taskhostw.exe", "services.exe", "MsMpEng.exe", "SenseCncProxy.exe"]`

**Variants:**

### Correlation: multiple signals from same device
```kql
| summarize Signals=make_set(ActionType), SignalCount=count(),
    Dumpers=make_set(InitiatingProcessFileName)
    by DeviceName, DeviceId
| where array_length(Signals) >= 2
```

### comsvcs.dll MiniDump (LOLBin)
```kql
DeviceProcessEvents
| where Timestamp > ago({{lookback}})
| where ProcessCommandLine has "comsvcs.dll" and ProcessCommandLine has "MiniDump"
```

**FP guidance:**
- EDR/AV may legitimately open LSASS — maintain exclusion list
- Credential Guard blocks some access methods (good — less noise)

**Performance:** Moderate — filter by `ActionType` then `FileName`.
