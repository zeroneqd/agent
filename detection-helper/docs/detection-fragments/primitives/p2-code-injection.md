---
primitive: P2
table: DeviceEvents
action_types: [WriteProcessMemoryApiCall, CreateRemoteThreadApiCall, NtAllocateVirtualMemoryRemoteApiCall, NtMapViewOfSectionRemoteApiCall, MemoryRemoteProtect]
confidence: L4
tenant_observed: true
schema_validated: "2026-05-28"
schema_source: "docs/advanced-hunting/advanced-hunting-deviceevents-table.md"
---

# P2: Code Injection via Memory APIs

**Core detection block (sequence-based, high fidelity):**
```kql
let InjectionAPIs = dynamic([
    "NtAllocateVirtualMemoryRemoteApiCall",
    "WriteProcessMemoryApiCall",
    "CreateRemoteThreadApiCall",
    "NtMapViewOfSectionRemoteApiCall",
    "NtProtectVirtualMemoryRemoteApiCall",
    "MemoryRemoteProtect"
]);
DeviceEvents
| where Timestamp > ago({{lookback}})
| where ActionType in (InjectionAPIs)
| where InitiatingProcessFileName !in ({{known_good_injectors}})
| summarize APIs=make_set(ActionType), APICount=count(),
    Targets=make_set(FileName), First=min(Timestamp), Last=max(Timestamp)
    by DeviceName, InitiatingProcessSHA1, InitiatingProcessFileName,
       InitiatingProcessCommandLine
| where APICount >= {{min_api_count}}
| extend Score = APICount + array_length(APIs)
```

**Required columns:**
- `ActionType` [L3] — API call type
- `FileName` [L3] — target process
- `InitiatingProcessFileName` [L3] — injecting process
- `InitiatingProcessSHA1` [L3] — injector hash

**Parameters:**
- `lookback` — time range (default: `24h`)
- `min_api_count` — minimum distinct API calls (default: 2)
- `known_good_injectors` — excluded processes (default: `["explorer.exe", "services.exe", "svchost.exe", "SearchIndexer.exe", "MsMpEng.exe"]`)

**Variants:**

### Single API call from unusual process
```kql
| where ActionType in ("WriteProcessMemoryApiCall", "CreateRemoteThreadApiCall")
| where InitiatingProcessFileName !in (KnownGoodInjectors)
```

### Injection into high-value targets
```kql
let HighValue = dynamic(["lsass.exe", "svchost.exe", "services.exe",
    "explorer.exe", "winlogon.exe"]);
| where FileName in (HighValue)
| where InitiatingProcessFileName != FileName
```

**FP guidance:**
- EDR/AV agents inject legitimately — maintain exclusion list
- .NET JIT compilation triggers memory protection changes
- Windows Search injects into explorer

**Performance:** Moderate — `DeviceEvents` is large, filter by `ActionType` first.
