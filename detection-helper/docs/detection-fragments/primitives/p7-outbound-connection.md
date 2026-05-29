---
primitive: P7
table: DeviceNetworkEvents
action_types: [ConnectionSuccess, ConnectionAttempt]
confidence: L4
tenant_observed: true
schema_validated: "2026-05-28"
schema_source: "docs/advanced-hunting/advanced-hunting-devicenetworkevents-table.md"
---

# P7: Outbound Connection (C2 / Download / Beacon)

**Core detection block:**
```kql
DeviceNetworkEvents
| where Timestamp > ago({{lookback}})
| where ActionType in ("ConnectionSuccess", "ConnectionAttempt")
| where InitiatingProcessFileName in ({{source_processes}})
| where {{destination_filter}}
| project Timestamp, DeviceName,
    Process=InitiatingProcessFileName, ProcessCmd=InitiatingProcessCommandLine,
    RemoteIP, RemotePort, RemoteUrl, Protocol,
    AccountName, DeviceId, ReportId
```

**Required columns:**
- `ActionType` [L3]
- `RemoteIP` [L3] — NOT `DestIP`
- `RemotePort` [L3] — NOT `DestPort`
- `RemoteUrl` [L3]
- `InitiatingProcessFileName` [L3]
- `InitiatingProcessCommandLine` [L3]

**Parameters:**
- `source_processes` — dynamic array of processes that shouldn't make outbound
- `destination_filter` — condition on destination (public IP, specific ports, etc.)
- `lookback` — time range (default: `24h`)

**Default destination filter (public IP only):**
```kql
ipv4_is_private(RemoteIP) == false and isnotempty(RemoteIP)
```

**Variants:**

### Exploited app + unexpected outbound
```kql
let ExploitableApps = dynamic([
    "winword.exe", "excel.exe", "powerpnt.exe",
    "acrord32.exe", "chrome.exe", "java.exe"
]);
| where InitiatingProcessFileName in (ExploitableApps)
| where RemotePort in (80, 443, 8080, 4444, 5555, 9999)
| where ipv4_is_private(RemoteIP) == false
```

### Beacon detection (repeated connections)
```kql
| summarize ConnectionCount=count(),
    Ports=make_set(RemotePort), URLs=make_set(RemoteUrl)
    by DeviceName, InitiatingProcessFileName, RemoteIP, Hour=startofhour(Timestamp)
| where ConnectionCount > {{beacon_threshold}}
```

**FP guidance:**
- Browsers and Java often connect outbound legitimately
- Focus on unusual ports + public IPs + unexpected processes
- Correlate with P1 (process spawn) for higher fidelity

**Performance:** Fast — single table, `ActionType` filter is indexed.
