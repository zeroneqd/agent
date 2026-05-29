---
primitive: P8
table: DeviceNetworkEvents
action_types: [DnsConnectionInspected]
confidence: L4
tenant_observed: true
schema_validated: "2026-05-28"
schema_source: "docs/advanced-hunting/advanced-hunting-devicenetworkevents-table.md"
---

# P8: DNS Query (DGA / C2 Resolution)

**Core detection block:**
```kql
DeviceNetworkEvents
| where Timestamp > ago({{lookback}})
| where ActionType == "DnsConnectionInspected"
| where InitiatingProcessFileName in ({{source_processes}})
| where RemoteUrl !contains "."
    or RemoteUrl matches regex @"[a-z0-9]{20,}\.[a-z]{2,6}$"
| summarize QueryCount=count(), Domains=make_set(RemoteUrl)
    by DeviceName, InitiatingProcessFileName, Hour=startofhour(Timestamp)
| where QueryCount > {{threshold}}
```

**Required columns:**
- `RemoteUrl` [L3] — the queried domain
- `InitiatingProcessFileName` [L3]
- `ActionType` [L3]

**Parameters:**
- `source_processes` — non-browser processes doing DNS (suspicious)
- `threshold` — default 10 queries/hour from single process
- `lookback` — default `24h`

**Variants:**

### DGA pattern detection
```kql
| where RemoteUrl matches regex @"[a-z]{20,30}\.[a-z]{2,6}$"
// High-entropy domain names characteristic of DGAs
```

### Non-browser DNS to rare TLD
```kql
| where InitiatingProcessFileName !in ("chrome.exe", "msedge.exe", "firefox.exe")
| where RemoteUrl endswith ".tk" or RemoteUrl endswith ".ml"
    or RemoteUrl endswith ".ga" or RemoteUrl endswith ".cf"
```

**Blind spots:** DoH/DoT completely invisible; direct IP connections skip DNS.
**Performance:** Fast — single table, ActionType filter.
