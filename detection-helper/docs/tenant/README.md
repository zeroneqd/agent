# Tenant-observed Defender Telemetry
This folder contains ActionType frequency and platform-breakdown data
exported from the live Defender XDR Advanced Hunting environment. It
complements the public Microsoft schema documentation under
`docs/advanced-hunting/` — it does not replace it.
## What's in here
- **`actiontypes/<TableName>.md`** — for each Defender Advanced Hunting
 table, the ActionType values observed in the tenant with event counts,
 device counts, and first/last seen timestamps over the refresh lookback.
- **`actiontypes/DeviceEvents-by-platform.md`** — `DeviceEvents`
 ActionTypes broken down by `OSPlatform` (Windows / Linux / macOS).
 Useful for confirming Linux coverage gaps with real data rather than
 documented expectation.
## How this differs from public docs
| Source | Tells you |
|---|---|
| `docs/advanced-hunting/` | What Microsoft documents the schema to contain |
| `docs/tenant/` | What's actually been emitted in our tenant over the lookback |
When the two disagree:
- ActionType in public docs, absent in tenant → may indicate missing sensor
 coverage, an audit policy not enabled, an absent workload (e.g. no Defender
 for Identity), or simply rare behaviour. Don't assume "doesn't fire" — it
 may just not have fired during the lookback.
- ActionType in tenant, absent from public docs → newer sensor surface area
 the docs haven't caught up on. Treat as real but verify schema before
 building detections.
## Handling notes
This data describes our detection telemetry surface area and event volumes.
Treat the same as any other internal operational documentation — keep
within personal/team-controlled storage, don't sync to external systems.
ActionType names themselves are schema values (not sensitive), but the
volume and platform-distribution data is environment-specific.
---
*This README is the contract between the tenant data and the agent. When
refresh cadence or query shape changes, update it.*