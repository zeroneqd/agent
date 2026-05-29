# Tenant Data Freshness Guidelines

> **Purpose.** Rules for how agents interpret the age of tenant data and when
to require live validation.

## Freshness thresholds

| Age | Action | Confidence impact |
|---|---|---|
| < 7 days | Use normally | L4 claims are valid |
| 7-14 days | Use with caution | L4 claims valid but flag age |
| 14-30 days | Require verification | Downgrade L4 → L3; include validation query |
| > 30 days | Treat as stale | All L4 → L3; L3 must be re-confirmed |

## Current data status

Check `docs/tenant/README.md` for the lookback window and generation date.
Check `docs/tenant/all-actiontypes.md` header for generation timestamp.

## Validation query template

When tenant data is stale, every "confirmed" claim must include:

```kql
// === Live Validation ===
// Run this to confirm the signal is still present in your tenant
<TableName>
| where Timestamp > ago(7d)
| where ActionType == "<ActionType>"
| summarize EventCount=count(), DeviceCount=dcount(DeviceId) by OSPlatform
| extend Status = iff(EventCount > 0, "CONFIRMED", "NOT OBSERVED")
| order by EventCount desc
```

## Per-Agent freshness rules

### Defender Telemetry
- If `all-actiontypes.md` > 14 days old: downgrade "confirmed in tenant" to
  "documented — tenant data stale, run validation query"
- If > 30 days old: require validation query in every response

### Detection Author
- If tenant data stale: rule confidence = L3 max (schema-confirmed)
- Include validation query as mandatory prerequisite before deployment

### Threat Translator
- Does not claim L4/L5 — unaffected by tenant freshness
- Notes when L4 would be needed for reliable detection planning
