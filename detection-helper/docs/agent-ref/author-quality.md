# Detection Author — Quality Assurance Procedures

> **Loaded by:** `detection-helper.agent.md` (Path C) during quality assurance.

## Quality score dimensions

| Dimension | Values | How to assess |
|---|---|---|
| **Coverage** | high / medium / low | What % of the technique's variants does this catch? High = most variants; Low = only specific instances |
| **FP risk** | low / medium / high | Based on: how common is the parent process? how specific are the filters? how much environment tuning needed? |
| **Performance** | fast / moderate / slow | fast = single table, no joins, no regex; moderate = joins on indexed keys; slow = regex, unions, unfiltered joins |
| **Blind spots** | list | Specific evasions or gaps where this rule won't fire |
| **MITRE coverage** | technique + sub-technique | Full ATT&CK mapping |

## Scoring rubric

### Coverage

| Score | Criteria |
|---|---|
| **High** | Catches the technique across most tools/variants without tool-specific IOCs |
| **Medium** | Catches common variants, misses some specialized implementations |
| **Low** | Only catches specific tools or very narrow conditions |

### FP Risk

| Score | Criteria |
|---|---|
| **Low** | Fires < 1% of the time for benign activity; minimal tuning needed |
| **Medium** | Requires known-good exclusions; fires occasionally for legitimate activity |
| **High** | Requires extensive tuning; common legitimate activity matches pattern |

### Performance

| Score | Criteria |
|---|---|
| **Fast** | Single table scan, filters on indexed columns, no joins |
| **Moderate** | Joins on high-cardinality keys, `make_set`, `parse_json` |
| **Slow** | Regex on `_raw`, `union *`, unfiltered cross-device joins |

## Test validation plan template

Every rule must include:

```markdown
### Benign test (should NOT alert)
<what to run> → expected: 0 alerts

### Benign edge (may alert — tuning guidance)
<what to run> → expected: may alert, tune with <exclusion>

### Malicious simulation (should alert)
<safe technique> → expected: alert fires

### Volume estimate
<expected alerts per day/week in typical environment>
```

## False positive guidance template

```markdown
### Expected noise sources
1. <source 1>
2. <source 2>

### Baseline query
```kql
<query to measure normal frequency>
```

### Exclusion recommendations
```kql
| where InitiatingProcessFileName !in (
    "KnownGood1.exe",
    "KnownGood2.exe"
)
```

### Threshold tuning
- Start with: <threshold>
- If too noisy: increase to <higher threshold> or add <additional filter>
```

## Performance optimization checklist

- [ ] Filter on `Timestamp` first (always)
- [ ] Filter on `ActionType` before other columns
- [ ] Use `has` / `has_any` instead of `contains` / `matches regex`
- [ ] `project` only needed columns before joins
- [ ] Filter both sides of a join before joining
- [ ] Use `materialize()` when a dataset is used > 1 time
- [ ] Avoid `union *` — specify tables explicitly
- [ ] Use `bin(Timestamp, <interval>)` for time-based aggregation
- [ ] Consider `hint.strategy=broadcast` for small lookup tables
