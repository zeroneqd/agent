# Unified Confidence Ontology (L1-L5)

> **Purpose.** All paths use identical confidence levels. A user can
> compare "L4" from a Path A decomposition with "L4" from a Path C rule and know
> both mean the same thing. Replaces per-workflow "confirmed / documented /
> inferred" with a unified 5-level system.

## Confidence Levels

| Level | Name | Meaning | Who Assigns | Example |
|---|---|---|---|---|
| **L5** | Live-Verified | Validation query ran in tenant, returned non-zero results | Any agent | "`summarize count() by ActionType` returned 1,247 events" |
| **L4** | Tenant-Observed | In tenant actiontypes within current lookback window | Defender Telemetry | "ProcessCreated: 890K events over 7d" |
| **L3** | Schema-Confirmed | Column/ActionType exists in `docs/advanced-hunting/*.md` | Any agent | "`FileName` confirmed in deviceprocessevents-table.md" |
| **L2** | Documented | In Microsoft public docs but not verified in workspace | Any agent | "Microsoft docs mention this column but schema file doesn't list it" |
| **L1** | Inferred | Logical extension, no direct source covers this | Any agent (must state basis) | "`InitiatingProcessAccountName` inferred from `AccountName` pattern" |

## Usage Rules

1. **Every factual claim gets an L-level.** No exceptions. If you state a table
   name, ActionType, column name, or event ID, prefix it with its L-level.

2. **L5 overrides L4 overrides L3.** If a primitive is L5 (live-verified), don't
   also mention L3. State the highest level achieved.

3. **L1 must include basis.** "L1: Inferred from `<basis>` — verify before deploying."

4. **Stale tenant data downgrades.** If `all-actiontypes.md` is > 14 days old,
   downgrade L4 claims to L3. If > 30 days old, require L5 verification.

5. **Column names must be L3 minimum.** Never write a column name in a query
   unless it's at least L3 (schema-confirmed). L1/L2 columns are proposals only.

## Shorthand Notation

In agent responses, use inline notation:

```markdown
- Table: `DeviceProcessEvents` [L4]
- ActionType: `ProcessCreated` [L5: 890K events/7d]
- Column: `InitiatingProcessFileName` [L3: confirmed in schema]
- Linux coverage: Partial [L2: documented only]
```

In YAML frontmatter:
```yaml
confidence_level: "L4"
confidence_basis: "Tenant actiontypes: 890K events over 7d"
```

## Per-Agent Defaults

| Agent | Typical highest level | When to require L5 |
|---|---|---|
| **Threat Translator** | L3 (schema-confirmed) | Before declaring "no gap" |
| **Defender Telemetry** | L4 (tenant-observed) | When tenant data is stale |
| **Detection Author** | L3 (schema-confirmed) | Before using a column in production query |

*All agents can achieve L5 by including a validation query in their response.*
