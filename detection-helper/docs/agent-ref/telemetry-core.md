# Telemetry Agent — Core Reference

> **Loaded by:** `detection-helper.agent.md` (Path B — telemetry lookup).
> **Purpose:** Essential telemetry guidance, workflow, search strategy, grounding rules.

## Workflow

1. **Read session state** — `docs/session/state.md` — skip already-confirmed primitives
2. **Route using decision matrix** — `docs/decision-matrix.md` or `docs/index/telemetry-index.json`
3. **Load index** — `docs/index/telemetry-index.json` — search `keywords` array
4. **Shortlist** — `docs/schema-overview.md` — read Gaps line per candidate
5. **Confirm columns** — `docs/advanced-hunting/<table>-table.md` — verify every column
6. **Check anti-patterns** — `docs/notes/anti-patterns.md` — before finalizing query
7. **Check tenant data** — `docs/tenant/all-actiontypes.md` — confirm ActionType observed
8. **Web-fetch if needed** — allowlist: `learn.microsoft.com`, `github.com/MicrosoftDocs`
9. **Run Column Validation Checklist + Confidence Calibration**
10. **Write response** with YAML frontmatter + Coverage Validator

## Search strategy (priority order)

1. **Index lookup** — `telemetry-index.json` — most efficient
2. **Exact table name** — `search/codebase "DeviceProcessEvents"`
3. **Exact ActionType** — `search/codebase "ProcessCreated"` — case-sensitive
4. **Decision matrix** — `docs/decision-matrix.md` — pattern matching
5. **Schema overview** — `docs/schema-overview.md` — table shortlist

**Never** search for generic terms: "event", "log", "activity", "telemetry", "process".
**Maximum 3 `search/codebase` calls.** After 3, use schema-overview as index.

## Column validation checklist (mandatory)

Before finalizing any KQL query:

- [ ] Column appears in `docs/advanced-hunting/<table>-table.md` schema
- [ ] Generic names (`AccountName`, `UserName`, `ProcessName`) checked against
      `docs/notes/anti-patterns.md` for correct prefix (`InitiatingProcess*`)
- [ ] ActionType string matches exactly (case-sensitive in KQL)
- [ ] Each column marked: ✓ confirmed [L3+] | ✗ not found | ? proposed [L1]

## Confidence notation (L1-L5)

Use `docs/agent-ref/shared-confidence.md`. Every factual claim must have an L-level.

**Telemetry agent typical levels:**
- L4: Tenant-observed ActionType (from `all-actiontypes.md`)
- L3: Schema-confirmed column (from per-table markdown)
- L2: Documented in public docs but not in workspace schema
- L1: Inferred — must state basis

## Grounding rules

- **Never invent.** Column names, ActionTypes, Event IDs from workspace docs or
  authoritative web sources only.
- **L3 minimum for columns in queries.** Never write a column name that's only L1/L2.
- **Check anti-patterns before every response.** Read `docs/notes/anti-patterns.md`.
- **Tenant data freshness:** If `all-actiontypes.md` is > 14 days old, downgrade
  L4 to L3. If > 30 days old, include live validation query.
- **Documented vs observed:** If ActionType in public docs but not in tenant data,
  flag: "Documented [L2] but not observed in tenant over <window>."

## Coverage validator (every response must include)

```kql
// === Coverage Validator ===
<PrimaryTable>
| where Timestamp > ago(7d)
| where ActionType == "<ConfirmedActionType>"
| summarize EventCount=count(), DeviceCount=dcount(DeviceId) by OSPlatform
| order by EventCount desc
```

## Platform & workload notes

- **Default per-platform breakdown** when coverage differs
- **Distinguish MDE tables from Sentinel/Log Analytics** — flag workload dependencies
- **Entra ID:** MDI-sourced (`IdentityLogonEvents`) vs native Entra (`AADSignInEventsBeta`)
- **Linux:** Default toward "partial" — see Caveat catalog
- **Always call out prerequisites** — audit policies, Sysmon config, script block logging

## Caveat catalog (consult when relevant)

- **Linux:** Kernel-level activity invisible to MDE (syscalls, eBPF, AF_ALG, etc.)
- **Containers/WSL2:** Limited sensor visibility
- **Browser:** App-bound encryption opaque to EDR
- **Sensor version:** Some ActionTypes need minimum MDE sensor version
- **Reflective loads:** Memory-only loads may not trigger `ImageLoad`
- **DNS DoH/DoT:** Bypasses standard DNS visibility
- **PowerShell:** v2 downgrade defeats 4104; PS7 logs to different channel
- **Sysmon:** Coverage entirely config-dependent

## Query hygiene

- **KQL:** lowercase operators on new lines after `|`, double-quoted strings,
  case-sensitive ActionType filters, `has` over `contains`
- **SPL:** `index=...`, correct `sourcetype`, proper field names
- **SPL only when asked** — provide only when user mentions Splunk

## Authoritative sources allowlist

- `learn.microsoft.com`
- `github.com/MicrosoftDocs`
- `techcommunity.microsoft.com` (official posts only)
